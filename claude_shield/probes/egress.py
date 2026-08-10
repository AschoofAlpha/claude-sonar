import re
import ipaddress
from ..models import AuditCheck, Evidence
from .base import ProbeContext, ProbeError
from .runtime_probe import run_python_probe, run_curl_probe
from ..redaction import Redactor

def extract_ip(text: str):
    # Prefer Cloudflare-style ip= lines, then fall back to the first IPv4/IPv6 literal.
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'([0-9a-fA-F]{1,4}:){1,7}:?[0-9a-fA-F]{1,4}'
    
    # Check trace format (Cloudflare)
    for line in text.splitlines():
        if line.startswith('ip='):
            return line.split('=', 1)[1].strip()
            
    # Check plain IP
    m4 = re.search(ipv4_pattern, text)
    if m4:
        return m4.group(0)
        
    m6 = re.search(ipv6_pattern, text)
    if m6:
        return m6.group(0)
        
    return None

def check_egress_consistency(ctx: ProbeContext, is_custom: bool = False):
    # Compare Python stdlib and curl egress when both are available.
    results = []
    
    # Python stdlib
    py_text = run_python_probe(ctx.endpoint.url, ctx.timeout, is_custom=is_custom)
    # curl stdlib
    curl_text = run_curl_probe(ctx.endpoint.url, ctx.timeout)
    
    # Memory-only IP pseudonymization; raw addresses are not persisted.
    redactor = Redactor()
    
    def process_result(runtime, probe_result):
        if not probe_result:
            return None, "unavailable"
        text, ssrf_mode = probe_result
        if not text:
            return None, ssrf_mode
        ip_str = extract_ip(text)
        if not ip_str:
            return None, ssrf_mode
            
        try:
            ip = ipaddress.ip_address(ip_str)
            # Memory-only redaction
            return {
                "runtime": runtime,
                "endpoint": ctx.endpoint.id,
                "address_family": "ipv6" if ip.version == 6 else "ipv4",
                "observed_address": redactor.redact_ipv6(ip_str) if ip.version == 6 else redactor.redact_ipv4(ip_str),
                "raw_value_persisted": False
            }, ssrf_mode
        except ValueError:
            return None, ssrf_mode

    ev_py, ssrf_py = process_result("python", py_text)
    ev_curl, ssrf_curl = process_result("curl", curl_text)
    
    evidence = []
    if ev_py: 
        ev_py["ssrf_validation_mode"] = ssrf_py
        evidence.append(Evidence(type="runtime_egress", description="Python egress", data=ev_py))
    if ev_curl: 
        ev_curl["ssrf_validation_mode"] = ssrf_curl
        evidence.append(Evidence(type="runtime_egress", description="Curl egress", data=ev_curl))
    
    status = "unknown"
    confidence = "unknown"
    explanation = "Only one probe source succeeded or none succeeded."
    
    if ev_py and ev_curl:
        if ev_py["observed_address"] == ev_curl["observed_address"]:
            status = "pass"
            confidence = "confirmed"
            explanation = "Egress IPs match across runtimes."
        else:
            status = "warning"
            confidence = "possible"
            explanation="Egress IPs differ across runtimes. This could be due to split routing, load balancing, or different proxy behaviors."
            
    # Proxy Metadata Check
    from .proxy_detector import detect_proxy_for_url
    proxy_meta = detect_proxy_for_url(ctx.endpoint.url)
    proxy_evidence = Evidence(type="proxy_metadata", description="Proxy observation", data=proxy_meta)
            
    return AuditCheck(
        id=f"network.egress.runtime_consistency.{ctx.endpoint.id}",
        title=f"Runtime egress consistency ({ctx.endpoint.id})",
        category="network",
        status=status,
        severity="info" if status == "pass" else "medium",
        confidence=confidence,
        evidence=evidence + [proxy_evidence],
        explanation=explanation
    )
