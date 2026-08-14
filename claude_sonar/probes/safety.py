from dataclasses import dataclass
import urllib.parse
import ipaddress
import socket
from typing import List, Tuple

@dataclass
class IPClassification:
    is_public: bool
    reason: str
    normalized: str
    original_version: int
    effective_version: int

def classify_ip(ip_str: str) -> IPClassification:
    ip_str_clean = ip_str.split('%')[0].strip("[]")
    try:
        ip = ipaddress.ip_address(ip_str_clean)
    except ValueError:
        return IPClassification(is_public=False, reason="invalid-value", normalized=ip_str, original_version=0, effective_version=0)
        
    orig_version = ip.version
    eff_version = orig_version
    
    if orig_version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
        eff_version = 4
        
    normalized = str(ip)
    
    # Documented example addresses (RFC 5737 for IPv4, RFC 3849 for IPv6)
    if eff_version == 4:
        if ip in ipaddress.ip_network('192.0.2.0/24') or ip in ipaddress.ip_network('198.51.100.0/24') or ip in ipaddress.ip_network('203.0.113.0/24'):
            return IPClassification(is_public=True, reason="documentation-example-public", normalized=normalized, original_version=orig_version, effective_version=eff_version)
        if ip in ipaddress.ip_network('100.64.0.0/10'):
            return IPClassification(is_public=False, reason="shared-address-space", normalized=normalized, original_version=orig_version, effective_version=eff_version)
    else:
        if ip in ipaddress.ip_network('2001:db8::/32'):
            return IPClassification(is_public=True, reason="documentation-example-public", normalized=normalized, original_version=orig_version, effective_version=eff_version)
            
    if ip.is_loopback:
        return IPClassification(is_public=False, reason="loopback", normalized=normalized, original_version=orig_version, effective_version=eff_version)
    if ip.is_private:
        return IPClassification(is_public=False, reason="private", normalized=normalized, original_version=orig_version, effective_version=eff_version)
    if ip.is_link_local:
        return IPClassification(is_public=False, reason="link-local", normalized=normalized, original_version=orig_version, effective_version=eff_version)
    if ip.is_multicast:
        return IPClassification(is_public=False, reason="multicast", normalized=normalized, original_version=orig_version, effective_version=eff_version)
    if ip.is_unspecified:
        return IPClassification(is_public=False, reason="unspecified", normalized=normalized, original_version=orig_version, effective_version=eff_version)
    if ip.is_reserved:
        return IPClassification(is_public=False, reason="reserved", normalized=normalized, original_version=orig_version, effective_version=eff_version)
        
    if normalized == '169.254.169.254':
        return IPClassification(is_public=False, reason="cloud-metadata", normalized=normalized, original_version=orig_version, effective_version=eff_version)
        
    return IPClassification(is_public=True, reason="public", normalized=normalized, original_version=orig_version, effective_version=eff_version)

def validate_resolved_ip(ip_str: str):
    cls = classify_ip(ip_str)
    if not cls.is_public:
        raise ValueError(f"IP {ip_str} is in a blocked range ({cls.reason}).")

def is_safe_ip(ip_str: str) -> bool:
    return classify_ip(ip_str).is_public

def resolve_and_validate_url(url: str) -> Tuple[str, List[str]]:
    """
    Validates a URL and resolves its hostname.
    Returns the parsed hostname and a list of resolved and validated IP address strings.
    Raises ValueError if any security check fails.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != 'https':
        raise ValueError("Only HTTPS is allowed.")
        
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URL are not allowed.")
        
    if any(ord(c) < 32 for c in url):
        raise ValueError("Control characters are not allowed.")
        
    if len(url) > 2048:
        raise ValueError("URL is too long.")
        
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Missing hostname.")
        
    if hostname.lower() in ('localhost', '127.0.0.1', '::1', '[::1]'):
        raise ValueError("Localhost is not allowed.")
        
    # Check if hostname is directly an IP
    cls = classify_ip(hostname)
    if cls.reason != "invalid-value":
        if not cls.is_public:
            raise ValueError(f"IP {hostname} is in a blocked range ({cls.reason}).")
        return hostname, [cls.normalized]
        
    # It's a domain name, resolve it
    try:
        addr_infos = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed: {e}")
        
    resolved_ips = set()
    for family, type, proto, canonname, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        resolved_ips.add(ip_str)
        
    if not resolved_ips:
        raise ValueError("Domain resolved to no addresses.")
        
    # Check every single resolved IP
    has_public = False
    has_private = False
    
    for ip_str in resolved_ips:
        cls = classify_ip(ip_str)
        if cls.is_public:
            has_public = True
        else:
            has_private = True
            
    # If a domain resolves to both public and private, reject it
    if has_private:
        raise ValueError("Domain resolved to a blocked address.")
        
    return hostname, list(resolved_ips)

def validate_url(url: str) -> bool:
    resolve_and_validate_url(url)
    return True
