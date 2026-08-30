import urllib.request
import urllib.error
import urllib.parse
import ssl
import socket
import http.client
from .safety import validate_url, is_safe_ip
from .base import ProbeError
from .proxy_detector import detect_proxy_for_url
from .. import __version__

class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port=None, pinned_ip=None, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(host, port, **kwargs)

    def connect(self):
        self.sock = socket.create_connection(
            (self.pinned_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)

class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pinned_ip, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(**kwargs)

    def https_open(self, req):
        def build(host, port=None, **kwargs):
            return PinnedHTTPSConnection(host, port, pinned_ip=self.pinned_ip, **kwargs)
        return self.do_open(build, req)

def resolve_and_pick_ip(hostname):
    try:
        addrinfo = socket.getaddrinfo(hostname, 443, 0, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ProbeError(f"DNS resolution failed: {e}")
        
    ips = [info[4][0] for info in addrinfo]
    safe_ips = [ip for ip in set(ips) if is_safe_ip(ip)]
    
    if not safe_ips:
        raise ProbeError(f"No safe public IPs found for {hostname}")
        
    # Just pick the first safe IP
    return safe_ips[0]

def fetch_http(url: str, timeout: int = 5, max_bytes: int = 16384, is_custom: bool = False):
    validate_url(url)

    proxy_meta = detect_proxy_for_url(url)
    has_proxy = proxy_meta["proxy_applies_to_request"]
    
    parsed = urllib.parse.urlparse(url)
    
    if has_proxy:
        ssrf_validation_mode = "proxy_limited"
        # We don't try to pin IP if proxy is involved, because the proxy will resolve it.
        # We just rely on the proxy for egress, but we still ensure it's not a cross-host redirect
        class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                if urllib.parse.urlparse(req.full_url).hostname != urllib.parse.urlparse(newurl).hostname:
                    raise ProbeError("Cross-host redirect blocked in proxy mode.")
                return super().redirect_request(req, fp, code, msg, headers, newurl)
                
        opener = urllib.request.build_opener(SafeRedirectHandler())
    else:
        ssrf_validation_mode = "direct_pinned"
        # We must validate DNS and pin IP
        pinned_ip = resolve_and_pick_ip(parsed.hostname)
        
        class PinnedRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                if urllib.parse.urlparse(req.full_url).hostname != urllib.parse.urlparse(newurl).hostname:
                    raise ProbeError("Cross-host redirect blocked.")
                # We would need to re-validate if same host, but same host uses same pinned IP implicitly
                # if we were to create a new connection. 
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        opener = urllib.request.build_opener(
            PinnedHTTPSHandler(pinned_ip=pinned_ip, context=ssl.create_default_context()),
            PinnedRedirectHandler()
        )

    req = urllib.request.Request(
        url,
        headers={'User-Agent': f'Claude-Sonar/{__version__}'}
    )
    
    try:
        with opener.open(req, timeout=timeout) as response:
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ProbeError("Response too large.")
                
            return data.decode('utf-8', errors='ignore'), ssrf_validation_mode
    except Exception as e:
        raise ProbeError(f"HTTP fetch failed: {e}")
