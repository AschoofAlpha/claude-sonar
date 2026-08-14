import urllib.request
import urllib.parse
import os

def detect_proxy_for_url(url: str) -> dict:
    proxies = urllib.request.getproxies()
    proxy_applies = False
    proxy_source = "none"
    
    # Check if a proxy would be used for this specific URL
    proxy_handler = urllib.request.ProxyHandler(proxies)
    opener = urllib.request.build_opener(proxy_handler)
    
    # In python's urllib, getproxies() merges environment variables and system proxies (e.g. Windows Registry, macOS SystemConfiguration)
    if proxies:
        # Determine source
        env_vars = ['http_proxy', 'https_proxy', 'all_proxy', 'no_proxy']
        env_has_proxy = any(os.environ.get(k) or os.environ.get(k.upper()) for k in env_vars)
        if env_has_proxy:
            proxy_source = "environment"
        else:
            proxy_source = "system"
            
        req = urllib.request.Request(url)
        # We can test if the handler would add a proxy by checking req.host vs what ProxyHandler does
        # Actually, simpler: bypass is handled by proxy_bypass.
        parsed = urllib.parse.urlparse(url)
        if not urllib.request.proxy_bypass(parsed.hostname):
            # Also check if the scheme is in proxies
            if parsed.scheme in proxies:
                proxy_applies = True
                
    return {
        "proxy_detected": bool(proxies),
        "proxy_applies_to_request": proxy_applies,
        "proxy_source": proxy_source,
        "proxy_credentials_persisted": False # Not checking persisted creds in this MVP
    }
