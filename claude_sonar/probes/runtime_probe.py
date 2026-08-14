import subprocess
import shutil
from .http_probe import fetch_http
from .base import ProbeError

def run_python_probe(url: str, timeout: int, is_custom: bool = False):
    try:
        return fetch_http(url, timeout=timeout, is_custom=is_custom)
    except ProbeError:
        return None, "unavailable"
    except Exception:
        return None, "unavailable"

def run_curl_probe(url: str, timeout: int):
    curl = shutil.which('curl')
    if not curl:
        return None, "unavailable"
        
    # Determine ssrf_validation_mode for curl based on proxy
    from .proxy_detector import detect_proxy_for_url
    has_proxy = detect_proxy_for_url(url)["proxy_applies_to_request"]
    ssrf_mode = "proxy_limited" if has_proxy else "unavailable"
        
    try:
        # Prevent curlrc usage
        result = subprocess.run(
            [curl, '-s', '-q', '--max-time', str(timeout), '--proto', '=https', '--max-redirs', '0', url],
            capture_output=True,
            text=True,
            timeout=timeout+1,
        )
        if result.returncode == 0:
            return result.stdout, ssrf_mode
        return None, ssrf_mode
    except Exception:
        return None, ssrf_mode
