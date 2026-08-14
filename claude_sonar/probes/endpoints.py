def get_all_endpoints():
    return [
        {
            "id": "cloudflare-trace",
            "purpose": "public-egress-observation",
            "url": "https://1.1.1.1/cdn-cgi/trace",
            "enabled": True,
            "supports_ipv4": True,
            "supports_ipv6": True,
            "expected_content_type": "text/plain",
            "maximum_response_bytes": 16384
        },
        {
            "id": "ipify-ipv4",
            "purpose": "public-egress-observation",
            "url": "https://api.ipify.org",
            "enabled": True,
            "supports_ipv4": True,
            "supports_ipv6": False,
            "expected_content_type": "text/plain",
            "maximum_response_bytes": 1024
        }
    ]
