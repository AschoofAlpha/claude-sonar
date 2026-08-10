from dataclasses import dataclass
from typing import Optional, Iterable


@dataclass
class ProbeEndpoint:
    id: str
    purpose: str
    url: str
    enabled: bool
    supports_ipv4: bool
    supports_ipv6: bool
    expected_content_type: str
    maximum_response_bytes: int


class ProbeError(Exception):
    pass


@dataclass
class ProbeContext:
    timeout: int
    endpoint: ProbeEndpoint


def run_probes(
    custom_endpoint: str = None,
    timeout: int = 5,
    online: bool = False,
    intended_region: str = None,
    cross_site_urls: Optional[Iterable[str]] = None,
):
    """Run optional live egress/DNS/reputation/cross-site probes.

    Offline by default: with ``online=False`` and no ``custom_endpoint``, return
    an empty list and contact no public endpoints. Pass ``online=True`` or a
    validated custom endpoint to observe egress.

    Optional kwargs (defaults preserve the previous signature):
    - ``intended_region``: ISO-3166-1 alpha-2 hint for reputation consistency note
    - ``cross_site_urls``: override the default cross-site observation URL set
    """
    from .endpoints import get_all_endpoints
    from .egress import check_egress_consistency
    from .dns_probe import check_dns_consistency
    from .reputation import check_ip_reputation
    from .cross_site import check_cross_site_routing

    if not online and not custom_endpoint:
        return []

    results = []

    if custom_endpoint:
        from .safety import validate_url
        validate_url(custom_endpoint)
        ep = ProbeEndpoint(
            id="custom",
            purpose="public-egress-observation",
            url=custom_endpoint,
            enabled=True,
            supports_ipv4=True,
            supports_ipv6=True,
            expected_content_type="text/plain",
            maximum_response_bytes=16384,
        )
        eps = [ep]
    else:
        eps = [e for e in get_all_endpoints() if e["enabled"]]
        eps = [ProbeEndpoint(**e) for e in eps]

    for ep in eps:
        ctx = ProbeContext(timeout=timeout, endpoint=ep)
        res = check_egress_consistency(ctx, is_custom=custom_endpoint is not None)
        results.append(res)

    results.append(check_dns_consistency(timeout=min(timeout, 5)))

    # Extended online probes (reputation + cross-site). Run when online=True.
    # custom_endpoint-only path keeps prior egress+dns behavior.
    if online:
        results.append(
            check_ip_reputation(
                timeout=timeout,
                intended_region=intended_region,
            )
        )
        results.append(
            check_cross_site_routing(
                urls=cross_site_urls,
                timeout=timeout,
            )
        )

    return results
