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

    Offline by default for network contact: with ``online=False`` and no
    ``custom_endpoint``, only the cheap offline WebRTC guidance check runs
    (no public endpoints contacted). Pass ``online=True`` or a validated
    custom endpoint to observe egress.

    Optional kwargs (defaults preserve the previous signature):
    - ``intended_region``: ISO-3166-1 alpha-2 hint for reputation consistency note
    - ``cross_site_urls``: override the default cross-site observation URL set
    """
    from .endpoints import get_all_endpoints
    from .egress import check_dual_stack_egress, check_egress_consistency
    from .dns_probe import check_dns_consistency
    from .reputation import check_ip_reputation
    from .cross_site import check_cross_site_routing
    from .stability import check_egress_stability
    from .webrtc_guide import check_webrtc_guidance

    results = []

    # Cheap offline guidance — no network. Always included so offline audits
    # still surface manual WebRTC verification advice.
    results.append(check_webrtc_guidance())

    if not online and not custom_endpoint:
        return results

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

    # Multi-method DNS when online; single-method when custom-only offline path.
    results.append(
        check_dns_consistency(
            timeout=min(timeout, 5),
            online=bool(online),
        )
    )

    # Extended online probes. custom_endpoint-only (online=False) keeps prior
    # egress+dns (+webrtc) behavior without reputation/cross-site/stability.
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
        results.append(check_dual_stack_egress(timeout=timeout))
        results.append(check_egress_stability(timeout=timeout))

    return results
