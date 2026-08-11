from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Sequence, Tuple


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


def _run_online_probes_parallel(
    jobs: Sequence[Tuple[str, Callable[[], object]]],
) -> List[object]:
    """Run independent online probe callables in parallel; preserve job order.

    Falls back to sequential execution if the pool raises unexpectedly.
    Each job is ``(name, zero_arg_callable)``; results keep the same order as
    ``jobs``. A single job failure becomes an exception result that the caller
    may convert into an AuditCheck — here we re-raise after gathering so the
    existing best-effort wrapper in ``run_full_audit`` still applies, but we
    still return successful siblings when possible by catching per-future.
    """
    if not jobs:
        return []

    ordered: List[Optional[object]] = [None] * len(jobs)

    def _sequential() -> List[object]:
        out: List[object] = []
        for _name, fn in jobs:
            out.append(fn())
        return out

    try:
        max_workers = min(8, max(1, len(jobs)))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_map = {pool.submit(fn): idx for idx, (_name, fn) in enumerate(jobs)}
            for fut in as_completed(future_map):
                idx = future_map[fut]
                try:
                    ordered[idx] = fut.result()
                except Exception:
                    # Fall back to full sequential for a clean, deterministic path.
                    return _sequential()
    except Exception:
        return _sequential()

    # If any slot is still None, sequential fallback.
    if any(item is None for item in ordered):
        return _sequential()
    return list(ordered)  # type: ignore[arg-type]


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

    When ``online=True``, independent probes (DNS, reputation, cross-site,
    dual-stack, stability) run in a thread pool with shared ``timeout``;
    order of results is preserved. On pool failure, execution falls back to
    sequential. Offline / custom-endpoint-only paths stay sequential.
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

    # Egress-per-endpoint stays sequential (shared endpoint list, ordered).
    for ep in eps:
        ctx = ProbeContext(timeout=timeout, endpoint=ep)
        res = check_egress_consistency(ctx, is_custom=custom_endpoint is not None)
        results.append(res)

    # custom_endpoint-only (online=False): dns only, sequential — preserve prior
    # egress+dns (+webrtc) behavior without reputation/cross-site/stability.
    if not online:
        results.append(
            check_dns_consistency(
                timeout=min(timeout, 5),
                online=False,
            )
        )
        return results

    # Independent online probes — parallel with ordered merge.
    dns_timeout = min(timeout, 5)
    jobs: List[Tuple[str, Callable[[], object]]] = [
        (
            "dns",
            lambda: check_dns_consistency(timeout=dns_timeout, online=True),
        ),
        (
            "reputation",
            lambda: check_ip_reputation(
                timeout=timeout,
                intended_region=intended_region,
            ),
        ),
        (
            "cross_site",
            lambda: check_cross_site_routing(
                urls=cross_site_urls,
                timeout=timeout,
            ),
        ),
        (
            "dual_stack",
            lambda: check_dual_stack_egress(timeout=timeout),
        ),
        (
            "stability",
            lambda: check_egress_stability(timeout=timeout),
        ),
    ]
    results.extend(_run_online_probes_parallel(jobs))
    return results
