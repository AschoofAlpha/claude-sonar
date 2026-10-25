"""Pin Mihomo selection chains to a concrete leaf node."""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple

AUTOMATIC_TYPES = frozenset({
    "url-test",
    "urltest",
    "fallback",
    "load-balance",
    "loadbalance",
    "smart",
})
GROUP_TYPES = AUTOMATIC_TYPES | frozenset({"selector", "relay"})
CONCRETE_TYPES = frozenset({
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "ss",
    "hysteria",
    "hysteria2",
    "tuic",
    "snell",
    "wireguard",
    "ssh",
    "http",
    "socks",
    "socks5",
    "direct",
    "anytls",
    "mieru",
    "shadowtls",
})


def _norm_type(value: Any) -> str:
    return str(value or "").lower().replace("_", "-").strip()


def format_selection_chain(chain: Optional[Iterable[Any]]) -> str:
    names = []
    for link in chain or []:
        if not isinstance(link, Mapping):
            continue
        name = str(link.get("Name") or "").strip()
        if name:
            names.append(name)
    return " → ".join(names)


def leaf_of_chain(chain: Optional[Sequence[Any]]) -> Optional[Mapping[str, Any]]:
    links = [item for item in (chain or []) if isinstance(item, Mapping)]
    return links[-1] if links else None


def assess_policy_chain(runtime_groups: Optional[Iterable[Any]]) -> Tuple[str, str]:
    """Return (status, explanation) for the first usable selection chain."""
    chains = []
    for group in runtime_groups or []:
        if not isinstance(group, Mapping):
            continue
        chain = group.get("SelectionChain")
        if isinstance(chain, list) and chain:
            chains.append(chain)
    if not chains:
        return "unknown", "没有可用的选择链，无法判断叶子节点是否固定。"

    chain = chains[0]
    formatted = format_selection_chain(chain) or "（空）"
    leaf = leaf_of_chain(chain)
    if not leaf:
        return "unknown", "选择链为空，无法判断叶子节点是否固定。"

    ntype = _norm_type(leaf.get("Type"))
    pretty = str(leaf.get("Type") or ntype or "unknown")
    if ntype in GROUP_TYPES:
        return (
            "warning",
            f"选择链停在自动/分组节点（{pretty}）：{formatted}。"
            "叶子不是具体节点，出口可能随测速变化。",
        )
    return "pass", f"选择链钉在具体节点：{formatted}。"


def collect_policy_chain_checks(mihomo: Mapping[str, Any], builder) -> Optional[Mapping[str, Any]]:
    """Add network.policy_chain when runtime groups exist. Return first leaf or None."""
    policy = mihomo.get("PolicyGroups")
    if not isinstance(policy, Mapping):
        return None
    runtime_groups = policy.get("RuntimeGroups")
    if not isinstance(runtime_groups, list):
        return None
    status, explanation = assess_policy_chain(runtime_groups)
    builder.add(
        "network.policy_chain",
        "Policy selection chain leaf",
        "network",
        status,
        "low" if status == "warning" else "info",
        explanation,
        "把敏感流量组点到具体节点名，不要停在「自动选择」或故障转移。",
    )
    for group in runtime_groups:
        if not isinstance(group, Mapping):
            continue
        leaf = leaf_of_chain(group.get("SelectionChain") if isinstance(group.get("SelectionChain"), list) else [])
        if leaf:
            return leaf
    return None
