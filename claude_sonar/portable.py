"""Windows portable launcher.

Running the frozen executable with no arguments starts the read-only local
panel, binds an ephemeral loopback port, and opens the browser immediately.
The panel then runs the audit locally with the approved read-only online probes
enabled by default; users can turn them off through the switch. Arguments
switch to the normal offline-by-default CLI for troubleshooting or exports.
"""

from __future__ import annotations

import sys
from typing import Optional, Sequence

from .__main__ import main as cli_main
from .serve import serve


def _configure_stdio() -> None:
    """Keep Chinese reports printable on legacy Windows code pages."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            # A closed or non-standard redirected stream should not prevent an
            # otherwise valid audit from running.
            continue


def main(argv: Optional[Sequence[str]] = None) -> int:
    _configure_stdio()
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        return int(cli_main(args))

    serve(
        port=0,
        open_browser=True,
        open_delay=0.0,
        pre_audit=False,
        online=True,
        timeout=5.0,
        lang="zh",
    )
    return 0


__all__ = ["main"]
