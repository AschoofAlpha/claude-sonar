#!/usr/bin/env python3
"""CLI wrapper: limited POSIX collector (Python; replaces .sh)."""

from claude_sonar.collectors.posix import main

if __name__ == "__main__":
    raise SystemExit(main())
