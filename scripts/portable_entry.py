"""PyInstaller entry point for the Windows portable executable."""

from claude_sonar.portable import main


if __name__ == "__main__":
    raise SystemExit(main())
