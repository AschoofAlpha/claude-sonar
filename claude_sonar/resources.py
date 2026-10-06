import sysconfig
from pathlib import Path


def resource_path(*parts: str) -> Path:
    """Find a bundled file in source, a frozen exe, or an installed wheel."""
    source_path = Path(__file__).resolve().parent.parent.joinpath(*parts)
    if source_path.exists():
        return source_path

    # PyInstaller extracts one-file data under ``sys._MEIPASS``. Keep this
    # lookup explicit so the portable exe never falls back to the user's cwd.
    frozen_root = getattr(__import__("sys"), "_MEIPASS", None)
    if frozen_root:
        frozen_path = Path(frozen_root) / "share" / "claude-sonar" / Path(*parts)
        if frozen_path.exists():
            return frozen_path

    installed_path = Path(sysconfig.get_path("data")) / "share" / "claude-sonar"
    installed_path = installed_path.joinpath(*parts)
    if installed_path.exists():
        return installed_path

    raise FileNotFoundError(f"Bundled resource not found: {'/'.join(parts)}")
