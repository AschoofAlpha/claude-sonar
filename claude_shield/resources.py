import sysconfig
from pathlib import Path


def resource_path(*parts: str) -> Path:
    """Find a bundled file in a source checkout or an installed wheel."""
    source_path = Path(__file__).resolve().parent.parent.joinpath(*parts)
    if source_path.exists():
        return source_path

    installed_path = Path(sysconfig.get_path("data")) / "share" / "claude-shield"
    installed_path = installed_path.joinpath(*parts)
    if installed_path.exists():
        return installed_path

    raise FileNotFoundError(f"Bundled resource not found: {'/'.join(parts)}")
