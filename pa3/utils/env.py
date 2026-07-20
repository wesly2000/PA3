"""Helpers for loading local environment files."""

from __future__ import annotations

import os
from pathlib import Path


def find_repo_root(start: str | os.PathLike[str] | None = None) -> Path:
    """Find the repository root by walking upward from ``start``."""
    current = Path(start or __file__).resolve()
    if current.is_file():
        current = current.parent

    for path in (current, *current.parents):
        if (path / ".git").exists() or (path / "setup.py").exists():
            return path
    return Path.cwd()


def _parse_dotenv_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].lstrip()
    if "=" not in stripped:
        return None

    key, value = stripped.split("=", 1)
    key = key.strip()
    if not key:
        return None

    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return key, value


def load_dotenv(path: str | os.PathLike[str] | None = None, *, override: bool = False) -> Path | None:
    """Load environment variables from a .env file.

    Existing environment variables are preserved unless ``override`` is true.
    Returns the loaded file path, or ``None`` when the file does not exist.
    """
    dotenv_path = Path(path) if path is not None else find_repo_root() / ".env"
    dotenv_path = dotenv_path.expanduser().resolve()
    if not dotenv_path.exists():
        return None

    for line in dotenv_path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_dotenv_line(line)
        if parsed is None:
            continue
        key, value = parsed
        if override or key not in os.environ:
            os.environ[key] = value
    return dotenv_path
