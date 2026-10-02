"""Safe path resolution and runtime directory handling.

Threat addressed
----------------
Any path that originates outside the process (a CLI argument, an API field, a
scan result filename, an archive member) can attempt to escape its intended
directory:

* traversal: ``../../etc/shadow``
* absolute escape: ``/etc/shadow``
* NUL/control-character truncation: ``report.pdf\\x00.png``
* symlink escape: a link inside the workspace pointing outside it

:func:`safe_join` refuses all four. It resolves symlinks BEFORE the
containment check, so a link cannot be used to step outside the root.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from core.errors import SecurityViolation, ValidationError

MAX_PATH_LEN: Final[int] = 4096
MAX_COMPONENT_LEN: Final[int] = 255

# Repository root: core/paths.py -> core/ -> <repo root>
REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent


def repo_root() -> Path:
    """Absolute path to the repository root."""
    return REPO_ROOT


def _reject_control_characters(text: str) -> None:
    """Reject NUL and other control characters.

    A NUL byte can truncate a path at the OS boundary, so ``safe.txt\\x00.exe``
    may be validated as one name and opened as another.
    """
    if "\x00" in text:
        raise SecurityViolation(
            "path contains a NUL byte", context={"reason": "nul_byte"}
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise SecurityViolation(
            "path contains control characters", context={"reason": "control_chars"}
        )


def safe_join(root: str | os.PathLike[str], *parts: str) -> Path:
    """Join ``parts`` under ``root`` and guarantee the result stays inside it.

    Raises :class:`SecurityViolation` for traversal, absolute components,
    control characters or symlink escape. Returns an absolute, fully resolved
    path.
    """
    base = Path(root).expanduser()
    try:
        base_resolved = base.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise SecurityViolation(
            "workspace root could not be resolved", context={"reason": "bad_root"}
        ) from exc

    if not parts:
        return base_resolved

    cleaned: list[str] = []
    for part in parts:
        if not isinstance(part, str):
            raise ValidationError(
                f"path component must be str, got {type(part).__name__}"
            )
        if part in ("", ".", os.curdir):
            continue
        _reject_control_characters(part)
        if len(part) > MAX_PATH_LEN:
            raise SecurityViolation(
                "path component too long", context={"reason": "too_long"}
            )
        if os.path.isabs(part) or part.startswith(("/", "\\")):
            raise SecurityViolation(
                "absolute path component rejected",
                context={"reason": "absolute_component"},
            )
        # Windows drive/UNC forms are rejected even on POSIX so the same
        # input is refused consistently on every platform.
        if len(part) >= 2 and part[1] == ":":
            raise SecurityViolation(
                "drive-qualified path rejected", context={"reason": "drive_letter"}
            )
        if ".." in Path(part.replace("\\", "/")).parts:
            raise SecurityViolation(
                "path traversal rejected", context={"reason": "traversal"}
            )
        cleaned.append(part)

    candidate = base_resolved.joinpath(*cleaned)
    if len(str(candidate)) > MAX_PATH_LEN:
        raise SecurityViolation("path too long", context={"reason": "too_long"})

    # Resolve symlinks BEFORE containment: a symlink inside the root that
    # points outside must not pass.
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise SecurityViolation(
            "path could not be resolved", context={"reason": "unresolvable"}
        ) from exc

    if not is_within(resolved, base_resolved):
        raise SecurityViolation(
            "path escapes the workspace root", context={"reason": "escape"}
        )
    return resolved


def is_within(path: str | os.PathLike[str], root: str | os.PathLike[str]) -> bool:
    """True when ``path`` is ``root`` itself or lives beneath it."""
    try:
        p = Path(path).resolve(strict=False)
        r = Path(root).resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    if p == r:
        return True
    try:
        p.relative_to(r)
        return True
    except ValueError:
        return False


def safe_filename(name: str, *, default: str = "unnamed") -> str:
    """Reduce an untrusted string to a single safe filename component.

    Strips directory separators and control characters, refuses ``.`` and
    ``..``, and bounds the length. The result never contains a path
    separator, so it cannot redirect a write.
    """
    if not isinstance(name, str):
        return default
    _reject_control_characters(name)
    base = os.path.basename(name.replace("\\", "/")).strip()
    if base in ("", ".", ".."):
        return default
    safe = "".join(
        ch for ch in base if ch.isalnum() or ch in ("-", "_", ".", " ")
    ).strip()
    safe = safe.lstrip(".") or default
    return safe[:MAX_COMPONENT_LEN]


def ensure_directory(path: str | os.PathLike[str], *, mode: int = 0o700) -> Path:
    """Create a directory (parents included) with restrictive permissions.

    ``0o700`` by default: runtime directories hold databases, evidence and
    logs, which must not be world- or group-readable.
    """
    target = Path(path).expanduser().resolve(strict=False)
    target.mkdir(parents=True, exist_ok=True, mode=mode)
    try:
        current = target.stat().st_mode & 0o777
        if current & 0o077:
            target.chmod(mode)
    except OSError:
        # Filesystems that do not support chmod (some mounts) must not crash
        # startup; the directory still exists and the caller can proceed.
        pass
    return target


__all__ = [
    "REPO_ROOT",
    "repo_root",
    "safe_join",
    "is_within",
    "safe_filename",
    "ensure_directory",
    "MAX_PATH_LEN",
]
