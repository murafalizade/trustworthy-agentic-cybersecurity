"""Real (not mocked) recon of the machine we're defending.

This machine is treated as the server. Everything the agents are allowed to
look at or act on is scoped to MONITORED_ROOT — a human decision about blast
radius, not something any agent/LLM can widen. Path-scoping helpers here are
the single place that boundary is enforced; tools.py calls into them rather
than re-implementing the check.
"""

import subprocess
from pathlib import Path
from typing import Dict

MONITORED_ROOT = Path.home() / "Desktop" / "ML Projects"

_MANIFEST_NAMES = {
    "requirements.txt", "pyproject.toml", "Pipfile", "package.json",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "go.mod",
}
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next"}

# Safe, read-only "what's on this host" probes — fixed argv, never built from
# model/user input, so there's no injection surface for these.
_HOST_VERSION_COMMANDS = {
    "python3": ["python3", "--version"],
    "node": ["node", "--version"],
    "npm": ["npm", "--version"],
    "docker": ["docker", "--version"],
    "git": ["git", "--version"],
    "nginx": ["nginx", "-v"],
    "psql": ["psql", "--version"],
    "kubectl": ["kubectl", "version", "--client"],
    "os": ["uname", "-a"],
}


def is_within_monitored_root(path: Path) -> bool:
    try:
        path.resolve().relative_to(MONITORED_ROOT.resolve())
        return True
    except (ValueError, OSError):
        return False


def resolve_scoped(raw_path: str) -> Path:
    """Resolve a path the agent asked for relative to MONITORED_ROOT, or as an
    absolute path — either way, the result must land inside MONITORED_ROOT.
    Raises ValueError if it doesn't.
    """
    candidate = Path(raw_path)
    resolved = candidate if candidate.is_absolute() else (MONITORED_ROOT / candidate)
    resolved = resolved.resolve()
    if not is_within_monitored_root(resolved):
        raise ValueError(f"'{raw_path}' resolves outside the monitored root ({MONITORED_ROOT}); refusing.")
    return resolved


def probe_host_versions() -> Dict[str, str]:
    versions = {}
    for name, cmd in _HOST_VERSION_COMMANDS.items():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            output = (result.stdout or result.stderr).strip()
            versions[name] = output.splitlines()[0] if output else "(no output)"
        except FileNotFoundError:
            versions[name] = "not installed"
        except Exception as e:
            versions[name] = f"check failed: {e}"
    return versions


def scan_manifests(root: Path = MONITORED_ROOT, max_files: int = 25, max_chars_each: int = 800) -> Dict[str, str]:
    """Walks MONITORED_ROOT for dependency/config manifests. Read-only,
    bounded in count and size so it can't be used to pull the whole tree
    into a prompt.
    """
    found: Dict[str, str] = {}
    if not root.exists():
        return found
    for path in sorted(root.rglob("*")):
        if len(found) >= max_files:
            break
        if not path.is_file() or path.name not in _MANIFEST_NAMES:
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        try:
            content = path.read_text(errors="ignore")[:max_chars_each]
        except Exception:
            continue
        found[str(path.relative_to(root))] = content
    return found


def build_system_snapshot() -> str:
    """Rendered summary of the real host + monitored project folder — this is
    what both agents are told 'our system' is, instead of a static mock.
    """
    versions = probe_host_versions()
    manifests = scan_manifests()

    lines = ["Host tool versions:"]
    for name, v in versions.items():
        lines.append(f"  - {name}: {v}")

    lines.append(f"\nProjects under {MONITORED_ROOT} (dependency/config manifests found):")
    if not manifests:
        lines.append("  (none found, or the folder doesn't exist)")
    for rel_path, content in manifests.items():
        preview = "\n".join(content.splitlines()[:12])
        lines.append(f"  --- {rel_path} ---\n{preview}")

    return "\n".join(lines)
