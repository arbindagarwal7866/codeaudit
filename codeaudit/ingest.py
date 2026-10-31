"""Stage 1: Ingestion — accept a local folder or a GitHub URL, list the Python files."""
from __future__ import annotations
import hashlib
import os
import re
import subprocess
from pathlib import Path
from .models import FileRecord

DEFAULT_EXCLUDES = {
    ".git", ".venv", "venv", "env", "__pycache__", "build", "dist", ".eggs",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", "node_modules", "site-packages",
    "docs", "audit_out", ".codeaudit_cache",
}
_URL = re.compile(r"^(https?://|git@)[\w.@:/~-]+?(\.git)?/?$")


def normalize_url(src: str) -> str:
    """Accept what people paste: github.com/o/r, a browser link to /tree/<branch> or /blob/..., trailing .git."""
    src = src.strip()
    if re.match(r"^(www\.)?(github|gitlab)\.com/", src):
        src = "https://" + src
    m = re.match(r"^(https?://[^/]+/[^/]+/[^/]+?)(\.git)?/(tree|blob|pull|issues|commit)(/.*)?$", src)
    return m.group(1) if m else src


def is_remote(src: str) -> bool:
    return bool(_URL.match(normalize_url(src)))


def resolve_source(src: str, workdir: str = ".codeaudit_repos", log=print) -> str:
    """Local path -> itself. GitHub URL -> shallow clone (reused if already cloned)."""
    src = normalize_url(src)
    if not is_remote(src):
        p = Path(src).expanduser().resolve()
        if not p.is_dir():
            raise FileNotFoundError(f"not a folder: {p}")
        return str(p)
    name = re.sub(r"\.git$", "", src.rstrip("/").split("/")[-1]) or "repo"
    owner = src.rstrip("/").split("/")[-2] if src.count("/") >= 4 else "remote"
    dest = Path(workdir).resolve() / f"{owner}__{name}"
    if (dest / ".git").is_dir():
        log(f"using existing clone {dest}")
        return str(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    log(f"cloning {src} ...")
    try:
        r = subprocess.run(["git", "clone", "--depth", "1", "--quiet", src, str(dest)],
                           capture_output=True, text=True, timeout=300,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    except subprocess.TimeoutExpired:
        raise RuntimeError("git clone took longer than 5 minutes (slow network or huge repo)") from None
    if r.returncode != 0:
        msg = r.stderr.strip()
        if "not found" in msg or "Authentication" in msg or "could not read Username" in msg:
            msg = "repository not found (check the URL; private repos need access)"
        raise RuntimeError(f"git clone failed: {msg[:300]}")
    return str(dest)


def path_to_module(rel: Path) -> str:
    parts = list(rel.with_suffix("").parts)
    if parts and parts[0] == "src" and len(parts) > 1:      # src-layout: src/pkg/x.py -> pkg.x
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) or "__root__"


def _is_test_path(rel: Path) -> bool:
    return any(p in {"tests", "test", "testing"} or p.startswith("test_") or p.endswith("_test.py")
               or p == "conftest.py" for p in rel.parts)


def ingest(repo_root: str, extra_excludes: set[str] | None = None) -> list[FileRecord]:
    root = Path(repo_root).resolve()
    excludes = DEFAULT_EXCLUDES | (extra_excludes or set())
    records: list[FileRecord] = []
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root)
        if any(part in excludes for part in rel.parts[:-1]):
            continue
        data = p.read_bytes()
        records.append(FileRecord(
            path=rel.as_posix(), module=path_to_module(rel),
            sha1=hashlib.sha1(data).hexdigest(), loc=data.count(b"\n") + 1,
            is_test=_is_test_path(rel),
        ))
    return records
