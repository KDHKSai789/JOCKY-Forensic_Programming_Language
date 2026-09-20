import os
import sys
import hashlib
from datetime import datetime, timezone
from typing import Any

# Directories to prune during os.walk to avoid very slow or infinite scans
_PRUNE_DIRS = frozenset({
    ".cache", ".git", ".venv", "venv", "__pycache__", "node_modules",
    # Linux snap / proc-like virtual directories
    "snap", "proc", "sys", "dev",
})

# Windows executable extensions
_WIN_EXEC_EXTS = frozenset({
    ".exe", ".bat", ".cmd", ".ps1", ".vbs",
    ".msi", ".dll", ".sys", ".com", ".scr",
})


class BinaryCollector:
    """
    Collects forensic metadata and SHA-256 hashes of executable binaries
    on Linux and Windows. Scan is bounded by ``max_binaries`` and
    ``max_depth`` to guarantee fast, safe collection.
    """

    name = "binaries"

    def __init__(self, max_binaries: int = 100, max_depth: int = 3):
        self.max_binaries = max_binaries
        self.max_depth = max_depth

    def _scan_dir(self, scan_dir: str, binaries: list) -> None:
        """Walk *scan_dir* up to max_depth, collecting executable metadata."""
        scan_dir = os.path.realpath(scan_dir)  # resolve once at top level
        base_depth = scan_dir.count(os.sep)

        try:
            for root, dirnames, files in os.walk(
                scan_dir, topdown=True, followlinks=False
            ):
                # Depth guard — prune directories that would exceed max_depth
                current_depth = root.count(os.sep) - base_depth
                if current_depth >= self.max_depth:
                    dirnames.clear()
                    continue

                # Prune noise directories in-place (mutates the walk)
                dirnames[:] = [
                    d for d in dirnames
                    if d not in _PRUNE_DIRS and not os.path.islink(os.path.join(root, d))
                ]

                for filename in files[: 50]:  # cap per directory
                    if len(binaries) >= self.max_binaries:
                        return

                    full_path = os.path.join(root, filename)

                    # Skip symlinks — they can point anywhere and cause loops
                    if os.path.islink(full_path):
                        continue

                    try:
                        st = os.stat(full_path, follow_symlinks=False)

                        # Determine executability
                        is_exec = bool(st.st_mode & 0o111)
                        if sys.platform.startswith("win32"):
                            ext = os.path.splitext(filename)[1].lower()
                            if ext in _WIN_EXEC_EXTS:
                                is_exec = True

                        # On Linux only record executables (skip plain data files)
                        if not is_exec and not sys.platform.startswith("win32"):
                            continue

                        # Hash small-enough files (<= 10 MB)
                        sha256 = ""
                        if st.st_size <= 10 * 1024 * 1024:
                            try:
                                with open(full_path, "rb") as fh:
                                    sha256 = hashlib.sha256(fh.read()).hexdigest()
                            except (PermissionError, OSError):
                                pass

                        binaries.append({
                            "path": full_path,
                            "size": st.st_size,
                            "sha256": sha256,
                            "mode": oct(st.st_mode),
                            "modified_time": datetime.fromtimestamp(
                                st.st_mtime, tz=timezone.utc
                            ).isoformat(),
                            "executable": is_exec,
                        })

                    except (PermissionError, OSError):
                        continue

        except (PermissionError, OSError):
            pass

    def collect(self, target: str = "LOCAL") -> dict[str, Any]:
        started_at = datetime.now(timezone.utc).isoformat()
        binaries: list[dict] = []
        platform_name = "windows" if sys.platform.startswith("win32") else sys.platform

        if sys.platform.startswith("win32"):
            scan_dirs = []
            for env_var in ("TEMP", "LOCALAPPDATA", "USERPROFILE"):
                val = os.environ.get(env_var)
                if val and os.path.exists(val):
                    scan_dirs.append(val)
            if not scan_dirs:
                scan_dirs = ["C:\\Windows\\Temp"]
        else:
            scan_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/usr/local/bin"]

        for scan_dir in scan_dirs:
            if len(binaries) >= self.max_binaries:
                break
            if not os.path.exists(scan_dir):
                continue
            self._scan_dir(scan_dir, binaries)

        finished_at = datetime.now(timezone.utc).isoformat()
        return {
            "collector": self.name,
            "target": target,
            "platform": platform_name,
            "status": "complete",
            "started_at": started_at,
            "finished_at": finished_at,
            "binary_count": len(binaries),
            "binaries": binaries,
        }
