import hashlib
import os
import stat
import sys
from datetime import datetime, timezone
from typing import Any


def _get_default_paths() -> list[str]:
    if sys.platform.startswith("win32"):
        paths = []
        for env_var in ("TEMP", "LOCALAPPDATA", "USERPROFILE"):
            val = os.environ.get(env_var)
            if val and os.path.exists(val):
                paths.append(val)
        return paths or ["C:\\Windows\\Temp"]
    return [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/home",
        "/var/log",
    ]


class FilesystemCollector:
    """
    Defensive filesystem forensic collector.

    Collects recently modified files from selected forensic
    directories without modifying the filesystem.
    """

    DEFAULT_PATHS = [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/home",
        "/var/log",
    ]

    def __init__(
        self,
        paths: list[str] | None = None,
        max_files: int = 500,
        recent_hours: int = 24,
    ):
        self.paths = paths if paths is not None else _get_default_paths()
        self.max_files = max_files
        self.recent_hours = recent_hours

    def _sha256_file(
        self,
        path: str,
    ) -> str | None:

        sha256 = hashlib.sha256()

        try:
            with open(
                path,
                "rb",
            ) as file:

                while True:

                    chunk = file.read(
                        1024 * 1024
                    )

                    if not chunk:
                        break

                    sha256.update(chunk)

            return sha256.hexdigest()

        except (
            OSError,
            PermissionError,
        ):
            return None

    def _file_record(
        self,
        path: str,
    ) -> dict[str, Any] | None:

        try:
            info = os.stat(
                path,
                follow_symlinks=False,
            )

            mode = info.st_mode

            if not stat.S_ISREG(mode):
                return None

            modified = datetime.fromtimestamp(
                info.st_mtime,
                timezone.utc,
            ).isoformat()

            accessed = datetime.fromtimestamp(
                info.st_atime,
                timezone.utc,
            ).isoformat()

            changed = datetime.fromtimestamp(
                info.st_ctime,
                timezone.utc,
            ).isoformat()

            is_exec = bool(
                mode & stat.S_IXUSR
                or mode & stat.S_IXGRP
                or mode & stat.S_IXOTH
            )
            if sys.platform.startswith("win32"):
                ext = os.path.splitext(path)[1].lower()
                if ext in (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".dll", ".sys", ".com", ".scr"):
                    is_exec = True

            is_hidden = os.path.basename(path).startswith(".")
            if sys.platform.startswith("win32"):
                try:
                    file_attr = getattr(info, "st_file_attributes", 0)
                    if file_attr & getattr(stat, "FILE_ATTRIBUTE_HIDDEN", 2):
                        is_hidden = True
                except Exception:
                    pass

            record = {
                "path": path,
                "name": os.path.basename(path),
                "size": info.st_size,
                "modified_time": modified,
                "accessed_time": accessed,
                "metadata_changed_time": changed,
                "mode": oct(
                    stat.S_IMODE(mode)
                ),
                "uid": getattr(info, "st_uid", 0),
                "gid": getattr(info, "st_gid", 0),
                "executable": is_exec,
                "hidden": is_hidden,
                "sha256": self._sha256_file(
                    path
                ),
            }

            return record

        except (
            OSError,
            PermissionError,
        ):
            return None

    def collect(
        self,
        target: str = "LOCAL",
    ) -> dict[str, Any]:

        started = datetime.now(
            timezone.utc
        ).isoformat()

        files = []
        platform_name = "windows" if sys.platform.startswith("win32") else sys.platform

        cutoff = (
            datetime.now(
                timezone.utc
            ).timestamp()
            - self.recent_hours * 3600
        )

        for root in self.paths:

            if len(files) >= self.max_files:
                break

            if not os.path.exists(root):
                continue

            try:

                for directory, dirnames, filenames in os.walk(
                    root,
                    topdown=True,
                    followlinks=False,
                ):
                    dirnames[:] = [d for d in dirnames if d not in (".cache", ".git", ".venv", "node_modules", "__pycache__", "venv")]

                    if len(files) >= self.max_files:
                        break

                    for filename in filenames:

                        if len(files) >= self.max_files:
                            break

                        path = os.path.join(
                            directory,
                            filename,
                        )

                        try:

                            info = os.stat(
                                path,
                                follow_symlinks=False,
                            )

                            if info.st_mtime < cutoff:
                                continue

                        except (
                            OSError,
                            PermissionError,
                        ):
                            continue

                        record = self._file_record(
                            path
                        )

                        if record is not None:
                            files.append(record)

            except (
                OSError,
                PermissionError,
            ):
                continue

        files.sort(
            key=lambda item: item.get(
                "modified_time",
                "",
            ),
            reverse=True,
        )

        finished = datetime.now(
            timezone.utc
        ).isoformat()

        return {
            "collector": "filesystem",
            "target": target,
            "platform": platform_name,
            "started_at": started,
            "finished_at": finished,
            "recent_hours": self.recent_hours,
            "file_count": len(files),
            "files": files,
        }
