import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

try:
    import psutil
except ImportError:
    psutil = None


class MemoryIndicatorCollector:
    """
    Defensive process memory-indicator collector for Linux and Windows.

    Collects process memory-map metadata from /proc/<pid>/maps or psutil/system APIs.
    """

    def __init__(
        self,
        max_processes: int = 500,
        max_mappings_per_process: int = 200,
    ):
        self.max_processes = max_processes
        self.max_mappings_per_process = (
            max_mappings_per_process
        )

    def _parse_maps_line(
        self,
        line: str,
    ) -> dict[str, Any] | None:

        pattern = (
            r"^([0-9a-f]+)-([0-9a-f]+)\s+"
            r"(\S+)\s+"
            r"([0-9a-f]+)\s+"
            r"(\S+)\s+"
            r"(\d+)\s*(.*)$"
        )

        match = re.match(pattern, line.strip())

        if not match:
            return None

        start_hex = match.group(1)
        end_hex = match.group(2)
        permissions = match.group(3)
        offset_hex = match.group(4)
        device = match.group(5)
        inode = int(match.group(6))
        pathname = match.group(7).strip()

        start = int(start_hex, 16)
        end = int(end_hex, 16)

        return {
            "start": f"0x{start_hex}",
            "end": f"0x{end_hex}",
            "size": end - start,
            "permissions": permissions,
            "offset": f"0x{offset_hex}",
            "device": device,
            "inode": inode,
            "pathname": pathname or None,
            "readable": "r" in permissions,
            "writable": "w" in permissions,
            "executable": "x" in permissions,
            "private": "p" in permissions,
            "shared": "s" in permissions,
            "anonymous": pathname == "",
            "deleted": "(deleted)" in pathname,
        }

    def _collect_process(
        self,
        pid: int,
    ) -> dict[str, Any] | None:

        maps_path = f"/proc/{pid}/maps"

        try:
            with open(
                maps_path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as file:

                mappings = []

                for line_number, line in enumerate(file):

                    if (
                        line_number
                        >= self.max_mappings_per_process
                    ):
                        break

                    parsed = self._parse_maps_line(line)

                    if parsed is not None:
                        mappings.append(parsed)

            suspicious = []

            for mapping in mappings:

                if (
                    mapping["writable"]
                    and mapping["executable"]
                ):
                    suspicious.append(
                        "writable_executable_mapping"
                    )

                if (
                    mapping["executable"]
                    and mapping["deleted"]
                ):
                    suspicious.append(
                        "deleted_executable_mapping"
                    )

                if (
                    mapping["writable"]
                    and mapping["anonymous"]
                ):
                    suspicious.append(
                        "writable_anonymous_mapping"
                    )

            return {
                "pid": pid,
                "mapping_count": len(mappings),
                "writable_executable_count": sum(
                    1
                    for item in mappings
                    if (
                        item["writable"]
                        and item["executable"]
                    )
                ),
                "deleted_executable_count": sum(
                    1
                    for item in mappings
                    if (
                        item["executable"]
                        and item["deleted"]
                    )
                ),
                "writable_anonymous_count": sum(
                    1
                    for item in mappings
                    if (
                        item["writable"]
                        and item["anonymous"]
                    )
                ),
                "indicators": sorted(
                    set(suspicious)
                ),
                "mappings": mappings,
            }

        except (
            FileNotFoundError,
            PermissionError,
            ProcessLookupError,
            OSError,
        ):
            return None

    def collect(
        self,
        target: str = "LOCAL",
    ) -> dict[str, Any]:

        started = datetime.now(
            timezone.utc
        ).isoformat()

        platform_name = "windows" if sys.platform.startswith("win32") else sys.platform
        processes = []

        total_mappings = 0
        writable_executable = 0
        deleted_executable = 0
        writable_anonymous = 0

        collection_notes = []

        if os.path.exists("/proc"):
            process_ids = []
            try:
                for entry in os.listdir("/proc"):
                    if entry.isdigit():
                        process_ids.append(int(entry))
            except OSError:
                process_ids = []

            process_ids.sort()
            process_ids = process_ids[: self.max_processes]

            for pid in process_ids:
                result = self._collect_process(pid)
                if result is None:
                    continue

                processes.append(result)
                total_mappings += result["mapping_count"]
                writable_executable += result["writable_executable_count"]
                deleted_executable += result["deleted_executable_count"]
                writable_anonymous += result["writable_anonymous_count"]
        elif psutil is not None:
            count = 0
            for proc in psutil.process_iter(["pid", "name"]):
                if count >= self.max_processes:
                    break
                try:
                    pid = proc.info["pid"]
                    mappings = []
                    try:
                        mem_maps = proc.memory_maps(grouped=False)
                        for m in mem_maps[:self.max_mappings_per_process]:
                            path = getattr(m, "path", "")
                            perms = getattr(m, "perms", "rw")
                            mappings.append({
                                "start": "0x0",
                                "end": "0x0",
                                "size": getattr(m, "rss", 0),
                                "permissions": perms,
                                "pathname": path,
                                "readable": "r" in perms,
                                "writable": "w" in perms,
                                "executable": "x" in perms,
                                "anonymous": not path,
                                "deleted": False,
                            })
                    except Exception:
                        pass

                    p_result = {
                        "pid": pid,
                        "mapping_count": len(mappings),
                        "writable_executable_count": sum(1 for m in mappings if m.get("writable") and m.get("executable")),
                        "deleted_executable_count": 0,
                        "writable_anonymous_count": sum(1 for m in mappings if m.get("writable") and m.get("anonymous")),
                        "indicators": [],
                        "mappings": mappings,
                    }
                    processes.append(p_result)
                    total_mappings += p_result["mapping_count"]
                    writable_executable += p_result["writable_executable_count"]
                    writable_anonymous += p_result["writable_anonymous_count"]
                    count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        finished = datetime.now(
            timezone.utc
        ).isoformat()

        return {
            "collector": "memory.indicators",
            "target": target,
            "platform": platform_name,
            "started_at": started,
            "finished_at": finished,
            "process_count": len(processes),
            "total_mappings": total_mappings,
            "writable_executable_count":
                writable_executable,
            "deleted_executable_count":
                deleted_executable,
            "writable_anonymous_count":
                writable_anonymous,
            "collection_notes":
                collection_notes,
            "processes": processes,
        }
