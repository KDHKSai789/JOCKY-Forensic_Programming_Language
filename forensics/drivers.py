import os
import sys
import subprocess
from datetime import datetime, timezone
from typing import Any


class DriverCollector:
    """
    Collects Linux driver and kernel module inventory or Windows device drivers.
    """

    name = "drivers"

    def collect(self, target: str = "LOCAL") -> dict[str, Any]:
        started_at = datetime.now(timezone.utc).isoformat()
        modules = []
        platform_name = "windows" if sys.platform.startswith("win32") else sys.platform

        try:
            if os.path.exists("/proc/modules"):
                with open("/proc/modules", "r", encoding="utf-8", errors="replace") as file:
                    for line in file:
                        parts = line.strip().split()
                        if not parts:
                            continue

                        name = parts[0]
                        size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                        refcount = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
                        used_by = parts[3].split(",") if len(parts) > 3 and parts[3] != "-" else []
                        state = parts[4] if len(parts) > 4 else "unknown"

                        modules.append({
                            "name": name,
                            "size": size,
                            "refcount": refcount,
                            "used_by": used_by,
                            "state": state,
                        })
            elif sys.platform.startswith("win32"):
                try:
                    output = subprocess.check_output(["driverquery", "/fo", "csv"], text=True, errors="replace")
                    lines = output.strip().splitlines()
                    if len(lines) > 1:
                        for line in lines[1:]:
                            parts = [p.strip('"') for p in line.split('","')]
                            if parts:
                                modules.append({
                                    "name": parts[0],
                                    "display_name": parts[1] if len(parts) > 1 else parts[0],
                                    "driver_type": parts[2] if len(parts) > 2 else "Kernel",
                                    "link_date": parts[3] if len(parts) > 3 else "",
                                    "state": "loaded",
                                })
                except Exception:
                    pass
        except Exception as error:
            finished_at = datetime.now(timezone.utc).isoformat()
            return {
                "collector": self.name,
                "target": target,
                "platform": platform_name,
                "status": "error",
                "error": str(error),
                "started_at": started_at,
                "finished_at": finished_at,
                "driver_count": 0,
                "drivers": [],
            }

        finished_at = datetime.now(timezone.utc).isoformat()
        return {
            "collector": self.name,
            "target": target,
            "platform": platform_name,
            "status": "complete",
            "started_at": started_at,
            "finished_at": finished_at,
            "driver_count": len(modules),
            "drivers": modules,
        }
