import os
import sys
import subprocess
from datetime import datetime, timezone
from typing import Any


class EventCollector:
    """
    Collects forensic events from Linux or Windows log sources safely.
    """

    name = "events"

    def collect(self, target: str = "LOCAL") -> dict[str, Any]:
        started_at = datetime.now(timezone.utc).isoformat()
        events = []
        platform_name = "windows" if sys.platform.startswith("win32") else sys.platform

        if sys.platform.startswith("win32"):
            win_logs = ["System", "Application"]
            for log_name in win_logs:
                try:
                    output = subprocess.check_output(
                        ["wevtutil", "qe", log_name, "/c:25", "/f:text"],
                        text=True,
                        errors="replace",
                        stderr=subprocess.DEVNULL
                    )
                    for line in output.splitlines():
                        line_str = line.strip()
                        if line_str and not line_str.startswith("Event["):
                            events.append({
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "source": f"WinEventLog:{log_name}",
                                "event_type": "LOG_ENTRY",
                                "message": line_str[:300],
                            })
                except Exception:
                    pass

            system_root = os.environ.get("SystemRoot", "C:\\Windows")
            win_log_files = [
                os.path.join(system_root, "inf", "setupapi.dev.log"),
                os.path.join(system_root, "Panther", "setupact.log"),
            ]
            for log_path in win_log_files:
                if os.path.exists(log_path):
                    try:
                        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                            lines = f.readlines()[-50:]
                            for line in lines:
                                line_str = line.strip()
                                if line_str:
                                    events.append({
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "source": os.path.basename(log_path),
                                        "event_type": "LOG_ENTRY",
                                        "message": line_str[:300],
                                    })
                    except Exception:
                        pass
        else:
            log_files = [
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/log/messages",
                "/var/log/kern.log",
            ]

            for log_path in log_files:
                if not os.path.exists(log_path):
                    continue

                try:
                    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()[-100:]
                        for line in lines:
                            line_str = line.strip()
                            if not line_str:
                                continue
                            events.append({
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "source": os.path.basename(log_path),
                                "event_type": "LOG_ENTRY",
                                "message": line_str[:300],
                            })
                except (PermissionError, OSError):
                    events.append({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "source": os.path.basename(log_path),
                        "event_type": "PERMISSION_DENIED",
                        "message": f"Access denied to {log_path}",
                    })

        finished_at = datetime.now(timezone.utc).isoformat()
        return {
            "collector": self.name,
            "target": target,
            "platform": platform_name,
            "status": "complete",
            "started_at": started_at,
            "finished_at": finished_at,
            "event_count": len(events),
            "events": events,
        }
