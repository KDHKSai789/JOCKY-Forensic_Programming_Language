import os
import sys
from datetime import datetime, timezone
from typing import Any

try:
    import pwd
except ImportError:
    pwd = None

try:
    import psutil
except ImportError:
    psutil = None


class ProcessCollector:
    """
    Collects information about currently running processes
    on Linux and Windows host systems.

    The collector uses the Linux /proc filesystem or cross-platform
    psutil / system APIs.
    """

    name = "processes"

    def collect(self, target: str = "LOCAL") -> dict[str, Any]:
        """
        Collect process information from the local host.
        """

        started_at = datetime.now(
            timezone.utc
        ).isoformat()

        processes = []
        platform_name = "windows" if sys.platform.startswith("win32") else sys.platform

        if os.path.exists("/proc"):
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue

                pid = int(entry)

                try:
                    process = self._collect_process(pid)
                    if process is not None:
                        processes.append(process)
                except (
                    PermissionError,
                    FileNotFoundError,
                    ProcessLookupError,
                ):
                    continue
                except Exception as error:
                    processes.append(
                        {
                            "pid": pid,
                            "collection_error": str(error),
                        }
                    )
        elif psutil is not None:
            for proc in psutil.process_iter([
                "pid", "name", "cmdline", "status", "ppid", "username", "exe", "cwd", "num_threads"
            ]):
                try:
                    info = proc.info
                    processes.append({
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "command_line": info.get("cmdline") or [],
                        "state": info.get("status"),
                        "parent_pid": info.get("ppid"),
                        "user": info.get("username"),
                        "executable": info.get("exe"),
                        "working_directory": info.get("cwd"),
                        "thread_count": info.get("num_threads"),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as error:
                    processes.append({
                        "pid": getattr(proc, "pid", 0),
                        "collection_error": str(error),
                    })
        else:
            # Fallback for Windows without psutil
            import subprocess
            try:
                output = subprocess.check_output(["tasklist", "/fo", "csv", "/v"], text=True, errors="replace")
                lines = output.strip().splitlines()
                if len(lines) > 1:
                    headers = [h.strip('"') for h in lines[0].split('","')]
                    for line in lines[1:]:
                        parts = [p.strip('"') for p in line.split('","')]
                        if len(parts) >= 2 and parts[1].isdigit():
                            pid = int(parts[1])
                            processes.append({
                                "pid": pid,
                                "name": parts[0],
                                "command_line": [parts[0]],
                                "state": "running",
                                "parent_pid": None,
                                "user": parts[6] if len(parts) > 6 else None,
                                "executable": parts[0],
                                "working_directory": None,
                                "thread_count": 1,
                            })
            except Exception as error:
                processes.append({"collection_error": str(error)})

        processes.sort(
            key=lambda process: process.get(
                "pid",
                0
            ) or 0
        )

        finished_at = datetime.now(
            timezone.utc
        ).isoformat()

        return {
            "collector": self.name,
            "target": target,
            "platform": platform_name,
            "started_at": started_at,
            "finished_at": finished_at,
            "process_count": len(processes),
            "processes": processes,
        }

    # ========================================================
    # Collect one process
    # ========================================================

    def _collect_process(
        self,
        pid: int,
    ) -> dict[str, Any] | None:

        proc_path = f"/proc/{pid}"

        if not os.path.exists(proc_path):
            return None

        process = {
            "pid": pid,
            "name": self._read_name(pid),
            "command_line": self._read_cmdline(pid),
            "state": self._read_state(pid),
            "parent_pid": self._read_parent_pid(pid),
            "user": self._read_user(pid),
            "executable": self._read_executable(pid),
            "working_directory": self._read_cwd(pid),
            "thread_count": self._read_thread_count(pid),
        }

        return process

    # ========================================================
    # Process name
    # ========================================================

    def _read_name(self, pid: int) -> str | None:

        try:

            with open(
                f"/proc/{pid}/comm",
                "r",
                encoding="utf-8",
                errors="replace",
            ) as file:

                return file.read().strip()

        except (
            OSError,
            PermissionError,
        ):

            return None

    # ========================================================
    # Command line
    # ========================================================

    def _read_cmdline(
        self,
        pid: int,
    ) -> list[str]:

        try:

            with open(
                f"/proc/{pid}/cmdline",
                "rb",
            ) as file:

                data = file.read()

            if not data:
                return []

            return [
                argument.decode(
                    "utf-8",
                    errors="replace",
                )
                for argument in data.split(
                    b"\x00"
                )
                if argument
            ]

        except (
            OSError,
            PermissionError,
        ):

            return []

    # ========================================================
    # Process state
    # ========================================================

    def _read_state(
        self,
        pid: int,
    ) -> str | None:

        try:

            with open(
                f"/proc/{pid}/status",
                "r",
                encoding="utf-8",
                errors="replace",
            ) as file:

                for line in file:

                    if line.startswith("State:"):

                        return line.split(
                            ":", 1
                        )[1].strip()

        except (
            OSError,
            PermissionError,
        ):

            pass

        return None

    # ========================================================
    # Parent PID
    # ========================================================

    def _read_parent_pid(
        self,
        pid: int,
    ) -> int | None:

        try:

            with open(
                f"/proc/{pid}/stat",
                "r",
                encoding="utf-8",
                errors="replace",
            ) as file:

                data = file.read()

            closing_parenthesis = data.rfind(")")

            if closing_parenthesis == -1:
                return None

            remaining = data[
                closing_parenthesis + 2:
            ]

            fields = remaining.split()

            # After the process name:
            # field 0 = state
            # field 1 = parent PID

            if len(fields) < 2:
                return None

            return int(fields[1])

        except (
            OSError,
            PermissionError,
            ValueError,
        ):

            return None

    # ========================================================
    # User
    # ========================================================

    def _read_user(
        self,
        pid: int,
    ) -> str | None:

        try:

            stat = os.stat(
                f"/proc/{pid}"
            )

            if pwd is not None:
                return pwd.getpwuid(
                    stat.st_uid
                ).pw_name
            return str(stat.st_uid)

        except (
            OSError,
            PermissionError,
            KeyError,
        ):

            return None

    # ========================================================
    # Executable
    # ========================================================

    def _read_executable(
        self,
        pid: int,
    ) -> str | None:

        try:

            return os.readlink(
                f"/proc/{pid}/exe"
            )

        except (
            OSError,
            PermissionError,
        ):

            return None

    # ========================================================
    # Working directory
    # ========================================================

    def _read_cwd(
        self,
        pid: int,
    ) -> str | None:

        try:

            return os.readlink(
                f"/proc/{pid}/cwd"
            )

        except (
            OSError,
            PermissionError,
        ):

            return None

    # ========================================================
    # Thread count
    # ========================================================

    def _read_thread_count(
        self,
        pid: int,
    ) -> int | None:

        try:

            with open(
                f"/proc/{pid}/status",
                "r",
                encoding="utf-8",
                errors="replace",
            ) as file:

                for line in file:

                    if line.startswith("Threads:"):

                        return int(
                            line.split(
                                ":",
                                1
                            )[1].strip()
                        )

        except (
            OSError,
            PermissionError,
            ValueError,
        ):

            pass

        return None
