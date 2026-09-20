import os
import socket
import struct
import sys
import subprocess
from datetime import datetime, timezone
from typing import Any

try:
    import psutil
except ImportError:
    psutil = None


class NetworkConnectionCollector:
    """
    Collects network socket information from Linux /proc or Windows psutil/netstat.

    Sources:
        /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6
        or psutil.net_connections / netstat.

    The collector maps socket endpoints back to owning processes.
    """

    name = "network.connections"

    TCP_STATES = {
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "04": "FIN_WAIT1",
        "05": "FIN_WAIT2",
        "06": "TIME_WAIT",
        "07": "CLOSE",
        "08": "CLOSE_WAIT",
        "09": "LAST_ACK",
        "0A": "LISTEN",
        "0B": "CLOSING",
    }

    def collect(
        self,
        target: str = "LOCAL",
    ) -> dict[str, Any]:

        started_at = datetime.now(
            timezone.utc
        ).isoformat()

        platform_name = "windows" if sys.platform.startswith("win32") else sys.platform
        connections = []

        if os.path.exists("/proc/net/tcp"):
            inode_map = self._build_inode_map()
            files = [
                ("/proc/net/tcp", "tcp", 4),
                ("/proc/net/tcp6", "tcp6", 6),
                ("/proc/net/udp", "udp", 4),
                ("/proc/net/udp6", "udp6", 6),
            ]

            for path, protocol, address_family in files:
                try:
                    entries = self._read_proc_net(
                        path,
                        protocol,
                        address_family,
                        inode_map,
                    )
                    connections.extend(entries)
                except (
                    FileNotFoundError,
                    PermissionError,
                    OSError,
                ):
                    continue
        elif psutil is not None:
            try:
                raw_conns = psutil.net_connections(kind="all")
                proc_cache = {}
                for conn in raw_conns:
                    l_ip, l_port = (conn.laddr.ip, conn.laddr.port) if conn.laddr else (None, None)
                    r_ip, r_port = (conn.raddr.ip, conn.raddr.port) if conn.raddr else (None, None)
                    pid = conn.pid
                    pname, pexe = None, None
                    if pid and pid > 0:
                        if pid not in proc_cache:
                            try:
                                p = psutil.Process(pid)
                                proc_cache[pid] = (p.name(), p.exe())
                            except Exception:
                                proc_cache[pid] = (None, None)
                        pname, pexe = proc_cache[pid]

                    proto_name = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                    connections.append({
                        "protocol": proto_name,
                        "local_ip": l_ip,
                        "local_port": l_port,
                        "remote_ip": r_ip,
                        "remote_port": r_port,
                        "state": conn.status or "UNKNOWN",
                        "socket_inode": None,
                        "pid": pid,
                        "process_name": pname,
                        "executable": pexe,
                    })
            except Exception:
                pass
        else:
            try:
                output = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
                lines = output.strip().splitlines()
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[0].upper() in ("TCP", "UDP"):
                        proto = parts[0].lower()
                        local = parts[1]
                        l_ip, l_port = local.rsplit(":", 1) if ":" in local else (local, 0)
                        try:
                            l_port = int(l_port)
                        except ValueError:
                            l_port = 0
                        if proto == "tcp" and len(parts) >= 5:
                            remote = parts[2]
                            r_ip, r_port = remote.rsplit(":", 1) if ":" in remote else (remote, 0)
                            try:
                                r_port = int(r_port)
                            except ValueError:
                                r_port = 0
                            state = parts[3]
                            pid_str = parts[4]
                        else:
                            r_ip, r_port = None, None
                            state = "UNKNOWN"
                            pid_str = parts[3]
                        pid = int(pid_str) if pid_str.isdigit() else None
                        connections.append({
                            "protocol": proto,
                            "local_ip": l_ip,
                            "local_port": l_port,
                            "remote_ip": r_ip,
                            "remote_port": r_port,
                            "state": state,
                            "socket_inode": None,
                            "pid": pid,
                            "process_name": None,
                            "executable": None,
                        })
            except Exception:
                pass

        connections.sort(
            key=lambda item: (
                item.get("protocol", ""),
                item.get("local_port", 0) or 0,
                item.get("remote_port", 0) or 0,
            )
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
            "connection_count": len(
                connections
            ),
            "connections": connections,
        }

    # ========================================================
    # Read /proc/net files
    # ========================================================

    def _read_proc_net(
        self,
        path: str,
        protocol: str,
        address_family: int,
        inode_map: dict[str, list[dict[str, Any]]],
    ) -> list[dict[str, Any]]:

        results = []

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:

            lines = file.readlines()

        for line in lines[1:]:

            fields = line.split()

            if len(fields) < 10:
                continue

            local_address = fields[1]
            remote_address = fields[2]
            state = fields[3]
            inode = fields[9]

            local_ip, local_port = (
                self._decode_address(
                    local_address,
                    address_family,
                )
            )

            remote_ip, remote_port = (
                self._decode_address(
                    remote_address,
                    address_family,
                )
            )

            owners = inode_map.get(
                inode,
                [],
            )

            if owners:

                for owner in owners:

                    result = {
                        "protocol": protocol,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": self._decode_state(
                            protocol,
                            state,
                        ),
                        "socket_inode": inode,
                        "pid": owner.get("pid"),
                        "process_name": owner.get(
                            "process_name"
                        ),
                        "executable": owner.get(
                            "executable"
                        ),
                    }

                    results.append(result)

            else:

                results.append(
                    {
                        "protocol": protocol,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": self._decode_state(
                            protocol,
                            state,
                        ),
                        "socket_inode": inode,
                        "pid": None,
                        "process_name": None,
                        "executable": None,
                    }
                )

        return results

    # ========================================================
    # Decode addresses
    # ========================================================

    def _decode_address(
        self,
        value: str,
        address_family: int,
    ) -> tuple[str, int]:

        address, port_hex = value.split(":")

        port = int(
            port_hex,
            16,
        )

        if address_family == 4:

            raw = bytes.fromhex(address)

            ip = socket.inet_ntoa(
                struct.pack(
                    "<I",
                    int.from_bytes(
                        raw,
                        byteorder="big",
                    ),
                )
            )

            return ip, port

        # Linux stores IPv6 values in /proc/net/tcp6
        # as four little-endian 32-bit words.

        raw = bytes.fromhex(address)

        converted = bytearray()

        for index in range(0, 16, 4):

            word = raw[
                index:index + 4
            ]

            converted.extend(
                reversed(word)
            )

        ip = socket.inet_ntop(
            socket.AF_INET6,
            bytes(converted),
        )

        return ip, port

    # ========================================================
    # Connection state
    # ========================================================

    def _decode_state(
        self,
        protocol: str,
        state: str,
    ) -> str:

        if protocol.startswith("tcp"):
            return self.TCP_STATES.get(
                state.upper(),
                f"UNKNOWN({state})",
            )

        return "UNCONNECTED" if state == "07" else state

    # ========================================================
    # Build socket inode → process map
    # ========================================================

    def _build_inode_map(
        self,
    ) -> dict[str, list[dict[str, Any]]]:

        inode_map: dict[
            str,
            list[dict[str, Any]]
        ] = {}

        if not os.path.exists("/proc"):
            return inode_map

        for entry in os.listdir("/proc"):

            if not entry.isdigit():
                continue

            pid = int(entry)

            fd_path = f"/proc/{pid}/fd"

            try:

                for fd in os.listdir(fd_path):

                    link_path = (
                        f"{fd_path}/{fd}"
                    )

                    try:

                        target = os.readlink(
                            link_path
                        )

                    except (
                        OSError,
                        PermissionError,
                    ):
                        continue

                    if not target.startswith(
                        "socket:["
                    ):
                        continue

                    inode = target[
                        8:-1
                    ]

                    owner = {
                        "pid": pid,
                        "process_name": (
                            self._read_process_name(
                                pid
                            )
                        ),
                        "executable": (
                            self._read_executable(
                                pid
                            )
                        ),
                    }

                    inode_map.setdefault(
                        inode,
                        [],
                    ).append(owner)

            except (
                OSError,
                PermissionError,
                FileNotFoundError,
            ):
                continue

        return inode_map

    # ========================================================
    # Process name
    # ========================================================

    def _read_process_name(
        self,
        pid: int,
    ) -> str | None:

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
    # Process executable
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
