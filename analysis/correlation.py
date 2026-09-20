from datetime import datetime, timezone
from typing import Any


class CorrelationEngine:
    """
    Correlates already-collected forensic datasets.

    Supported correlations:
        processes <-> network.connections
        processes <-> filesystem.recent
        processes <-> memory.indicators
        ioc       <-> processes
        ioc       <-> network.connections
        ioc       <-> filesystem.recent
        processes <-> binaries
        generic   (any other pair)
    """

    name = "correlation"

    def correlate(
        self,
        left_source: str,
        right_source: str,
        collected_data: dict[str, Any],
        analysis_results: dict[str, Any] | None = None,
    ) -> dict[str, Any]:

        started_at = datetime.now(timezone.utc).isoformat()

        if analysis_results is None:
            analysis_results = {}

        pair = tuple(sorted([left_source, right_source]))

        if pair == tuple(sorted(["processes", "network.connections"])):
            result = self._correlate_processes_network(collected_data)

        elif pair == tuple(sorted(["processes", "filesystem.recent"])):
            result = self._correlate_processes_filesystem(collected_data)

        elif pair == tuple(sorted(["processes", "memory.indicators"])):
            result = self._correlate_processes_memory(collected_data)

        elif pair == tuple(sorted(["ioc", "processes"])):
            result = self._correlate_ioc_processes(collected_data, analysis_results)

        elif pair == tuple(sorted(["ioc", "network.connections"])):
            result = self._correlate_ioc_network(collected_data, analysis_results)

        elif pair == tuple(sorted(["ioc", "filesystem.recent"])):
            result = self._correlate_ioc_filesystem(collected_data, analysis_results)

        elif pair == tuple(sorted(["processes", "binaries"])):
            result = self._correlate_processes_binaries(collected_data)

        else:
            result = self._generic_correlation(
                left_source,
                right_source,
                collected_data,
                analysis_results,
            )

        finished_at = datetime.now(timezone.utc).isoformat()

        result["engine"] = self.name
        result["started_at"] = started_at
        result["finished_at"] = finished_at

        return result

    # ============================================================
    # PROCESS <-> NETWORK
    # ============================================================

    def _correlate_processes_network(
        self,
        collected_data: dict[str, Any],
    ) -> dict[str, Any]:

        process_data = collected_data.get("processes") or {}
        network_data = collected_data.get("network.connections") or {}

        processes = process_data.get("processes", [])
        connections = network_data.get("connections", [])

        if not processes:
            return self._missing("process_network_correlation", "process data")

        if not connections:
            return {
                "type": "process_network_correlation",
                "status": "missing_network_data",
                "process_count": len(processes),
                "network_connection_count": 0,
                "correlated_connection_count": 0,
                "unmapped_connection_count": 0,
                "processes_with_network_activity": 0,
                "processes": [],
                "unmapped": [],
                "explanation": "No network connections were collected.",
            }

        process_map = {
            p["pid"]: p for p in processes if isinstance(p.get("pid"), int)
        }

        correlated_by_pid: dict[int, dict[str, Any]] = {}
        unmapped = []
        correlated_count = 0

        for connection in connections:
            pid = connection.get("pid")

            if not isinstance(pid, int) or pid not in process_map:
                unmapped.append(self._build_unmapped_connection(connection))
                continue

            process = process_map[pid]

            if pid not in correlated_by_pid:
                correlated_by_pid[pid] = {
                    "pid": pid,
                    "process_name": process.get("name"),
                    "user": process.get("user"),
                    "executable": process.get("executable"),
                    "command_line": process.get("command_line", []),
                    "parent_pid": process.get("parent_pid"),
                    "thread_count": process.get("thread_count"),
                    "connections": [],
                    "explanation": [
                        f"Process '{process.get('name')}' (PID {pid}) owns network connections."
                    ],
                }

            correlated_by_pid[pid]["connections"].append(
                self._build_connection_record(connection)
            )
            correlated_count += 1

        process_results = sorted(
            correlated_by_pid.values(), key=lambda x: x.get("pid", 0)
        )

        return {
            "type": "process_network_correlation",
            "status": "success",
            "process_count": len(processes),
            "network_connection_count": len(connections),
            "correlated_connection_count": correlated_count,
            "unmapped_connection_count": len(unmapped),
            "processes_with_network_activity": len(process_results),
            "processes": process_results,
            "unmapped": unmapped,
            "explanation": (
                f"{len(process_results)} processes matched to {correlated_count} connections. "
                f"{len(unmapped)} connections had no matching process."
            ),
        }

    # ============================================================
    # PROCESS <-> FILESYSTEM
    # ============================================================

    def _correlate_processes_filesystem(
        self,
        collected_data: dict[str, Any],
    ) -> dict[str, Any]:

        process_data = collected_data.get("processes") or {}
        fs_data = collected_data.get("filesystem.recent") or {}

        processes = process_data.get("processes", [])
        files = fs_data.get("files", [])

        if not processes:
            return self._missing("process_filesystem_correlation", "process data")
        if not files:
            return self._missing("process_filesystem_correlation", "filesystem data")

        process_executables = {
            p.get("executable", ""): p
            for p in processes
            if p.get("executable")
        }

        file_paths = {f.get("path", ""): f for f in files}

        overlap = []
        for exe_path, process in process_executables.items():
            if exe_path in file_paths:
                file_info = file_paths[exe_path]
                overlap.append({
                    "type": "executable_in_filesystem",
                    "pid": process.get("pid"),
                    "process_name": process.get("name"),
                    "executable": exe_path,
                    "file_sha256": file_info.get("sha256"),
                    "file_size": file_info.get("size"),
                    "file_mode": file_info.get("mode"),
                    "modified_time": file_info.get("modified_time"),
                    "explanation": [
                        f"Process '{process.get('name')}' (PID {process.get('pid')}) "
                        f"executable '{exe_path}' was found in recent filesystem scan.",
                        f"SHA-256: {file_info.get('sha256', 'N/A')}",
                    ],
                })

        return {
            "type": "process_filesystem_correlation",
            "status": "success",
            "process_count": len(processes),
            "file_count": len(files),
            "overlap_count": len(overlap),
            "overlaps": overlap,
            "explanation": (
                f"{len(overlap)} processes have executables appearing in the recent filesystem scan."
            ),
        }

    # ============================================================
    # PROCESS <-> MEMORY
    # ============================================================

    def _correlate_processes_memory(
        self,
        collected_data: dict[str, Any],
    ) -> dict[str, Any]:

        process_data = collected_data.get("processes") or {}
        mem_data = collected_data.get("memory.indicators") or {}

        processes = process_data.get("processes", [])
        indicators = mem_data.get("indicators", [])

        if not processes:
            return self._missing("process_memory_correlation", "process data")
        if not indicators:
            return self._missing("process_memory_correlation", "memory indicator data")

        process_map = {
            p.get("pid"): p for p in processes if p.get("pid") is not None
        }

        matched = []
        for indicator in indicators:
            pid = indicator.get("pid")
            if pid and pid in process_map:
                proc = process_map[pid]
                matched.append({
                    "pid": pid,
                    "process_name": proc.get("name"),
                    "indicator_type": indicator.get("type"),
                    "indicator_value": indicator.get("value"),
                    "severity": indicator.get("severity"),
                    "explanation": [
                        f"Memory indicator '{indicator.get('type')}' found in "
                        f"process '{proc.get('name')}' (PID {pid}).",
                    ],
                })

        return {
            "type": "process_memory_correlation",
            "status": "success",
            "process_count": len(processes),
            "indicator_count": len(indicators),
            "matched_count": len(matched),
            "matches": matched,
            "explanation": (
                f"{len(matched)} memory indicators correlated with running processes."
            ),
        }

    # ============================================================
    # IOC <-> PROCESSES
    # ============================================================

    def _correlate_ioc_processes(
        self,
        collected_data: dict[str, Any],
        analysis_results: dict[str, Any],
    ) -> dict[str, Any]:

        ioc_result = analysis_results.get("ioc") or {}
        ioc_findings = ioc_result.get("findings", [])
        processes = (collected_data.get("processes") or {}).get("processes", [])

        if not ioc_findings:
            return self._missing("ioc_process_correlation", "IOC findings")
        if not processes:
            return self._missing("ioc_process_correlation", "process data")

        process_executables = {
            p.get("executable", ""): p for p in processes if p.get("executable")
        }
        process_names = {
            p.get("name", ""): p for p in processes if p.get("name")
        }

        matches = []
        for finding in ioc_findings:
            ioc_value = str(finding.get("ioc_value", ""))
            for exe, proc in process_executables.items():
                if ioc_value and ioc_value in exe:
                    matches.append({
                        "ioc_value": ioc_value,
                        "ioc_type": finding.get("ioc_type"),
                        "pid": proc.get("pid"),
                        "process_name": proc.get("name"),
                        "executable": exe,
                        "explanation": [
                            f"IOC '{ioc_value}' matched executable of "
                            f"process '{proc.get('name')}' (PID {proc.get('pid')}).",
                        ],
                    })
            for name, proc in process_names.items():
                if ioc_value and ioc_value in name:
                    matches.append({
                        "ioc_value": ioc_value,
                        "ioc_type": finding.get("ioc_type"),
                        "pid": proc.get("pid"),
                        "process_name": proc.get("name"),
                        "match_type": "process_name",
                        "explanation": [
                            f"IOC '{ioc_value}' matched running process "
                            f"name '{name}' (PID {proc.get('pid')}).",
                        ],
                    })

        return {
            "type": "ioc_process_correlation",
            "status": "success",
            "ioc_finding_count": len(ioc_findings),
            "process_count": len(processes),
            "match_count": len(matches),
            "matches": matches,
            "explanation": (
                f"{len(matches)} IOC hits matched against {len(processes)} running processes."
            ),
        }

    # ============================================================
    # IOC <-> NETWORK
    # ============================================================

    def _correlate_ioc_network(
        self,
        collected_data: dict[str, Any],
        analysis_results: dict[str, Any],
    ) -> dict[str, Any]:

        ioc_result = analysis_results.get("ioc") or {}
        ioc_findings = ioc_result.get("findings", [])
        connections = (collected_data.get("network.connections") or {}).get("connections", [])

        if not ioc_findings:
            return self._missing("ioc_network_correlation", "IOC findings")
        if not connections:
            return self._missing("ioc_network_correlation", "network connection data")

        matches = []
        for finding in ioc_findings:
            ioc_value = str(finding.get("ioc_value", ""))
            for conn in connections:
                remote_ip = str(conn.get("remote_ip", ""))
                remote_host = str(conn.get("remote_host", ""))
                if ioc_value and (ioc_value == remote_ip or ioc_value in remote_host):
                    matches.append({
                        "ioc_value": ioc_value,
                        "ioc_type": finding.get("ioc_type"),
                        "remote_ip": remote_ip,
                        "remote_port": conn.get("remote_port"),
                        "protocol": conn.get("protocol"),
                        "pid": conn.get("pid"),
                        "explanation": [
                            f"IOC '{ioc_value}' matched network connection "
                            f"to {remote_ip}:{conn.get('remote_port')} ({conn.get('protocol')}).",
                        ],
                    })

        return {
            "type": "ioc_network_correlation",
            "status": "success",
            "ioc_finding_count": len(ioc_findings),
            "connection_count": len(connections),
            "match_count": len(matches),
            "matches": matches,
            "explanation": (
                f"{len(matches)} IOC hits matched active network connections."
            ),
        }

    # ============================================================
    # IOC <-> FILESYSTEM
    # ============================================================

    def _correlate_ioc_filesystem(
        self,
        collected_data: dict[str, Any],
        analysis_results: dict[str, Any],
    ) -> dict[str, Any]:

        ioc_result = analysis_results.get("ioc") or {}
        ioc_findings = ioc_result.get("findings", [])
        files = (collected_data.get("filesystem.recent") or {}).get("files", [])

        if not ioc_findings:
            return self._missing("ioc_filesystem_correlation", "IOC findings")
        if not files:
            return self._missing("ioc_filesystem_correlation", "filesystem data")

        matches = []
        for finding in ioc_findings:
            ioc_value = str(finding.get("ioc_value", ""))
            for file_rec in files:
                path = str(file_rec.get("path", ""))
                sha256 = str(file_rec.get("sha256", ""))
                if ioc_value and (ioc_value in path or ioc_value == sha256):
                    matches.append({
                        "ioc_value": ioc_value,
                        "ioc_type": finding.get("ioc_type"),
                        "path": path,
                        "sha256": sha256,
                        "explanation": [
                            f"IOC '{ioc_value}' matched filesystem path or hash: {path}.",
                        ],
                    })

        return {
            "type": "ioc_filesystem_correlation",
            "status": "success",
            "ioc_finding_count": len(ioc_findings),
            "file_count": len(files),
            "match_count": len(matches),
            "matches": matches,
            "explanation": (
                f"{len(matches)} IOC hits matched filesystem entries."
            ),
        }

    # ============================================================
    # PROCESS <-> BINARIES
    # ============================================================

    def _correlate_processes_binaries(
        self,
        collected_data: dict[str, Any],
    ) -> dict[str, Any]:

        process_data = collected_data.get("processes") or {}
        binary_data = collected_data.get("binaries") or {}

        processes = process_data.get("processes", [])
        binaries = binary_data.get("binaries", [])

        if not processes:
            return self._missing("process_binary_correlation", "process data")
        if not binaries:
            return self._missing("process_binary_correlation", "binary scan data")

        binary_paths = {b.get("path", ""): b for b in binaries}

        matches = []
        for proc in processes:
            exe = proc.get("executable", "")
            if exe and exe in binary_paths:
                bin_rec = binary_paths[exe]
                matches.append({
                    "pid": proc.get("pid"),
                    "process_name": proc.get("name"),
                    "executable": exe,
                    "sha256": bin_rec.get("sha256"),
                    "size": bin_rec.get("size"),
                    "mode": bin_rec.get("mode"),
                    "modified_time": bin_rec.get("modified_time"),
                    "explanation": [
                        f"Process '{proc.get('name')}' (PID {proc.get('pid')}) "
                        f"running binary found in scan: {exe}",
                        f"SHA-256: {bin_rec.get('sha256', 'N/A')}",
                    ],
                })

        return {
            "type": "process_binary_correlation",
            "status": "success",
            "process_count": len(processes),
            "binary_count": len(binaries),
            "match_count": len(matches),
            "matches": matches,
            "explanation": (
                f"{len(matches)} running processes matched binary scan records."
            ),
        }

    # ============================================================
    # GENERIC
    # ============================================================

    def _generic_correlation(
        self,
        left_source: str,
        right_source: str,
        collected_data: dict[str, Any],
        analysis_results: dict[str, Any],
    ) -> dict[str, Any]:

        left_available = left_source in collected_data
        right_available = right_source in collected_data

        return {
            "type": "generic_correlation",
            "status": "available",
            "left": left_source,
            "right": right_source,
            "left_available": left_available,
            "right_available": right_available,
            "left_analyzed": left_source in analysis_results,
            "right_analyzed": right_source in analysis_results,
            "explanation": (
                f"Generic correlation between '{left_source}' and '{right_source}' "
                f"(no specialized correlator registered for this pair)."
            ),
        }

    # ============================================================
    # HELPERS
    # ============================================================

    def _missing(self, corr_type: str, what: str) -> dict[str, Any]:
        return {
            "type": corr_type,
            "status": f"missing_{what.replace(' ', '_')}",
            "explanation": f"Cannot correlate: {what} not collected.",
            "match_count": 0,
            "matches": [],
        }

    def _build_connection_record(self, connection: dict[str, Any]) -> dict[str, Any]:
        return {
            "protocol": connection.get("protocol"),
            "local_ip": connection.get("local_ip"),
            "local_port": connection.get("local_port"),
            "remote_ip": connection.get("remote_ip"),
            "remote_port": connection.get("remote_port"),
            "state": connection.get("state"),
            "socket_inode": connection.get("socket_inode"),
        }

    def _build_unmapped_connection(self, connection: dict[str, Any]) -> dict[str, Any]:
        return {
            "pid": connection.get("pid"),
            "process_name": connection.get("process_name"),
            "executable": connection.get("executable"),
            "protocol": connection.get("protocol"),
            "local_ip": connection.get("local_ip"),
            "local_port": connection.get("local_port"),
            "remote_ip": connection.get("remote_ip"),
            "remote_port": connection.get("remote_port"),
            "state": connection.get("state"),
            "socket_inode": connection.get("socket_inode"),
        }
