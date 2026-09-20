from datetime import datetime, timezone
from typing import Any


class NetworkAnalyzer:
    """
    Defensive forensic analyzer for network connection data.

    This analyzer identifies connections that deserve
    investigation and preserves the process ownership
    information collected from the Linux host.
    """

    name = "network.connections"

    PRIVATE_NETWORKS = (
        "127.",
        "10.",
        "192.168.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
    )

    COMMON_PORTS = {
        22: "SSH",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-ALT",
    }

    def analyze(
        self,
        data: dict[str, Any],
    ) -> dict[str, Any]:

        started_at = datetime.now(
            timezone.utc
        ).isoformat()

        connections = data.get(
            "connections",
            [],
        )

        findings = []

        for connection in connections:

            findings.extend(
                self._analyze_connection(
                    connection
                )
            )

        severity_counts = {
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for finding in findings:

            severity = finding.get(
                "severity",
                "low",
            )

            if severity in severity_counts:
                severity_counts[severity] += 1

        finished_at = datetime.now(
            timezone.utc
        ).isoformat()

        return {
            "analyzer": self.name,
            "status": "complete",
            "started_at": started_at,
            "finished_at": finished_at,
            "connection_count": len(
                connections
            ),
            "finding_count": len(
                findings
            ),
            "severity_counts": (
                severity_counts
            ),
            "findings": findings,
        }

    def _analyze_connection(
        self,
        connection: dict[str, Any],
    ) -> list[dict[str, Any]]:

        findings = []

        protocol = connection.get(
            "protocol"
        )

        local_ip = connection.get(
            "local_ip"
        )

        local_port = connection.get(
            "local_port"
        )

        remote_ip = connection.get(
            "remote_ip"
        )

        remote_port = connection.get(
            "remote_port"
        )

        state = connection.get(
            "state"
        )

        pid = connection.get(
            "pid"
        )

        process_name = connection.get(
            "process_name"
        )

        executable = connection.get(
            "executable"
        )

        # ----------------------------------------------------
        # Connection without process ownership
        # ----------------------------------------------------

        if pid is None:

            findings.append(
                self._finding(
                    severity="low",
                    category="ownership",
                    rule="UNMAPPED_SOCKET",
                    description=(
                        f"[Source: network.connections] Network socket ({protocol} {local_ip}:{local_port} -> {remote_ip or '*'}:{remote_port or '*'}, state: {state}) "
                        f"could not be associated with any active process PID. Why suspicious: Unmapped sockets may indicate transient connections, "
                        f"hidden process sockets, or kernel-level network listeners."
                    ),
                    evidence={
                        "protocol": protocol,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": state,
                    },
                )
            )

        # ----------------------------------------------------
        # Listening service
        # ----------------------------------------------------

        if state == "LISTEN":

            service_label = self.COMMON_PORTS.get(local_port, "custom/unknown")
            findings.append(
                self._finding(
                    severity="low",
                    category="network_service",
                    rule="LISTENING_SERVICE",
                    description=(
                        f"[Source: network.connections] Process '{process_name or 'unknown'}' (PID {pid or 'N/A'}) is listening for "
                        f"incoming connections on {local_ip}:{local_port} ({service_label}). Why suspicious: Active listening ports expose system services "
                        f"to network probes and potential remote ingress."
                    ),
                    evidence={
                        "pid": pid,
                        "process_name": process_name,
                        "executable": executable,
                        "protocol": protocol,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "service": service_label,
                    },
                )
            )

        # ----------------------------------------------------
        # External established connection
        # ----------------------------------------------------

        if (
            state == "ESTABLISHED"
            and remote_ip
            and not self._is_private_ip(
                remote_ip
            )
        ):

            findings.append(
                self._finding(
                    severity="low",
                    category="external_communication",
                    rule="EXTERNAL_ESTABLISHED_CONNECTION",
                    description=(
                        f"[Source: network.connections] Process '{process_name or 'unknown'}' (PID {pid or 'N/A'}) has an active "
                        f"connection to external public IP {remote_ip}:{remote_port} ({protocol}). Why suspicious: Outbound connections to external public "
                        f"addresses warrant review for Command & Control (C2) communication or telemetry/exfiltration."
                    ),
                    evidence={
                        "pid": pid,
                        "process_name": process_name,
                        "executable": executable,
                        "protocol": protocol,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": state,
                    },
                )
            )

        # ----------------------------------------------------
        # Unusual remote port
        #
        # This is deliberately LOW severity because an
        # unusual port is not automatically malicious.
        # ----------------------------------------------------

        if (
            state == "ESTABLISHED"
            and isinstance(remote_port, int)
            and remote_port not in self.COMMON_PORTS
            and remote_port > 1024
        ):

            findings.append(
                self._finding(
                    severity="low",
                    category="remote_port",
                    rule="UNCOMMON_REMOTE_PORT",
                    description=(
                        f"[Source: network.connections] Process '{process_name or 'unknown'}' (PID {pid or 'N/A'}) connected to non-standard "
                        f"remote port {remote_port} at {remote_ip}. Why suspicious: Communications over high non-standard ports can be used to bypass "
                        f"standard port-filtered firewalls."
                    ),
                    evidence={
                        "pid": pid,
                        "process_name": process_name,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                    },
                )
            )

        return findings

    def _is_private_ip(
        self,
        ip: str,
    ) -> bool:

        if not ip:
            return True

        if ip == "localhost":
            return True

        for prefix in self.PRIVATE_NETWORKS:

            if ip.startswith(prefix):
                return True

        if ip == "::1":
            return True

        if ip.startswith("fc"):
            return True

        if ip.startswith("fd"):
            return True

        if ip.startswith("fe80:"):
            return True

        return False

    def _finding(
        self,
        severity: str,
        category: str,
        rule: str,
        description: str,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "source": self.name,

            "severity": severity,

            "category": category,

            "rule": rule,

            "description": description,

            "evidence": evidence,
        }
