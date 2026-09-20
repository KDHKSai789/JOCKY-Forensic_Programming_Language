import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class IOCAnalyzer:
    """
    Defensive IOC analyzer.

    Supports:
        - IPv4 / IPv6 addresses
        - SHA-256 hashes
        - File paths
        - Domain names
        - Command-line indicators

    Matching is contextual to reduce false positives.
    """

    name = "ioc"

    SHA256_RE = re.compile(
        r"^[a-fA-F0-9]{64}$"
    )

    DOMAIN_RE = re.compile(
        r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    )

    def __init__(self):
        pass

    # ---------------------------------------------------------
    # IOC FILE
    # ---------------------------------------------------------

    def _load_iocs(self, filename: str) -> list[str]:

        path = Path(filename)

        if not path.exists():
            raise FileNotFoundError(
                f"IOC file not found: {filename}"
            )

        iocs = []

        with path.open(
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            for line in file:

                value = line.strip()

                if not value:
                    continue

                if value.startswith("#"):
                    continue

                iocs.append(value)

        return iocs

    # ---------------------------------------------------------
    # IOC TYPE DETECTION
    # ---------------------------------------------------------

    def _ioc_type(self, value: str) -> str:

        # SHA-256
        if self.SHA256_RE.fullmatch(value):
            return "sha256"

        # IP address
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass

        # Domain
        if self.DOMAIN_RE.fullmatch(value):
            return "domain"

        # Absolute filesystem path
        if value.startswith("/"):
            return "path"

        # Windows absolute path
        if re.match(
            r"^[A-Za-z]:[\\/]",
            value,
        ):
            return "path"

        return "text"

    # ---------------------------------------------------------
    # NORMALIZATION
    # ---------------------------------------------------------

    def _normalize(self, value: Any) -> str:

        if value is None:
            return ""

        return str(value).strip()

    def _normalize_domain(self, value: str) -> str:

        value = value.lower().strip()

        if value.startswith("http://"):
            value = value[7:]

        if value.startswith("https://"):
            value = value[8:]

        value = value.split("/")[0]
        value = value.split(":")[0]

        return value.rstrip(".")

    def _normalize_path(self, value: str) -> str:

        value = value.strip()

        try:
            return str(
                Path(value).resolve()
            )
        except Exception:
            return value

    # ---------------------------------------------------------
    # MATCHING
    # ---------------------------------------------------------

    def _match_value(
        self,
        ioc: str,
        value: Any,
    ) -> bool:

        if value is None:
            return False

        candidate = self._normalize(value)

        if not candidate:
            return False

        ioc_type = self._ioc_type(ioc)

        # SHA-256 must match exactly.
        if ioc_type == "sha256":

            return (
                candidate.lower()
                == ioc.lower()
            )

        # IP must match exactly.
        if ioc_type == "ip":

            return candidate == ioc

        # Domains are normalized and matched exactly.
        if ioc_type == "domain":

            return (
                self._normalize_domain(candidate)
                == self._normalize_domain(ioc)
            )

        # Paths use normalized exact matching.
        if ioc_type == "path":

            return (
                self._normalize_path(candidate)
                == self._normalize_path(ioc)
            )

        # Text IOCs use case-insensitive
        # token/substring matching.
        return (
            ioc.lower()
            in candidate.lower()
        )

    # ---------------------------------------------------------
    # SEVERITY
    # ---------------------------------------------------------

    def _severity(
        self,
        ioc: str,
        source: str,
        field: str,
    ) -> str:

        ioc_type = self._ioc_type(ioc)

        # Cryptographic hash match is highly specific.
        if ioc_type == "sha256":
            return "high"

        # Exact IP match is strong evidence.
        if ioc_type == "ip":

            if source == "network.connections":
                return "high"

            return "medium"

        # Exact domain match is strong evidence.
        if ioc_type == "domain":
            return "high"

        # Exact suspicious file path.
        if ioc_type == "path":

            if field in {
                "path",
                "executable",
                "working_directory",
            }:
                return "medium"

            return "low"

        # Generic text IOC.
        return "low"

    # ---------------------------------------------------------
    # PROCESS SEARCH
    # ---------------------------------------------------------

    def _search_processes(
        self,
        ioc: str,
        processes: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        findings = []

        for process in processes:

            fields = [
                ("command_line", process.get("command_line")),
                ("executable", process.get("executable")),
                ("working_directory", process.get("working_directory")),
                ("name", process.get("name")),
            ]

            for field, value in fields:

                if isinstance(value, list):

                    values = value

                else:

                    values = [value]

                for item in values:

                    if not self._match_value(
                        ioc,
                        item,
                    ):
                        continue

                    severity = self._severity(
                        ioc,
                        "processes",
                        field,
                    )

                    findings.append(
                        self._create_finding(
                            ioc=ioc,
                            source="processes",
                            field=field,
                            value=item,
                            pid=process.get("pid"),
                            process_name=process.get("name"),
                            severity=severity,
                        )
                    )

        return findings

    # ---------------------------------------------------------
    # NETWORK SEARCH
    # ---------------------------------------------------------

    def _search_network(
        self,
        ioc: str,
        connections: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        findings = []

        fields = [
            "local_ip",
            "remote_ip",
            "local_address",
            "remote_address",
            "remote_port",
        ]

        for connection in connections:

            for field in fields:

                value = connection.get(field)

                if value is None:
                    continue

                if not self._match_value(
                    ioc,
                    value,
                ):
                    continue

                severity = self._severity(
                    ioc,
                    "network.connections",
                    field,
                )

                findings.append(
                    self._create_finding(
                        ioc=ioc,
                        source="network.connections",
                        field=field,
                        value=value,
                        pid=connection.get("pid"),
                        process_name=connection.get(
                            "process_name"
                        ),
                        severity=severity,
                    )
                )

        return findings

    # ---------------------------------------------------------
    # FILESYSTEM SEARCH
    # ---------------------------------------------------------

    def _search_filesystem(
        self,
        ioc: str,
        files: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        findings = []

        fields = [
            "path",
            "name",
            "sha256",
        ]

        for file_record in files:

            for field in fields:

                value = file_record.get(field)

                if value is None:
                    continue

                if not self._match_value(
                    ioc,
                    value,
                ):
                    continue

                severity = self._severity(
                    ioc,
                    "filesystem.recent",
                    field,
                )

                findings.append(
                    self._create_finding(
                        ioc=ioc,
                        source="filesystem.recent",
                        field=field,
                        value=value,
                        pid=None,
                        process_name=None,
                        severity=severity,
                    )
                )

        return findings

    # ---------------------------------------------------------
    # MEMORY SEARCH
    # ---------------------------------------------------------

    def _search_memory(
        self,
        ioc: str,
        memory: dict[str, Any],
    ) -> list[dict[str, Any]]:

        findings = []

        processes = memory.get(
            "processes",
            [],
        )

        for process in processes:

            mappings = process.get(
                "mappings",
                [],
            )

            for mapping in mappings:

                pathname = mapping.get(
                    "pathname"
                )

                if not pathname:
                    continue

                if not self._match_value(
                    ioc,
                    pathname,
                ):
                    continue

                severity = self._severity(
                    ioc,
                    "memory.indicators",
                    "pathname",
                )

                findings.append(
                    self._create_finding(
                        ioc=ioc,
                        source="memory.indicators",
                        field="pathname",
                        value=pathname,
                        pid=process.get("pid"),
                        process_name=process.get(
                            "process_name"
                        ),
                        severity=severity,
                    )
                )

        return findings

    # ---------------------------------------------------------
    # FINDING
    # ---------------------------------------------------------

    def _create_finding(
        self,
        ioc: str,
        source: str,
        field: str,
        value: Any,
        pid: Any,
        process_name: Any,
        severity: str,
    ) -> dict[str, Any]:

        proc_info = f"Process '{process_name}' (PID {pid})" if (pid or process_name) else f"Artifact in '{source}'"
        ioc_type = self._ioc_type(ioc)

        return {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "source": f"ioc.{source}",

            "severity": severity,

            "rule": "IOC_MATCH",

            "description": (
                f"[Source: ioc.{source}] {proc_info} matched IOC indicator '{ioc}' (type: {ioc_type}) "
                f"on field '{field}' = '{value}'. Why suspicious: Direct match against threat indicator database."
            ),

            "evidence": {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "source": source,
                "field": field,
                "value": value,
                "pid": pid,
                "process_name": process_name,
            },
        }

    # ---------------------------------------------------------
    # MAIN ANALYSIS
    # ---------------------------------------------------------

    def analyze(
        self,
        ioc_file: str,
        collected_data: dict[str, Any],
    ) -> dict[str, Any]:

        started = datetime.now(
            timezone.utc
        ).isoformat()

        iocs = self._load_iocs(
            ioc_file
        )

        findings = []

        processes = collected_data.get(
            "processes",
            {},
        )

        if isinstance(processes, dict):
            processes = processes.get(
                "processes",
                [],
            )

        network = collected_data.get(
            "network.connections",
            {},
        )

        if isinstance(network, dict):
            network = network.get(
                "connections",
                [],
            )

        filesystem = collected_data.get(
            "filesystem.recent",
            {},
        )

        if isinstance(filesystem, dict):
            filesystem = filesystem.get(
                "files",
                [],
            )

        memory = collected_data.get(
            "memory.indicators",
            {},
        )

        if not isinstance(memory, dict):
            memory = {}

        for ioc in iocs:

            findings.extend(
                self._search_processes(
                    ioc,
                    processes,
                )
            )

            findings.extend(
                self._search_network(
                    ioc,
                    network,
                )
            )

            findings.extend(
                self._search_filesystem(
                    ioc,
                    filesystem,
                )
            )

            findings.extend(
                self._search_memory(
                    ioc,
                    memory,
                )
            )

        # Remove exact duplicate findings.
        unique = []
        seen = set()

        for finding in findings:

            evidence = finding[
                "evidence"
            ]

            key = (
                evidence.get("ioc"),
                evidence.get("source"),
                evidence.get("field"),
                str(evidence.get("value")),
                evidence.get("pid"),
            )

            if key in seen:
                continue

            seen.add(key)
            unique.append(finding)

        findings = unique

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

            if severity not in severity_counts:
                severity = "low"

            severity_counts[
                severity
            ] += 1

        finished = datetime.now(
            timezone.utc
        ).isoformat()

        return {
            "analyzer": self.name,
            "status": "complete",
            "ioc_file": ioc_file,
            "ioc_count": len(iocs),
            "match_count": len(findings),
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "started_at": started,
            "finished_at": finished,
            "findings": findings,
        }
