from datetime import datetime, timezone
from typing import Any


class ProcessAnalyzer:
    """
    Defensive forensic analyzer for Linux process data.

    The analyzer focuses on meaningful indicators and does
    not treat normal /proc permission limitations as threats.
    """

    name = "processes"

    SUSPICIOUS_PATHS = (
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/run/user/",
        "/appdata/local/temp/",
        "/windows/temp/",
    )

    def analyze(
        self,
        data: dict[str, Any],
    ) -> dict[str, Any]:

        started_at = datetime.now(
            timezone.utc
        ).isoformat()

        processes = data.get(
            "processes",
            [],
        )

        findings = []

        collection_notes = []

        for process in processes:

            findings.extend(
                self._analyze_process(
                    process
                )
            )

            self._collect_metadata_notes(
                process,
                collection_notes,
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

            "process_count": len(
                processes
            ),

            "finding_count": len(
                findings
            ),

            "severity_counts": (
                severity_counts
            ),

            "collection_notes": (
                collection_notes
            ),

            "findings": findings,
        }

    # ========================================================
    # Analyze individual process
    # ========================================================

    def _analyze_process(
        self,
        process: dict[str, Any],
    ) -> list[dict[str, Any]]:

        findings = []

        pid = process.get("pid")
        name = process.get("name")
        executable = process.get(
            "executable"
        )

        command_line = process.get(
            "command_line",
            [],
        )

        thread_count = process.get(
            "thread_count"
        )

        # ----------------------------------------------------
        # Deleted executable
        # ----------------------------------------------------

        if executable and executable.endswith(
            " (deleted)"
        ):

            findings.append(
                self._finding(
                    pid=pid,
                    name=name,
                    severity="high",
                    category="process_integrity",
                    rule="DELETED_EXECUTABLE",
                    description=(
                        f"[Source: processes] Process '{name or 'unknown'}' (PID {pid}) is executing from "
                        f"deleted binary '{executable}'. Why suspicious: Executing binaries that have been deleted "
                        f"from disk is a fileless evasion technique to hinder forensic binary collection."
                    ),
                    evidence={
                        "executable": executable
                    },
                )
            )

        # ----------------------------------------------------
        # Suspicious executable location
        # ----------------------------------------------------

        if executable:

            normalized = executable.lower().replace("\\", "/")

            for path in self.SUSPICIOUS_PATHS:

                if (
                    normalized.startswith(path)
                    or path in normalized
                ):

                    findings.append(
                        self._finding(
                            pid=pid,
                            name=name,
                            severity="medium",
                            category="execution_location",
                            rule=(
                                "SUSPICIOUS_EXECUTION_PATH"
                            ),
                            description=(
                                f"[Source: processes] Process '{name or 'unknown'}' (PID {pid}) executable '{executable}' "
                                f"is running from temporary directory '{path}'. Why suspicious: Legitimate system software "
                                f"rarely runs from temporary or shared-memory paths (/tmp, /var/tmp, /dev/shm), making this a common malware staging location."
                            ),
                            evidence={
                                "executable": executable
                            },
                        )
                    )

                    break

        # ----------------------------------------------------
        # High thread count
        #
        # This is only a weak indicator, so it remains LOW.
        # ----------------------------------------------------

        if (
            isinstance(thread_count, int)
            and thread_count >= 100
        ):

            findings.append(
                self._finding(
                    pid=pid,
                    name=name,
                    severity="low",
                    category="process_behavior",
                    rule="HIGH_THREAD_COUNT",
                    description=(
                        f"[Source: processes] Process '{name or 'unknown'}' (PID {pid}) has an elevated thread count ({thread_count} threads). "
                        f"Why suspicious: Unusually high thread counts can indicate worker pool flooding, miner execution, or process injection."
                    ),
                    evidence={
                        "thread_count": thread_count
                    },
                )
            )

        # ----------------------------------------------------
        # Suspicious command-line location
        # ----------------------------------------------------

        command_text = " ".join(
            str(argument)
            for argument in command_line
        ).lower()

        for path in self.SUSPICIOUS_PATHS:

            if path in command_text:

                cmd_str = " ".join(str(arg) for arg in command_line)
                findings.append(
                    self._finding(
                        pid=pid,
                        name=name,
                        severity="medium",
                        category="command_line",
                        rule=(
                            "SUSPICIOUS_COMMAND_PATH"
                        ),
                        description=(
                            f"[Source: processes] Process '{name or 'unknown'}' (PID {pid}) command line ('{cmd_str[:120]}') "
                            f"references temporary path '{path}'. Why suspicious: Invoking commands that read or execute scripts "
                            f"from /tmp or /var/tmp often indicates dropper execution."
                        ),
                        evidence={
                            "command_line": command_line
                        },
                    )
                )

                break

        return findings

    # ========================================================
    # Collection metadata notes
    # ========================================================

    def _collect_metadata_notes(
        self,
        process: dict[str, Any],
        notes: list[dict[str, Any]],
    ):

        pid = process.get("pid")

        if process.get("executable") is None:

            notes.append(
                {
                    "type": "metadata_unavailable",
                    "pid": pid,
                    "field": "executable",
                    "reason": (
                        "The executable could not be "
                        "resolved from /proc."
                    ),
                }
            )

    # ========================================================
    # Finding creation
    # ========================================================

    def _finding(
        self,
        pid: int | None,
        name: str | None,
        severity: str,
        category: str,
        rule: str,
        description: str,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:

        return {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "source": self.name,

            "pid": pid,

            "process_name": name,

            "severity": severity,

            "category": category,

            "rule": rule,

            "description": description,

            "evidence": evidence or {},
        }

