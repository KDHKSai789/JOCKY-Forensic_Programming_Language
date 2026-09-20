from typing import Any


class MemoryAnalyzer:
    """
    Defensive analyzer for memory indicators collected from
    /proc/<pid>/maps.

    This analyzer does not read or modify process memory.
    It only evaluates metadata already collected by the
    memory indicator collector.
    """

    def __init__(
        self,
        writable_executable_threshold: int = 5,
        suspicious_anonymous_threshold: int = 500,
    ):
        self.writable_executable_threshold = (
            writable_executable_threshold
        )

        self.suspicious_anonymous_threshold = (
            suspicious_anonymous_threshold
        )

    def analyze(
        self,
        data: dict[str, Any],
    ) -> dict[str, Any]:

        processes = data.get(
            "processes",
            [],
        )

        findings = []
        collection_notes = data.get(
            "collection_notes",
            [],
        )

        for process in processes:

            pid = process.get(
                "pid"
            )

            process_name = process.get(
                "process_name",
                process.get(
                    "name",
                    "unknown",
                ),
            )

            writable_executable_count = process.get(
                "writable_executable_count",
                0,
            )

            deleted_executable_count = process.get(
                "deleted_executable_count",
                0,
            )

            writable_anonymous_count = process.get(
                "writable_anonymous_count",
                0,
            )

            # ------------------------------------------------
            # Writable + executable memory
            # ------------------------------------------------

            if (
                writable_executable_count
                > self.writable_executable_threshold
            ):

                findings.append(
                    self._finding(
                        severity="medium",
                        rule="WRITABLE_EXECUTABLE_MEMORY",
                        description=(
                            f"[Source: memory.indicators] Process '{process_name}' (PID {pid}) has {writable_executable_count} "
                            f"memory mapping(s) marked Writable and Executable (W^X model violation). Why suspicious: Memory regions "
                            f"that are simultaneously writable and executable facilitate dynamic shellcode execution and code injection."
                        ),
                        pid=pid,
                        process_name=process_name,
                        evidence={
                            "count": (
                                writable_executable_count
                            ),
                        },
                    )
                )

            # ------------------------------------------------
            # Deleted executable mappings
            # ------------------------------------------------

            if deleted_executable_count > 0:

                findings.append(
                    self._finding(
                        severity="high",
                        rule="DELETED_EXECUTABLE_MAPPING",
                        description=(
                            f"[Source: memory.indicators] Process '{process_name}' (PID {pid}) has {deleted_executable_count} "
                            f"executable memory mapping(s) tied to deleted files on disk. Why suspicious: Executing memory pages "
                            f"backed by unlinked files indicates payloads executed and erased from disk to hide evidence."
                        ),
                        pid=pid,
                        process_name=process_name,
                        evidence={
                            "count": (
                                deleted_executable_count
                            ),
                        },
                    )
                )

            # ------------------------------------------------
            # Large number of writable anonymous mappings
            # ------------------------------------------------

            if (
                writable_anonymous_count
                >= self.suspicious_anonymous_threshold
            ):

                findings.append(
                    self._finding(
                        severity="low",
                        rule="HIGH_ANONYMOUS_MEMORY",
                        description=(
                            f"[Source: memory.indicators] Process '{process_name}' (PID {pid}) contains {writable_anonymous_count} "
                            f"writable anonymous memory mappings (threshold: {self.suspicious_anonymous_threshold}). Why suspicious: A high volume "
                            f"of anonymous memory regions can indicate unpacked memory buffers or heap-staged code execution."
                        ),
                        pid=pid,
                        process_name=process_name,
                        evidence={
                            "count": (
                                writable_anonymous_count
                            ),
                            "threshold": (
                                self.suspicious_anonymous_threshold
                            ),
                        },
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

        return {
            "analyzer": "memory.indicators",
            "status": "complete",
            "process_count": len(processes),
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "collection_notes": collection_notes,
            "findings": findings,
        }

    def _finding(
        self,
        severity: str,
        rule: str,
        description: str,
        pid: Any,
        process_name: str,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return {
            "severity": severity,
            "rule": rule,
            "description": description,
            "source": "memory.indicators",
            "evidence": {
                "pid": pid,
                "process_name": process_name,
                **evidence,
            },
        }
