from datetime import datetime, timezone
from typing import Any


class FilesystemAnalyzer:
    """
    Defensive filesystem forensic analyzer.

    Examines collected filesystem records and produces
    explainable forensic findings.
    """

    SUSPICIOUS_PATHS = (
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/run/user/",
        "/appdata/local/temp/",
        "/windows/temp/",
    )

    SCRIPT_EXTENSIONS = (
        ".sh",
        ".bash",
        ".py",
        ".pl",
        ".rb",
        ".php",
        ".js",
        ".ps1",
        ".vbs",
        ".bat",
        ".cmd",
    )

    def __init__(self):
        pass

    def _finding(
        self,
        severity: str,
        rule: str,
        description: str,
        file_record: dict[str, Any],
    ) -> dict[str, Any]:

        return {
            "source": "filesystem.recent",
            "severity": severity,
            "rule": rule,
            "description": description,
            "path": file_record.get(
                "path",
                "unknown",
            ),
            "sha256": file_record.get(
                "sha256"
            ),
            "size": file_record.get(
                "size"
            ),
            "modified_time": file_record.get(
                "modified_time"
            ),
        }

    def _is_recent(
        self,
        timestamp: str | None,
        hours: int = 24,
    ) -> bool:

        if not timestamp:
            return False

        try:
            value = datetime.fromisoformat(
                timestamp.replace(
                    "Z",
                    "+00:00",
                )
            )

            now = datetime.now(
                timezone.utc
            )

            age_seconds = (
                now - value
            ).total_seconds()

            return (
                0
                <= age_seconds
                <= hours * 3600
            )

        except (
            ValueError,
            TypeError,
        ):

            return False

    def analyze(
        self,
        collection: dict[str, Any],
    ) -> dict[str, Any]:

        files = collection.get(
            "files",
            [],
        )

        findings = []

        collection_notes = []

        for file_record in files:

            path = str(
                file_record.get(
                    "path",
                    "",
                )
            )

            name = str(
                file_record.get(
                    "name",
                    "",
                )
            )

            executable = bool(
                file_record.get(
                    "executable",
                    False,
                )
            )

            hidden = bool(
                file_record.get(
                    "hidden",
                    False,
                )
            )

            size = int(
                file_record.get(
                    "size",
                    0,
                )
                or 0
            )

            mode = str(
                file_record.get(
                    "mode",
                    "",
                )
            )

            modified_time = (
                file_record.get(
                    "modified_time"
                )
            )

            lower_path = path.lower().replace("\\", "/")

            lower_name = name.lower()

            # ------------------------------------------------
            # Rule 1: Executable in temporary directory
            # ------------------------------------------------

            if (
                executable
                and lower_path.startswith(
                    self.SUSPICIOUS_PATHS
                )
            ):

                findings.append(
                    self._finding(
                        "high",
                        "EXECUTABLE_TEMP_PATH",
                        (
                            f"[Source: filesystem.recent] Executable file '{path}' (size: {size} bytes) found in temporary "
                            f"location. Why suspicious: Droppers and untrusted scripts often stage binary payloads in /tmp or /var/tmp."
                        ),
                        file_record,
                    )
                )

            # ------------------------------------------------
            # Rule 2: Recently modified executable
            # ------------------------------------------------

            elif (
                executable
                and self._is_recent(
                    modified_time
                )
            ):

                findings.append(
                    self._finding(
                        "medium",
                        "RECENT_EXECUTABLE",
                        (
                            f"[Source: filesystem.recent] Executable file '{path}' was modified recently ({modified_time}). "
                            f"Why suspicious: Recently updated binary executables may indicate new payload drops or persistence updates."
                        ),
                        file_record,
                    )
                )

            # ------------------------------------------------
            # Rule 3: Hidden executable
            # ------------------------------------------------

            if (
                hidden
                and executable
            ):

                findings.append(
                    self._finding(
                        "high",
                        "HIDDEN_EXECUTABLE",
                        (
                            f"[Source: filesystem.recent] Hidden executable file '{path}' observed. Why suspicious: Prefixing filenames "
                            f"with dot (.) is a common stealth mechanism to hide binaries from standard directory listings."
                        ),
                        file_record,
                    )
                )

            # ------------------------------------------------
            # Rule 4: Suspicious script in temp location
            # ------------------------------------------------

            if (
                executable
                and lower_name.endswith(
                    self.SCRIPT_EXTENSIONS
                )
                and lower_path.startswith(
                    self.SUSPICIOUS_PATHS
                )
            ):

                findings.append(
                    self._finding(
                        "high",
                        "EXECUTABLE_SCRIPT_TEMP",
                        (
                            f"[Source: filesystem.recent] Executable script '{path}' found in temporary directory. Why suspicious: Executable scripts "
                            f"in temp paths frequently act as payload downloaders or initial execution vectors."
                        ),
                        file_record,
                    )
                )

            # ------------------------------------------------
            # Rule 5: World-writable file
            #
            # 0o002 means the file is writable by others.
            # ------------------------------------------------

            try:

                permission_value = int(
                    mode,
                    8,
                )

                if (
                    permission_value
                    & 0o002
                ):

                    findings.append(
                        self._finding(
                            "medium",
                            "WORLD_WRITABLE_FILE",
                            (
                                f"[Source: filesystem.recent] File '{path}' has world-writable permissions (mode {mode}). "
                                f"Why suspicious: World-writable permissions allow unprivileged local users to modify file contents."
                            ),
                            file_record,
                        )
                    )

            except (
                ValueError,
                TypeError,
            ):

                pass

            # ------------------------------------------------
            # Rule 6: Very large recently modified file
            # ------------------------------------------------

            if (
                size >= 100 * 1024 * 1024
                and self._is_recent(
                    modified_time
                )
            ):

                findings.append(
                    self._finding(
                        "low",
                        "LARGE_RECENT_FILE",
                        (
                            f"[Source: filesystem.recent] Large file '{path}' ({size} bytes) was modified recently ({modified_time}). "
                            f"Why suspicious: Unusually large recent files can indicate exfiltration staging or raw memory dumps."
                        ),
                        file_record,
                    )
                )

        # ----------------------------------------------------
        # Collection notes
        # ----------------------------------------------------

        if not files:

            collection_notes.append(
                "No filesystem records were collected."
            )

        # ----------------------------------------------------
        # Severity counts
        # ----------------------------------------------------

        severity_counts = {
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for finding in findings:

            severity = finding.get(
                "severity"
            )

            if severity in severity_counts:

                severity_counts[
                    severity
                ] += 1

        return {
            "analyzer": "filesystem",
            "status": "completed",
            "file_count": len(files),
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "collection_notes": collection_notes,
            "findings": findings,
        }
