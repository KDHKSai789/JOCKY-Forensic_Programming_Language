import hashlib
from pathlib import Path
from typing import Any


class EvidenceHasher:
    """
    Provides SHA-256 hashing for forensic evidence.

    The original evidence is never modified.
    """

    algorithm = "sha256"

    def hash_bytes(self, data: bytes) -> str:
        """
        Calculate SHA-256 hash of raw bytes.
        """

        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")

        return hashlib.sha256(data).hexdigest()

    def hash_text(self, text: str) -> str:
        """
        Calculate SHA-256 hash of text using UTF-8 encoding.
        """

        if not isinstance(text, str):
            raise TypeError("Text must be a string.")

        return self.hash_bytes(
            text.encode("utf-8")
        )

    def hash_file(
        self,
        file_path: str,
    ) -> str:
        """
        Calculate SHA-256 hash of a file.

        The file is read in chunks so large forensic
        evidence files do not need to be loaded
        completely into memory.
        """

        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Evidence file not found: {file_path}"
            )

        if not path.is_file():
            raise ValueError(
                f"Evidence path is not a file: {file_path}"
            )

        digest = hashlib.sha256()

        with path.open("rb") as file:

            while True:

                chunk = file.read(1024 * 1024)

                if not chunk:
                    break

                digest.update(chunk)

        return digest.hexdigest()

    def create_record(
        self,
        evidence_id: str,
        evidence_type: str,
        sha256: str,
        collected_at: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Create a standard forensic evidence record.
        """

        if not evidence_id:
            raise ValueError(
                "Evidence ID cannot be empty."
            )

        if not evidence_type:
            raise ValueError(
                "Evidence type cannot be empty."
            )

        if not sha256:
            raise ValueError(
                "SHA-256 hash cannot be empty."
            )

        record = {
            "evidence_id": evidence_id,
            "type": evidence_type,
            "sha256": sha256,
            "algorithm": self.algorithm,
            "collected_at": collected_at,
            "integrity": "verified",
        }

        if metadata:
            record["metadata"] = metadata

        return record
