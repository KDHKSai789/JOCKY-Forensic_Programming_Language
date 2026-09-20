from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
import hashlib
import json


@dataclass
class ChainEvent:
    """
    Represents one event in the evidence chain of custody.
    """

    event: str
    timestamp: str
    actor: str
    details: dict[str, Any]


class ChainOfCustody:
    """
    Maintains a tamper-evident chain of evidence events.

    Every event contains the hash of the previous event.
    This allows later verification of the chain.
    """

    def __init__(self, evidence_id: str):

        if not evidence_id:
            raise ValueError(
                "Evidence ID cannot be empty."
            )

        self.evidence_id = evidence_id
        self.events: list[dict[str, Any]] = []

    def _timestamp(self) -> str:

        return datetime.now(
            timezone.utc
        ).isoformat()

    def _calculate_hash(
        self,
        event: dict[str, Any],
    ) -> str:

        serialized = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

    def add_event(
        self,
        event: str,
        actor: str = "JOCKY",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:

        if not event:
            raise ValueError(
                "Chain event cannot be empty."
            )

        if details is None:
            details = {}

        previous_hash = "GENESIS"

        if self.events:
            previous_hash = self.events[-1]["event_hash"]

        chain_event = ChainEvent(
            event=event,
            timestamp=self._timestamp(),
            actor=actor,
            details=details,
        )

        record = asdict(chain_event)

        record["evidence_id"] = self.evidence_id
        record["previous_hash"] = previous_hash

        record["event_hash"] = self._calculate_hash(
            record
        )

        self.events.append(record)

        return record

    def verify(self) -> dict[str, Any]:
        """
        Verify the complete chain.

        Checks:
        1. Every event hash is correct.
        2. Every event points to the previous event.
        """

        previous_hash = "GENESIS"

        for index, event in enumerate(self.events):

            stored_hash = event.get(
                "event_hash"
            )

            if not stored_hash:
                return {
                    "verified": False,
                    "event_index": index,
                    "reason": "Missing event hash.",
                }

            if event.get("previous_hash") != previous_hash:
                return {
                    "verified": False,
                    "event_index": index,
                    "reason": "Previous hash mismatch.",
                }

            event_copy = dict(event)

            del event_copy["event_hash"]

            calculated_hash = self._calculate_hash(
                event_copy
            )

            if calculated_hash != stored_hash:
                return {
                    "verified": False,
                    "event_index": index,
                    "reason": "Event hash mismatch.",
                }

            previous_hash = stored_hash

        return {
            "verified": True,
            "evidence_id": self.evidence_id,
            "events": len(self.events),
        }

    def to_dict(self) -> dict[str, Any]:

        return {
            "evidence_id": self.evidence_id,
            "events": self.events,
            "verification": self.verify(),
        }
