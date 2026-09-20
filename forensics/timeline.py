from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class TimelineEvent:
    timestamp: str
    source: str
    event_type: str
    description: str
    data: dict[str, Any]


class TimelineEngine:

    def __init__(self):
        self.events: list[TimelineEvent] = []

    def add_event(
        self,
        timestamp: str,
        source: str,
        event_type: str,
        description: str,
        data: dict[str, Any] | None = None,
    ) -> None:

        if data is None:
            data = {}

        event = TimelineEvent(
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            description=description,
            data=data,
        )

        self.events.append(event)

    def add_process_events(
        self,
        processes: list[dict[str, Any]],
    ) -> None:

        for process in processes:

            timestamp = process.get("start_time")

            if not timestamp:
                timestamp = datetime.now(
                    timezone.utc
                ).isoformat()

            pid = process.get("pid", "unknown")
            name = process.get("name", "unknown")

            self.add_event(
                timestamp=timestamp,
                source="processes",
                event_type="PROCESS",
                description=f"Process {name} started",
                data={
                    "pid": pid,
                    "name": name,
                    "executable": process.get(
                        "executable"
                    ),
                    "command_line": process.get(
                        "command_line"
                    ),
                },
            )

    def add_network_events(
        self,
        connections: list[dict[str, Any]],
    ) -> None:

        for connection in connections:

            timestamp = connection.get("timestamp")

            if not timestamp:
                timestamp = datetime.now(
                    timezone.utc
                ).isoformat()

            self.add_event(
                timestamp=timestamp,
                source="network",
                event_type="NETWORK_CONNECTION",
                description="Network connection observed",
                data={
                    "pid": connection.get("pid"),
                    "protocol": connection.get(
                        "protocol"
                    ),
                    "local_address": connection.get(
                        "local_address"
                    ),
                    "remote_address": connection.get(
                        "remote_address"
                    ),
                    "state": connection.get("state"),
                },
            )

    def sort_events(self) -> None:

        def parse_timestamp(event: TimelineEvent):

            try:
                return datetime.fromisoformat(
                    event.timestamp.replace(
                        "Z",
                        "+00:00"
                    )
                )
            except ValueError:
                return datetime.min.replace(
                    tzinfo=timezone.utc
                )

        self.events.sort(
            key=parse_timestamp
        )

    def build(self) -> list[dict[str, Any]]:

        self.sort_events()

        return [
            asdict(event)
            for event in self.events
        ]

    def summary(self) -> dict[str, Any]:

        self.sort_events()

        sources = {}

        for event in self.events:

            sources[event.source] = (
                sources.get(event.source, 0) + 1
            )

        return {
            "event_count": len(self.events),
            "sources": sources,
            "first_event": (
                self.events[0].timestamp
                if self.events
                else None
            ),
            "last_event": (
                self.events[-1].timestamp
                if self.events
                else None
            ),
        }
