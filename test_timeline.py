from forensics.timeline import TimelineEngine


print("=== TIMELINE ENGINE TEST ===")

timeline = TimelineEngine()


timeline.add_event(
    timestamp="2026-09-09T10:00:00+00:00",
    source="filesystem",
    event_type="FILE_CREATED",
    description="Suspicious file created",
    data={
        "path": "/tmp/sample.bin"
    },
)


timeline.add_event(
    timestamp="2026-09-09T10:05:00+00:00",
    source="processes",
    event_type="PROCESS",
    description="Suspicious process started",
    data={
        "pid": 1234,
        "name": "sample.bin"
    },
)


timeline.add_event(
    timestamp="2026-09-09T10:06:00+00:00",
    source="network",
    event_type="NETWORK_CONNECTION",
    description="External connection observed",
    data={
        "pid": 1234,
        "remote_address": "8.8.8.8:443"
    },
)


print("\nTimeline:")

for event in timeline.build():
    print(
        event["timestamp"],
        "|",
        event["source"],
        "|",
        event["event_type"],
        "|",
        event["description"],
    )


print("\nSummary:")
print(timeline.summary())
