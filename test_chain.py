from evidence.chain import ChainOfCustody


def main():

    chain = ChainOfCustody(
        "EV-0001"
    )

    print("=== CHAIN OF CUSTODY TEST ===")

    chain.add_event(
        "COLLECTED",
        details={
            "source": "processes"
        },
    )

    chain.add_event(
        "HASHED",
        details={
            "algorithm": "SHA-256"
        },
    )

    chain.add_event(
        "ANALYZED",
        details={
            "analyzer": "process_analyzer"
        },
    )

    chain.add_event(
        "VERIFIED",
        details={
            "integrity": "verified"
        },
    )

    chain.add_event(
        "REPORTED",
        details={
            "report": "result.json"
        },
    )

    print("\n=== EVENTS ===")

    for event in chain.events:

        print(
            f"{event['event']} "
            f"| {event['timestamp']} "
            f"| hash={event['event_hash'][:16]}..."
        )

    print("\n=== VERIFICATION ===")

    result = chain.verify()

    print(result)

    if result["verified"]:
        print("\nPASS: Chain integrity verified.")

    else:
        print("\nFAIL: Chain integrity verification failed.")
        return

    print("\n=== CHAIN SUCCESS ===")


if __name__ == "__main__":
    main()
