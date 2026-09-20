from evidence.hasher import EvidenceHasher


def main():

    hasher = EvidenceHasher()

    print("=== EVIDENCE HASH TEST ===")

    data = b"JOCKY forensic evidence"

    hash_value = hasher.hash_bytes(data)

    print("\nData:")
    print(data.decode())

    print("\nSHA-256:")
    print(hash_value)

    text_hash = hasher.hash_text(
        "JOCKY forensic evidence"
    )

    print("\nText SHA-256:")
    print(text_hash)

    if hash_value == text_hash:
        print("\nPASS: Byte and text hashes match.")

    else:
        print("\nFAIL: Hashes do not match.")
        return

    record = hasher.create_record(
        evidence_id="EV-0001",
        evidence_type="test",
        sha256=hash_value,
        collected_at="2026-09-09T00:00:00+00:00",
        metadata={
            "source": "test_hasher.py"
        },
    )

    print("\n=== EVIDENCE RECORD ===")

    for key, value in record.items():
        print(f"{key}: {value}")

    print("\n=== HASHER SUCCESS ===")


if __name__ == "__main__":
    main()
