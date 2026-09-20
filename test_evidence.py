from evidence.chain import ChainOfCustody


print("=== EVIDENCE INTEGRITY TEST ===")

chain = ChainOfCustody("EV-TEST")

chain.add_event(
    "COLLECTED",
    details={
        "source": "test",
        "records": 10,
    },
)

chain.add_event(
    "HASHED",
    details={
        "algorithm": "SHA-256",
    },
)

print("\nOriginal verification:")
print(chain.verify())


print("\nTampering with evidence...")

chain.events[0]["details"]["records"] = 9999


print("\nVerification after tampering:")
print(chain.verify())
