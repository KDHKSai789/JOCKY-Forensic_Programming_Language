from security_provider import (
    ExecutionJob,
    get_provider,
)


provider = get_provider()

print("=== SECURITY PROVIDER TEST ===")

print("Provider:", provider.name)
print("Available:", provider.is_available())


case = {
    "case_id": "TEST-001",
    "target": "LOCAL",
    "authorized": True,
}


authorized = provider.authorize(case)

print("Authorized:", authorized)


job = ExecutionJob(
    case_id="TEST-001",
    target="LOCAL",
    operation="COLLECT",
    arguments={
        "source": "processes"
    },
)


result = provider.execute(job)

output = provider.collect_result(result)


print("\n=== PROVIDER RESULT ===")

print(output)
