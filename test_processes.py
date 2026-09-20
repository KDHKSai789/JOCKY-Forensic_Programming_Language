from forensics.processes import ProcessCollector


if __name__ == "__main__":
    collector = ProcessCollector()

    result = collector.collect("LOCAL")

    print("=== PROCESS COLLECTION ===")

    print("Platform:", result["platform"])
    print("Process count:", result["process_count"])

    print("\nFirst 10 processes:\n")

    for process in result["processes"][:10]:

        print(
            f"PID: {process['pid']}"
        )

        print(
            f"Name: {process['name']}"
        )

        print(
            f"User: {process['user']}"
        )

        print(
            f"Parent PID: {process['parent_pid']}"
        )

        print(
            f"Executable: {process['executable']}"
        )

        print(
            f"Threads: {process['thread_count']}"
        )

        print("-" * 50)
