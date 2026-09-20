from compiler.compiler import Compiler
from runtime.executor import JockyRuntime


# ------------------------------------------------------------
# Compile JOCKY program
# ------------------------------------------------------------

compiler = Compiler()

ir = compiler.compile_file(
    "test.jocky"
)


# ------------------------------------------------------------
# Create runtime
# ------------------------------------------------------------

runtime = JockyRuntime()


# ------------------------------------------------------------
# Execute
# ------------------------------------------------------------

context = runtime.execute(ir)


# ------------------------------------------------------------
# Display result
# ------------------------------------------------------------

print("\n=== RUNTIME SUCCESS ===")

print("\nCase:")
print(context.case_name)

print("\nTarget:")
print(context.target)


# ------------------------------------------------------------
# Collection summary
# ------------------------------------------------------------

print("\n=== COLLECTION SUMMARY ===")

for source, data in context.collected_data.items():

    print(f"\nSource: {source}")

    if isinstance(data, dict):

        print(
            "Status:",
            data.get("status", "complete")
        )

        if "process_count" in data:
            print(
                "Processes:",
                data.get("process_count")
            )

        if "connection_count" in data:
            print(
                "Connections:",
                data.get("connection_count")
            )


# ------------------------------------------------------------
# Analysis summary
# ------------------------------------------------------------

print("\n=== ANALYSIS SUMMARY ===")

for source, result in context.analysis_results.items():

    print(f"\nSource: {source}")

    if isinstance(result, dict):

        print(
            "Status:",
            result.get("status")
        )

        print(
            "Findings:",
            result.get("finding_count", 0)
        )

        print(
            "Severity:",
            result.get(
                "severity_counts",
                {}
            )
        )


# ------------------------------------------------------------
# Correlation summary
# ------------------------------------------------------------

print("\n=== CORRELATION SUMMARY ===")

print(
    "Correlations:",
    len(context.correlations)
)

for correlation in context.correlations:

    if isinstance(correlation, dict):

        print(
            "Type:",
            correlation.get("type")
        )

        print(
            "Status:",
            correlation.get("status")
        )

        if "correlated_connection_count" in correlation:

            print(
                "Correlated connections:",
                correlation.get(
                    "correlated_connection_count"
                )
            )


# ------------------------------------------------------------
# Risk summary
# ------------------------------------------------------------

print("\n=== RISK SUMMARY ===")

if isinstance(context.risk, dict):

    print(
        "Risk Score:",
        context.risk.get(
            "risk_score",
            0
        )
    )

    print(
        "Risk Level:",
        context.risk.get(
            "risk_level",
            "UNKNOWN"
        )
    )

    print(
        "Total Findings:",
        context.risk.get(
            "finding_count",
            0
        )
    )

    print(
        "Severity Counts:",
        context.risk.get(
            "severity_counts",
            {}
        )
    )

    print(
        "Correlation Bonus:",
        context.risk.get(
            "correlation_bonus",
            0
        )
    )

else:

    print(
        "Risk data unavailable."
    )


# ------------------------------------------------------------
# Report
# ------------------------------------------------------------

print("\n=== REPORT ===")

print(context.report)
