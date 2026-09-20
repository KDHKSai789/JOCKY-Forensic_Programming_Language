import sys

from compiler.compiler import Compiler, CompilationError
from runtime.executor import JockyRuntime, JockyRuntimeError


def print_header():
    print("=" * 60)
    print("                 JOCKY FORENSIC FRAMEWORK")
    print("=" * 60)


def print_collection_summary(context):
    print("\n=== COLLECTION SUMMARY ===")

    collections = context.collected_data

    if not collections:
        print("No collection data.")
        return

    for source, item in collections.items():

        print(f"Source: {source}")

        status = item.get(
            "status",
            "complete",
        )

        print(f"Status: {status}")

        if "process_count" in item:
            print(
                f"Processes: "
                f"{item['process_count']}"
            )

        if "connection_count" in item:
            print(
                f"Connections: "
                f"{item['connection_count']}"
            )

        if "file_count" in item:
            print(
                f"Files: "
                f"{item['file_count']}"
            )

        if "total_mappings" in item:
            print(
                f"Mappings: "
                f"{item['total_mappings']}"
            )

        if source == "memory.indicators":

            print(
                "Writable+Executable: "
                f"{item.get('writable_executable_count', 0)}"
            )

            print(
                "Deleted Executables: "
                f"{item.get('deleted_executable_count', 0)}"
            )

            print(
                "Writable Anonymous: "
                f"{item.get('writable_anonymous_count', 0)}"
            )

        print()


def print_analysis_summary(context):
    print("=== ANALYSIS SUMMARY ===")

    analyses = context.analysis_results

    if not analyses:
        print("No analysis results.")
        return

    for source, item in analyses.items():

        print(f"Source: {source}")

        status = item.get(
            "status",
            "complete",
        )

        print(f"Status: {status}")

        print(
            f"Findings: "
            f"{item.get('finding_count', 0)}"
        )

        print(
            f"Severity: "
            f"{item.get('severity_counts', {})}"
        )

        print()


def print_correlation_summary(context):
    print("=== CORRELATION SUMMARY ===")

    correlations = context.correlations

    print(
        f"Correlations: "
        f"{len(correlations)}"
    )

    for item in correlations:

        print(
            f"Type: "
            f"{item.get('type', 'unknown')}"
        )

        print(
            f"Status: "
            f"{item.get('status', 'unknown')}"
        )

        correlated_count = (
            item.get("correlated_connection_count")
            or item.get("match_count")
            or item.get("overlap_count")
            or item.get("matched_count")
        )

        if correlated_count is not None:
            print(
                f"Correlated matches: "
                f"{correlated_count}"
            )

        print()

def print_risk_summary(context):
    print("=== RISK SUMMARY ===")

    risk = context.risk

    print(
        f"Risk Score: "
        f"{risk.get('risk_score', 0)}"
    )

    print(
        f"Risk Level: "
        f"{risk.get('risk_level', 'NONE')}"
    )

    print(
        f"Total Findings: "
        f"{risk.get('finding_count', 0)}"
    )

    print(
        f"Severity Counts: "
        f"{risk.get('severity_counts', {})}"
    )

    print(
        f"Correlation Bonus: "
        f"{risk.get('correlation_bonus', 0)}"
    )


def print_timeline_summary(context):
    print("=== TIMELINE SUMMARY ===")

    timeline = context.timeline

    print(
        f"Timeline Events: "
        f"{len(timeline)}"
    )

    if timeline:

        first_events = timeline[:5]

        for event in first_events:

            print(
                f"- {event}"
            )


def print_evidence_summary(context):
    print("=== EVIDENCE SUMMARY ===")

    evidence = context.evidence

    if not evidence:

        print("No evidence records.")
        return

    print(
        f"Evidence Records: "
        f"{len(evidence)}"
    )

    verification = evidence.get(
        "_verification"
    )

    if verification:

        print(
            f"Integrity Verification: "
            f"{verification}"
        )


def print_report_summary(context):
    print("=== REPORT ===")

    report = context.report

    if not report:
        print("No report generated.")
        return

    if isinstance(report, dict):

        output_file = (
            report.get("output_file")
            or report.get("file")
            or report.get("path")
        )

        if output_file:
            print(
                f"Report: {output_file}"
            )
        else:
            print("Report generated successfully.")

    else:
        print("Report generated successfully.")


VERSION = "1.3.0"

HELP_TEXT = """
╔══════════════════════════════════════════════════════════╗
║          JOCKY FORENSIC FRAMEWORK  v{version}              ║
╚══════════════════════════════════════════════════════════╝

USAGE:
  jocky <script.jocky>        Run a JOCKY forensic script
  jocky gui                   Launch the local web GUI dashboard
  jocky --version             Print version info
  jocky --help                Show this help message

EXAMPLES:
  jocky investigation.jocky
  jocky examples/full_investigation.jocky
  jocky gui

LANGUAGE KEYWORDS:
  CASE "<name>"               Define a forensic case
  TARGET "LOCAL"              Set analysis target
  COLLECT <source>            Collect forensic data
  ANALYZE <source>            Analyze collected data
  LET <var> = ANALYZE <src> WHERE <conditions>
  SEARCH IOC FROM <file>      Search for indicators of compromise
  CORRELATE <a> WITH <b>      Correlate two data sources
  TIMELINE                    Build forensic event timeline
  VERIFY evidence             Verify evidence integrity
  REPORT "<filename.json>"    Generate forensic report

CONDITION OPERATORS:
  >  <  >=  <=  ==  !=  MATCHES  IN
  Supports parentheses: WHERE ((pid > 100 OR threads > 10) AND pid != 1)

COLLECT SOURCES:
  processes, network.connections, filesystem.recent,
  memory.indicators, drivers, events, binaries

For full documentation: see LANGUAGE.md and ARCHITECTURE.md
""".format(version=VERSION)


def run_script(filename: str) -> None:
    """Run a .jocky script file."""

    print_header()
    print(f"\nCompiling: {filename}")

    try:
        compiler = Compiler()
        ir = compiler.compile_file(filename)

    except CompilationError as error:
        print("\nCOMPILATION ERROR:")
        print(error)
        sys.exit(1)

    except Exception as error:
        print("\nUNEXPECTED COMPILER ERROR:")
        print(error)
        sys.exit(1)

    print("Compilation: SUCCESS")
    print(f"Case: {ir.case_name}")
    print(f"Target: {ir.target}")
    print(f"IR instructions: {len(ir.instructions)}")
    print("\nExecuting JOCKY IR...")

    try:
        runtime = JockyRuntime()
        context = runtime.execute(ir)

    except JockyRuntimeError as error:
        print("\nRUNTIME ERROR:")
        print(error)
        sys.exit(1)

    except Exception as error:
        print("\nUNEXPECTED RUNTIME ERROR:")
        print(error)
        sys.exit(1)

    print("\nExecution: SUCCESS")
    print(f"Case: {context.case_name}")
    print(f"Target: {context.target}")
    print()

    print_collection_summary(context)
    print_analysis_summary(context)
    print_correlation_summary(context)
    print_risk_summary(context)
    print_timeline_summary(context)
    print_evidence_summary(context)
    print_report_summary(context)

    print("\n" + "=" * 60)
    print("           JOCKY EXECUTION COMPLETE")
    print("=" * 60)


def main():
    """Legacy entry point for python3 main.py <file>."""
    if len(sys.argv) < 2:
        print_header()
        print("\nUsage:  python3 main.py <script.jocky>")
        sys.exit(1)
    run_script(sys.argv[1])


def cli():
    """
    Entry point installed by pip install -e .
    Provides the `jocky` command.
    """
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h"):
        print(HELP_TEXT)
        return

    if args[0] in ("--version", "-v"):
        print(f"jocky {VERSION}")
        return

    if args[0] in ("gui", "--gui"):
        try:
            from gui import start_gui
            start_gui()
        except ImportError as err:
            print(f"GUI module not available: {err}")
            sys.exit(1)
        return

    if args[0].startswith("-"):
        print(f"Unknown option: {args[0]}")
        print("Run `jocky --help` for usage.")
        sys.exit(1)

    run_script(args[0])


if __name__ == "__main__":
    cli()
