# JOCKY Forensic Framework

JOCKY is a cross-platform (Linux & Windows) forensic programming language and framework for SIH 2026 problem statement SIH26148. Its auditable DSL turns a forensic case definition into live evidence collection, analysis, correlation, risk scoring, a timeline, integrity verification, and a JSON report.

JOCKY does not bypass, disable, or tamper with antivirus or EDR products. `security_provider.py` is the sole, safe integration boundary for future authorized security-control research or integrations.

## Pipeline

`JOCKY DSL → lexer → parser → AST → semantic analysis → JOCKY IR → execution engine → cross-platform collection → analysis → correlation → risk → timeline → evidence verification → JSON report`

Supported forensic sources include processes, network sockets, recent filesystem records, memory indicators, drivers, events, and binaries across Linux and Windows. Collectors report available data without fabricating results and tolerate inaccessible optional sources.

## Install and run

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
python -m pip install -e .
jocky --version
jocky examples/full_investigation.jocky
jocky gui
```

On Debian/Ubuntu or Windows systems, use the virtual environment above rather than installing into the system Python. The repository can also be run directly with `python main.py examples/full_investigation.jocky`.

The GUI is a local dashboard using the same compiler and runtime as the CLI. It includes the valid default script template, results, timeline, evidence, correlation, and report views.

## Language example

```jocky
CASE "SIH_Demo"
TARGET "LOCAL"
COLLECT processes
COLLECT network.connections
ANALYZE processes
LET process_review_candidates = ANALYZE processes WHERE threads > 20 AND pid > 100
CORRELATE processes WITH network.connections
TIMELINE
VERIFY evidence
REPORT "demo_report.json"
```

Strings for `CASE`, `TARGET`, search files, and report paths are quoted. Conditions support comparisons, parentheses, `AND`, and `OR`, with precedence of parentheses, comparisons, `AND`, then `OR`.

`LET` results are triage candidates for analyst review, not authenticated malicious findings. They are intentionally excluded from the risk calculation to avoid double-counting evidence already covered by the source analysis.

## Reports and evidence

Reports are valid JSON with case, target, collection, analysis, IOC, correlation, risk, timeline, evidence, and execution metadata. Evidence records include SHA-256 hashes and chain-of-custody verification.

## Testing and limitations

Run `python3 -m pytest -q` when pytest is installed, or `python -m unittest discover -v` with the standard library. Collection supports both Linux and Windows operating systems using platform-native APIs and cross-platform abstractions (`psutil`). Permission restrictions on system files or security log event views may yield partial data if not run with sufficient administrator/root privileges.
