# JOCKY Forensic Framework

> **Cross-platform forensic programming language and evidence pipeline for SIH 2026 (SIH26148)**

JOCKY is a domain-specific language (DSL) and execution framework for live forensic investigations. Write a human-readable case script; JOCKY compiles it, collects evidence from the live system, analyses it with rule-based detectors, correlates sources, builds a timeline, verifies chain-of-custody, and produces a tamper-evident JSON report — all without touching any security or antivirus controls.

JOCKY does **not** bypass, disable, or tamper with antivirus or EDR products. `security_provider.py` is the sole, safe integration boundary for future authorised security-control research.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Install and Run](#install-and-run)
3. [Language Syntax Reference](#language-syntax-reference)
   - [CASE](#case)
   - [TARGET](#target)
   - [COLLECT](#collect)
   - [ANALYZE](#analyze)
   - [LET](#let)
   - [SEARCH](#search)
   - [CORRELATE](#correlate)
   - [TIMELINE](#timeline)
   - [VERIFY](#verify)
   - [REPORT](#report)
4. [Forensic Sources](#forensic-sources)
5. [Condition Fields Reference](#condition-fields-reference)
6. [Operators](#operators)
7. [Analysis Detection Rules](#analysis-detection-rules)
8. [Report Output Format](#report-output-format)
9. [GUI Dashboard](#gui-dashboard)
10. [Testing](#testing)
11. [Platform Notes and Limitations](#platform-notes-and-limitations)

---

## Architecture

```
JOCKY script (.jocky)
      │
      ▼
  [ Lexer ]  →  Token stream
      │
      ▼
  [ Parser ]  →  Abstract Syntax Tree (AST)
      │
      ▼
  [ Semantic Analyser ]  →  Validated JOCKY IR
      │
      ▼
  [ Execution Engine / JockyRuntime ]
      │
      ├── Forensic Collectors  (processes, network, filesystem, memory,
      │                         drivers, events, binaries)
      │
      ├── Analysis Engines     (rule-based findings per source)
      │
      ├── Correlation Engine   (cross-source relationship detection)
      │
      ├── Risk Engine          (weighted severity scoring)
      │
      ├── Timeline Builder     (chronological event reconstruction)
      │
      ├── Evidence Verifier    (SHA-256 + chain-of-custody records)
      │
      └── Report Writer        (structured JSON output)
```

---

## Install and Run

### Requirements

- Python **3.10+**
- `psutil >= 5.9.0` (cross-platform OS abstraction)

### Setup

```bash
# 1. Clone the repository
git clone <repo-url>
cd jocky

# 2. Create a virtual environment
python3 -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate

# 3. Install (editable mode includes CLI entry point)
pip install -e .
```

### Running a script

```bash
# Via installed CLI entry point
jocky my_investigation.jocky

# Via python directly
python main.py my_investigation.jocky

# Check version
jocky --version

# Launch GUI dashboard
jocky gui
```

---

## Language Syntax Reference

A JOCKY script is a plain-text file with the `.jocky` extension. Statements are written one per line. Order matters — `COLLECT` must precede `ANALYZE` or `CORRELATE` for the same source.

### Required Statements

Every valid script **must** contain exactly one `CASE` and one `TARGET`.

---

### CASE

Declares the forensic case name. Must be a quoted string. Only one `CASE` statement is allowed per script.

```jocky
CASE "<case_name>"
```

**Example:**
```jocky
CASE "Ransomware_Investigation_2026"
```

---

### TARGET

Declares the investigation target. Currently `"LOCAL"` is supported for live local host collection. Must be a quoted string. Only one `TARGET` statement is allowed per script.

```jocky
TARGET "<target>"
```

**Example:**
```jocky
TARGET "LOCAL"
```

---

### COLLECT

Instructs the runtime to collect evidence from a forensic source identifier. Multiple `COLLECT` statements are allowed. See [Forensic Sources](#forensic-sources) for all valid identifiers.

```jocky
COLLECT <source_identifier>
```

**Examples:**
```jocky
COLLECT processes
COLLECT network.connections
COLLECT filesystem.recent
COLLECT memory.indicators
COLLECT drivers
COLLECT events
COLLECT binaries
```

---

### ANALYZE

Runs the rule-based detection engine over a previously collected source. Produces `findings` with severity, rule name, and description. Optionally filtered with a `WHERE` clause.

```jocky
ANALYZE <source_identifier>
ANALYZE <source_identifier> WHERE <condition>
```

**Examples:**
```jocky
ANALYZE processes
ANALYZE filesystem.recent
ANALYZE processes WHERE pid > 100
ANALYZE network.connections WHERE remote_port == 4444
```

> A bare `ANALYZE` (without `WHERE`) runs all built-in detection rules against the full collected dataset.

---

### LET

Assigns the filtered result of an `ANALYZE` operation to a named variable identifier. Used for triage candidate sets — these results are **not** included in the risk score (to avoid double-counting).

```jocky
LET <variable_name> = ANALYZE <source_identifier> WHERE <condition>
```

**Condition syntax:**

```jocky
WHERE <field> <operator> <value>
WHERE <field> <operator> <value> AND <field> <operator> <value>
WHERE <field> <operator> <value> OR  <field> <operator> <value>
WHERE (<condition>) AND (<condition>)
```

Operator precedence (high → low): parentheses `()` → comparisons → `AND` → `OR`

**Examples:**
```jocky
LET high_pid_procs   = ANALYZE processes WHERE pid > 1000
LET suspicious_ports = ANALYZE network.connections WHERE remote_port > 1024 AND remote_port < 9999
LET temp_execs       = ANALYZE processes WHERE (executable MATCHES "/tmp/") OR (executable MATCHES "/var/tmp/")
LET large_files      = ANALYZE filesystem.recent WHERE size > 10485760
```

**LET result object** — accessible in the JSON report under `variables`:

| Field | Description |
|-------|-------------|
| `input_count` | Total records passed to the filter |
| `matched_count` | Records matching the condition |
| `items` | The matching records |

---

### SEARCH

Searches a specified source target for a pattern or IOC type.

```jocky
SEARCH <search_type_identifier> FROM "<source_string>"
```

**Example:**
```jocky
SEARCH ioc FROM "/var/log/syslog"
```

---

### CORRELATE

Cross-references two collected sources to find relationships (e.g. a process that owns a network connection, or a process that recently modified a file).

```jocky
CORRELATE <source_identifier_a> WITH <source_identifier_b>
```

**Examples:**
```jocky
CORRELATE processes WITH network.connections
CORRELATE processes WITH filesystem.recent
```

Correlation results appear in the report under `correlations`. Each entry includes:

| Field | Description |
|-------|-------------|
| `type` | Correlation type (e.g. `process_network`, `process_filesystem`) |
| `explanation` | Human-readable description of the relationship |
| `left` / `right` | The matched records from each source |

---

### TIMELINE

Reconstructs a chronological event timeline from collected sources. Can run across all collected sources or be restricted to specific sources using `FROM` syntax.

```jocky
TIMELINE
TIMELINE FROM <source_identifier_1> FROM <source_identifier_2>
```

**Examples:**
```jocky
TIMELINE
TIMELINE FROM processes FROM events
```

Timeline entries are sorted by timestamp and written to `timeline` in the report. Each entry includes `timestamp`, `source`, `event_type`, and `detail`.

---

### VERIFY

Computes SHA-256 hashes of all collected evidence records and creates a chain-of-custody log. Requires an identifier target (typically `evidence`).

```jocky
VERIFY <target_identifier>
```

**Example:**
```jocky
VERIFY evidence
```

Evidence records appear in the report under `evidence`. Each record includes:

| Field | Description |
|-------|-------------|
| `sha256` | Hash of the serialised evidence record |
| `collected_at` | UTC timestamp of collection |
| `record` | The original evidence object |

A `_verification` summary block is also written, covering total records, verified count, and any integrity failures.

---

### REPORT

Writes the full investigation output to a JSON file. Path must be a quoted string.

```jocky
REPORT "<output_path>"
```

**Examples:**
```jocky
REPORT "investigation_report.json"
REPORT "/home/analyst/cases/2026-09-20_report.json"
```

---

## Forensic Sources

These are the valid identifiers for `COLLECT` and `ANALYZE`:

| Source Identifier | Description | Linux | Windows |
|-------------------|-------------|-------|---------|
| `processes` | Running processes — PID, name, user, executable, threads, memory, command line | ✅ (`/proc`) | ✅ (`tasklist` / `psutil`) |
| `network.connections` | Active TCP/UDP sockets — local/remote address, port, state, owning PID | ✅ (`/proc/net`) | ✅ (`netstat` / `psutil`) |
| `filesystem.recent` | Files modified in the last 24 hours under forensic directories | ✅ | ✅ |
| `filesystem` | Alias for `filesystem.recent` | ✅ | ✅ |
| `memory.indicators` | Per-process memory maps — writable+executable, deleted, anonymous segments | ✅ (`/proc/<pid>/maps`) | ✅ (`psutil`) |
| `memory` | Alias for `memory.indicators` | ✅ | ✅ |
| `drivers` | Loaded kernel modules / drivers | ✅ (`/proc/modules`) | ✅ (`driverquery`) |
| `events` | System and application log events | ✅ (`/var/log`) | ✅ (`wevtutil`) |
| `windows.events` | Alias for `events` | — | ✅ |
| `binaries` | Executable binaries in staging directories (scans `/tmp`, `/var/tmp`, etc.) | ✅ | ✅ |
| `registry` | (Planned) Windows Registry keys | — | 🔜 |
| `services` | (Planned) Running services | — | 🔜 |
| `persistence` | (Planned) Autorun / startup entries | — | 🔜 |
| `threads` | (Planned) Per-process thread list | — | 🔜 |
| `hashes` | (Planned) File hash collection | — | 🔜 |

---

## Condition Fields Reference

Valid fields for `WHERE` clauses in `ANALYZE` and `LET` statements, by source:

### `processes`

| Field | Type | Description |
|-------|------|-------------|
| `pid` | number | Process ID |
| `ppid` | number | Parent Process ID |
| `uid` | number | User ID of the owning user |
| `user` | string | Username of the owning user |
| `name` | string | Process name |
| `executable` | string | Absolute path to the executable on disk |
| `command_line` | string | Full command line arguments |
| `threads` | number | Number of threads |
| `memory` | number | Resident memory usage (bytes) |
| `cpu` | number | CPU usage percentage |

### `network.connections`

| Field | Type | Description |
|-------|------|-------------|
| `pid` | number | Owning process ID |
| `uid` | number | Owning user ID |
| `local_port` | number | Local port number |
| `remote_port` | number | Remote port number |

### `filesystem` / `filesystem.recent`

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | Absolute file path |
| `size` | number | File size in bytes |
| `mtime` | string | Last-modified timestamp (ISO 8601) |

### `memory` / `memory.indicators`

| Field | Type | Description |
|-------|------|-------------|
| `pid` | number | Process ID |
| `writable_executable` | number | Count of W+X memory segments |
| `deleted_executable` | number | Count of deleted executable mappings |
| `writable_anonymous` | number | Count of anonymous writable pages |

### `events` / `windows.events`

| Field | Type | Description |
|-------|------|-------------|
| `pid` | number | Associated process ID |
| `timestamp` | string | Event timestamp (ISO 8601) |
| `event_type` | string | Event category / type label |

### `drivers`

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Driver or module name |
| `path` | string | Path to the driver file |
| `version` | string | Driver version string |

### `binaries`

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | Full path to the binary |
| `size` | number | File size in bytes |
| `sha256` | string | SHA-256 hash of the file |

### `registry`

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | Registry key path |
| `value` | string | Registry value name |

### `services`

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Service name |
| `pid` | number | Service process ID |
| `status` | string | Running / stopped / etc. |

### `persistence`

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | Path of the persistence entry |
| `name` | string | Name of the entry |
| `type` | string | Persistence mechanism type |

### `threads`

| Field | Type | Description |
|-------|------|-------------|
| `pid` | number | Owning process ID |
| `tid` | number | Thread ID |

---

## Operators

### Comparison Operators (used in `WHERE` conditions)

| Operator Token / Syntax | Meaning |
|-------------------------|---------|
| `>` | Greater than |
| `<` | Less than |
| `>=` | Greater than or equal |
| `<=` | Less than or equal |
| `==` | Equal |
| `!=` | Not equal |
| `MATCHES` | Substring match / string contains |
| `IN` | Value presence check |

### Logical Operators

| Operator | Precedence | Description |
|----------|------------|-------------|
| `AND` | Medium-High | Logical conjunction — evaluated before `OR` |
| `OR` | Medium-Low | Logical disjunction |
| `( )` | Highest | Parentheses override default expression precedence |

---

## Analysis Detection Rules

These rules are triggered automatically when `ANALYZE` is run on a source.

### `ANALYZE processes`

| Rule | Severity | Trigger |
|------|----------|---------|
| `DELETED_EXECUTABLE` | **high** | Process executable path ends with ` (deleted)` |
| `SUSPICIOUS_EXECUTION_PATH` | **medium** | Executable is in `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, `AppData\Local\Temp`, `Windows\Temp` |
| `SUSPICIOUS_COMMAND_PATH` | **medium** | Command-line arguments reference a temp/staging path |
| `HIGH_THREAD_COUNT` | **low** | Thread count ≥ 100 (possible miner, injector, or flooder) |

### `ANALYZE filesystem.recent`

| Rule | Severity | Trigger |
|------|----------|---------|
| `EXECUTABLE_TEMP_PATH` | **high** | Executable file found in a temporary directory |
| `HIDDEN_EXECUTABLE` | **high** | File is hidden (`.`-prefixed on Linux, hidden attribute on Windows) and executable |
| `EXECUTABLE_SCRIPT_TEMP` | **high** | Executable script (`.sh`, `.ps1`, `.bat`, `.py`, etc.) in a temp path |
| `RECENT_EXECUTABLE` | **medium** | Executable modified within the last 24 hours |
| `WORLD_WRITABLE_FILE` | **medium** | File has world-writable permissions (`chmod o+w`) |
| `LARGE_RECENT_FILE` | **low** | File ≥ 100 MB modified in the last 24 hours |

---

## Report Output Format

The JSON report (`REPORT`) contains the following top-level keys:

```json
{
  "format": "JOCKY-FORENSIC-REPORT",
  "version": "1.3.0",
  "case": "<case name>",
  "target": "<target>",
  "generated_at": "<ISO 8601 UTC timestamp>",
  "collected_data": { "<source>": { ... } },
  "analysis_results": { "<source>": { "findings": [ ... ] } },
  "variables": { "<let_name>": { "matched_count": N, "items": [ ... ] } },
  "correlations": [ { "type": "...", "explanation": "...", ... } ],
  "risk": { "score": 0-100, "level": "low|medium|high|critical", "breakdown": { ... } },
  "timeline": [ { "timestamp": "...", "source": "...", "event_type": "...", "detail": "..." } ],
  "evidence": { "<id>": { "sha256": "...", "collected_at": "...", "record": { ... } } },
  "execution": { "started_at": "...", "finished_at": "...", "warnings": [ ... ] }
}
```

---

## Complete Example Script

```jocky
CASE "Full_Investigation"
TARGET "LOCAL"

COLLECT processes
COLLECT network.connections
COLLECT filesystem.recent
COLLECT memory.indicators
COLLECT drivers
COLLECT events
COLLECT binaries

ANALYZE processes
ANALYZE filesystem.recent

LET suspicious_procs = ANALYZE processes WHERE (executable MATCHES "/tmp/") OR (executable MATCHES "/var/tmp/")
LET high_thread_procs = ANALYZE processes WHERE threads > 100
LET suspicious_ports = ANALYZE network.connections WHERE remote_port > 1024 AND remote_port != 443
LET large_files = ANALYZE filesystem.recent WHERE size > 104857600

CORRELATE processes WITH network.connections
CORRELATE processes WITH filesystem.recent

TIMELINE
VERIFY evidence
REPORT "full_investigation_report.json"
```

---

## GUI Dashboard

Launch the local web-based GUI with:

```bash
jocky gui
```

The GUI provides:
- **Script editor** — write and run JOCKY scripts with the built-in template
- **Results view** — analysis findings with severity indicators
- **Timeline** — chronological event view
- **Evidence** — hash-verified chain of custody records
- **Correlations** — cross-source relationship viewer
- **Report** — formatted JSON export viewer

---

## Testing

```bash
# Run the full test suite (40 tests)
python -m unittest tests.test_compiler tests.test_runtime -v

# Or with pytest if installed
pytest -q
```

All 40 tests cover the lexer, parser, IR serialization, all collectors, evidence hashing, timeline, correlations, LET filtering, and report creation. Tests are platform-agnostic and use `tempfile` for all paths.

---

## Platform Notes and Limitations

| Aspect | Linux | Windows |
|--------|-------|---------|
| Process collection | `/proc` (full detail) or `psutil` | `tasklist` or `psutil` |
| Network collection | `/proc/net/tcp`, `/proc/net/udp` | `netstat -ano` or `psutil` |
| Memory maps | `/proc/<pid>/maps` (full) | `psutil.memory_maps` (partial) |
| Kernel drivers | `/proc/modules` | `driverquery` (requires admin) |
| Event logs | `/var/log` files | `wevtutil` (may require admin) |
| Privileges | Root recommended for full `/proc` access | Administrator recommended for event logs and driver queries |
| Filesystem scan dirs | `/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/var/log` | `%TEMP%`, `%LOCALAPPDATA%`, `%USERPROFILE%` |

> Partial data is always reported with a note rather than an error — JOCKY never fabricates evidence.
