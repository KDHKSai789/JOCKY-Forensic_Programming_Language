from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import json

from compiler.ir import JockyIR, IRInstruction

from security_provider import (
    SecurityProvider,
    ExecutionJob,
    get_provider,
)

from forensics.processes import ProcessCollector
from forensics.network import NetworkConnectionCollector
from forensics.filesystem import FilesystemCollector
from forensics.memory import MemoryIndicatorCollector
from forensics.drivers import DriverCollector
from forensics.events import EventCollector
from forensics.binaries import BinaryCollector
from forensics.timeline import TimelineEngine

from analysis.process_analyzer import ProcessAnalyzer
from analysis.network_analyzer import NetworkAnalyzer
from analysis.filesystem_analyzer import FilesystemAnalyzer
from analysis.memory_analyzer import MemoryAnalyzer
from analysis.correlation import CorrelationEngine
from analysis.risk_engine import RiskEngine
from analysis.ioc import IOCAnalyzer

from evidence.hasher import EvidenceHasher
from evidence.chain import ChainOfCustody


class JockyRuntimeError(Exception):
    pass


@dataclass
class RuntimeContext:

    case_name: str = ""
    target: str = ""

    collected_data: dict[str, Any] = field(
        default_factory=dict
    )

    analysis_results: dict[str, Any] = field(
        default_factory=dict
    )

    variables: dict[str, Any] = field(
        default_factory=dict
    )

    search_results: list[dict[str, Any]] = field(
        default_factory=list
    )

    correlations: list[dict[str, Any]] = field(
        default_factory=list
    )

    risk: dict[str, Any] = field(
        default_factory=dict
    )

    timeline: list[dict[str, Any]] = field(
        default_factory=list
    )

    evidence: dict[str, Any] = field(
        default_factory=dict
    )

    report: dict[str, Any] = field(
        default_factory=dict
    )


class JockyRuntime:

    def __init__(
        self,
        provider: SecurityProvider | None = None,
    ):

        self.provider = provider or get_provider()

        self.process_collector = ProcessCollector()

        self.network_collector = (
            NetworkConnectionCollector()
        )

        self.filesystem_collector = (
            FilesystemCollector()
        )
        self.memory_collector = (
            MemoryIndicatorCollector()
        )
        self.driver_collector = DriverCollector()
        self.event_collector = EventCollector()
        self.binary_collector = BinaryCollector()

        self.timeline_engine = TimelineEngine()

        self.process_analyzer = ProcessAnalyzer()

        self.network_analyzer = (
            NetworkAnalyzer()
        )
        self.filesystem_analyzer = FilesystemAnalyzer()
        self.correlation_engine = (
            CorrelationEngine()
        )
        self.memory_analyzer = (
            MemoryAnalyzer()
        )
        self.risk_engine = RiskEngine()
        self.ioc_analyzer = IOCAnalyzer()

        self.hasher = EvidenceHasher()

        self.context = RuntimeContext()

        self._evidence_counter = 0

        self._chains: dict[
            str,
            ChainOfCustody
        ] = {}

    # ========================================================
    # MAIN EXECUTION
    # ========================================================

    def execute(
        self,
        ir: JockyIR,
    ) -> RuntimeContext:

        self.context = RuntimeContext()

        self.context.case_name = (
            ir.case_name or ""
        )

        self.context.target = (
            ir.target or ""
        )

        self.timeline_engine = TimelineEngine()

        case = {
            "case": self.context.case_name,
            "target": self.context.target,
            "authorized": True,
        }

        if not self.provider.authorize(case):

            raise JockyRuntimeError(
                "Security provider did not authorize this case."
            )

        for instruction in ir.instructions:

            self._execute_provider(
                instruction
            )

            self._dispatch(
                instruction
            )

        self._calculate_risk()

        if self.context.report:

            output_file = (
                self.context.report.get(
                    "output_file"
                )
            )

            if output_file:

                self._build_report(
                    output_file
                )

        return self.context

    # ========================================================
    # SECURITY PROVIDER
    # ========================================================

    def _execute_provider(
        self,
        instruction: IRInstruction,
    ) -> None:

        job = ExecutionJob(
            case_id=self.context.case_name,
            target=self.context.target,
            operation=instruction.operation,
            arguments=instruction.arguments,
        )

        self.provider.execute(
            job
        )

    # ========================================================
    # DISPATCH
    # ========================================================

    def _dispatch(
        self,
        instruction: IRInstruction,
    ) -> None:

        operation = instruction.operation

        arguments = (
            instruction.arguments
        )

        if operation == "COLLECT":

            self._collect(
                arguments.get(
                    "source",
                    "",
                )
            )

        elif operation == "ANALYZE":

            self._analyze(
                arguments.get(
                    "source",
                    "",
                )
            )

        elif operation == "LET":

            self._let(
                arguments
            )

        elif operation == "SEARCH":

            self._search(
                arguments
            )

        elif operation == "CORRELATE":

            self._correlate(
                arguments
            )

        elif operation == "TIMELINE":

            self._timeline()

        elif operation == "VERIFY":

            self._verify()

        elif operation == "REPORT":

            self._report(
                arguments.get(
                    "output_file",
                    "",
                )
            )

        else:

            raise JockyRuntimeError(
                f"Unsupported IR operation: {operation}"
            )

    # ========================================================
    # COLLECTION
    # ========================================================

    def _collect(
        self,
        source: str,
    ) -> None:

        if source == "processes":

            result = (
                self.process_collector.collect()
            )

        elif source == "network.connections":

            result = (
                self.network_collector.collect(
                    self.context.target
                )
            )
        elif source == "filesystem.recent":

            result = (
                self.filesystem_collector.collect(
                    self.context.target
                )
            )
        elif source == "memory.indicators":

            result = (
                self.memory_collector.collect(
                    self.context.target
                )
            )

        elif source == "drivers":

            result = self.driver_collector.collect(
                self.context.target
            )

        elif source == "events":

            result = self.event_collector.collect(
                self.context.target
            )

        elif source == "binaries":

            result = self.binary_collector.collect(
                self.context.target
            )
        else:

            result = {
                "status": "unsupported",
                "source": source,
                "records": [],
                "count": 0,
                "message": (
                    "Collector not implemented yet."
                ),
            }

        self.context.collected_data[
            source
        ] = result

        # ----------------------------------------------------
        # Determine number of collected records.
        # ----------------------------------------------------

        if source == "processes":

            record_count = result.get(
                "process_count",
                len(
                    result.get(
                        "processes",
                        [],
                    )
                ),
            )

            collection_succeeded = (
                "processes" in result
            )

        elif source == "network.connections":

            record_count = result.get(
                "connection_count",
                len(
                    result.get(
                        "connections",
                        [],
                    )
                ),
            )

            collection_succeeded = (
                "connections" in result
            )

        elif source == "filesystem.recent":

            record_count = result.get(
                "file_count",
                len(
                    result.get(
                        "files",
                        [],
                    )
                ),
            )

            collection_succeeded = (
                "files" in result
            )
        elif source == "memory.indicators":

            record_count = result.get(
                "process_count",
                len(
                    result.get(
                        "processes",
                        [],
                    )
                ),
            )

            collection_succeeded = (
                "processes" in result
            )

        else:

            record_count = result.get(
                "count",
                len(
                    result.get(
                        "records",
                        [],
                    )
                ),
            )

            collection_succeeded = (
                result.get("status")
                in (
                    "complete",
                    "completed",
                    "success",
                )
            )

        # ----------------------------------------------------
        # Create evidence for successful collection.
        # ----------------------------------------------------

        if collection_succeeded:

            self._create_evidence(
                source,
                result,
                record_count,
            )

    # ========================================================
    # EVIDENCE
    # ========================================================

    def _next_evidence_id(self) -> str:

        self._evidence_counter += 1

        return (
            f"EV-{self._evidence_counter:04d}"
        )

    def _create_evidence(
        self,
        source: str,
        collection_result: dict[str, Any],
        record_count: int = 0,
    ) -> None:

        evidence_id = (
            self._next_evidence_id()
        )

        collected_at = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )

        serialized = json.dumps(
            collection_result,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

        sha256 = self.hasher.hash_text(
            serialized
        )

        record = self.hasher.create_record(
            evidence_id=evidence_id,
            evidence_type=source,
            sha256=sha256,
            collected_at=collected_at,
            metadata={
                "case": self.context.case_name,
                "target": self.context.target,
                "records": record_count,
            },
        )

        chain = ChainOfCustody(
            evidence_id
        )

        chain.add_event(
            "COLLECTED",
            details={
                "source": source,
                "records": record_count,
            },
        )

        chain.add_event(
            "HASHED",
            details={
                "algorithm": "SHA-256",
                "sha256": sha256,
            },
        )

        record["chain"] = (
            chain.to_dict()
        )

        self.context.evidence[
            evidence_id
        ] = {
            "record": record,
            "chain": chain,
            "source": source,
        }

        self._chains[
            evidence_id
        ] = chain

    # ========================================================
    # ANALYSIS
    # ========================================================
    def _analyze(
        self,
        source: str,
    ) -> None:

        # ----------------------------------------------------
        # Normalize user-facing JOCKY analysis names to the
        # internal collection names.
        # ----------------------------------------------------

        data_source = source

        if source == "memory":
            data_source = "memory.indicators"

        elif source == "filesystem":
            data_source = "filesystem.recent"

        # ----------------------------------------------------
        # Verify that the required collection exists.
        # ----------------------------------------------------

        if data_source not in (
            self.context.collected_data
        ):

            self.context.analysis_results[
                source
            ] = {
                "status": "error",
                "message": (
                    f"No collected data for {source}."
                ),
            }

            return

        data = (
            self.context.collected_data[
                data_source
            ]
        )

        # ----------------------------------------------------
        # Select the appropriate forensic analyzer.
        # ----------------------------------------------------

        if source == "processes":

            result = (
                self.process_analyzer.analyze(
                    data
                )
            )

        elif source == "network.connections":

            result = (
                self.network_analyzer.analyze(
                    data
                )
            )

        elif source in (
            "filesystem",
            "filesystem.recent",
        ):

            result = (
                self.filesystem_analyzer.analyze(
                    data
                )
            )

        elif source in (
            "memory",
            "memory.indicators",
        ):

            result = (
                self.memory_analyzer.analyze(
                    data
                )
            )

        else:

            result = {
                "status": "unsupported",
                "findings": [],
                "finding_count": 0,
            }

        # ----------------------------------------------------
        # Store analysis result using the name requested by
        # the JOCKY script.
        # ----------------------------------------------------

        self.context.analysis_results[
            source
        ] = result

        # ----------------------------------------------------
        # Record analysis in chain of custody.
        # ----------------------------------------------------

        for evidence_id, evidence in (
            self.context.evidence.items()
        ):

            if evidence_id == "_verification":
                continue

            if evidence["source"] != data_source:
                continue

            chain = evidence["chain"]

            already_analyzed = any(
                event.get("event")
                == "ANALYZED"
                for event in chain.events
            )

            if not already_analyzed:

                chain.add_event(
                    "ANALYZED",
                    details={
                        "analyzer": source,
                        "finding_count": result.get(
                            "finding_count",
                            len(
                                result.get(
                                    "findings",
                                    [],
                                )
                            ),
                        ),
                    },
                )

            evidence["record"][
                "chain"
            ] = chain.to_dict()

    # ========================================================
    # CONDITIONAL ANALYSIS / VARIABLES
    # ========================================================
    # ========================================================
    # CONDITIONAL ANALYSIS / VARIABLES
    # ========================================================
    def _let(
        self,
        arguments: dict[str, Any],
    ) -> None:

        name = arguments.get("name", "")
        action = arguments.get("action", "")
        source = arguments.get("source", "")
        conditions = arguments.get("conditions", [])

        if not name:
            raise JockyRuntimeError(
                "LET requires a variable name."
            )

        if action != "ANALYZE":
            raise JockyRuntimeError(
                f"Unsupported LET action: {action}"
            )

        data_source = source

        if source == "memory":
            data_source = "memory.indicators"

        elif source == "filesystem":
            data_source = "filesystem.recent"

        if data_source not in self.context.collected_data:
            self.context.variables[name] = {
                "status": "error",
                "message": f"No collected data for {source}.",
            }

            self.context.analysis_results[name] = (
                self.context.variables[name]
            )

            return

        data = self.context.collected_data[data_source]

        # LET conditions operate on record collections.
        records_key = None

        if source == "processes":
            records_key = "processes"

        elif source == "network.connections":
            records_key = "connections"

        elif data_source == "filesystem.recent":
            records_key = "files"

        elif data_source == "memory.indicators":
            records_key = "processes"

        if records_key is None:
            raise JockyRuntimeError(
                f"LET filtering is not supported "
                f"for source '{source}'."
            )

        records = data.get(records_key, [])

        filtered = []

        field_aliases = {
            "threads": "thread_count",
            "ppid": "parent_pid",
            "pid": "pid",
            "uid": "user",
            "cpu": "cpu",
            "memory": "memory",
        }

        def eval_comparison(field: str, operator: str, expected: Any, record: dict[str, Any]) -> bool:
            actual = record.get(field_aliases.get(field, field))
            if actual is None:
                return False
            try:
                if operator == ">":
                    return actual > expected
                if operator == "<":
                    return actual < expected
                if operator == ">=":
                    return actual >= expected
                if operator == "<=":
                    return actual <= expected
                if operator == "==":
                    return actual == expected
                if operator == "!=":
                    return actual != expected
                if operator == "IN":
                    if isinstance(expected, (list, tuple, set, str)):
                        return actual in expected
                    return str(actual) in str(expected)
                if operator == "MATCHES":
                    import re
                    return bool(re.search(str(expected), str(actual), re.IGNORECASE))
            except (TypeError, ValueError):
                return False
            return False

        def eval_node(node: Any, record: dict[str, Any]) -> bool:
            if node is None:
                return True

            if isinstance(node, dict):
                node_type = node.get("type")
                if node_type == "ComparisonExpr":
                    return eval_comparison(node.get("field", ""), node.get("operator", ""), node.get("value"), record)
                elif node_type == "LogicalExpr":
                    op = str(node.get("operator", "AND")).upper()
                    left_val = eval_node(node.get("left"), record)
                    if op == "AND":
                        return left_val and eval_node(node.get("right"), record)
                    elif op == "OR":
                        return left_val or eval_node(node.get("right"), record)
                elif node_type == "ParenExpr":
                    return eval_node(node.get("expression"), record)
                elif "field" in node:
                    return eval_comparison(node.get("field", ""), node.get("operator", ""), node.get("value"), record)

            if hasattr(node, "__class__"):
                cls_name = node.__class__.__name__
                if cls_name == "ComparisonExpr":
                    return eval_comparison(node.field, node.operator, node.value, record)
                elif cls_name == "LogicalExpr":
                    op = str(node.operator).upper()
                    left_val = eval_node(node.left, record)
                    if op == "AND":
                        return left_val and eval_node(node.right, record)
                    elif op == "OR":
                        return left_val or eval_node(node.right, record)
                elif cls_name == "ParenExpr":
                    return eval_node(node.expression, record)

            if isinstance(node, list):
                if not node:
                    return True
                res = eval_node(node[0], record)
                for item in node[1:]:
                    logical = item.get("logical", "AND").upper() if isinstance(item, dict) else "AND"
                    cur = eval_node(item, record)
                    if logical == "AND":
                        res = res and cur
                    elif logical == "OR":
                        res = res or cur
                return res

            return False

        for record in records:
            if eval_node(conditions, record):
                filtered.append(record)

        filtered_data = dict(data)

        filtered_data[records_key] = filtered

        if records_key == "processes":

            filtered_data["process_count"] = (
                len(filtered)
            )

        elif records_key == "connections":

            filtered_data["connection_count"] = (
                len(filtered)
            )

        elif records_key == "files":

            filtered_data["file_count"] = (
                len(filtered)
            )

        if source == "processes":

            result = (
                self.process_analyzer.analyze(
                    filtered_data
                )
            )

        elif source == "network.connections":

            result = (
                self.network_analyzer.analyze(
                    filtered_data
                )
            )

        elif source in (
            "filesystem",
            "filesystem.recent",
        ):

            result = (
                self.filesystem_analyzer.analyze(
                    filtered_data
                )
            )

        elif source in (
            "memory",
            "memory.indicators",
        ):

            result = (
                self.memory_analyzer.analyze(
                    filtered_data
                )
            )

        else:

            result = {
                "status": "unsupported",
                "findings": [],
                "finding_count": 0,
            }

        result["status"] = result.get(
            "status",
            "completed",
        )

        result["variable"] = name

        result["source"] = source

        result["conditions"] = conditions

        result["input_count"] = len(records)

        result["matched_count"] = len(filtered)

        self.context.variables[name] = {
            "name": name,
            "source": source,
            "conditions": conditions,
            "input_count": len(records),
            "matched_count": len(filtered),
            "data": filtered_data,
        }

        self.context.analysis_results[name] = result

    # ========================================================
    # SEARCH
    # ========================================================
    def _search(
        self,
        arguments: dict[str, Any],
    ) -> None:

        search_type = arguments.get(
            "search_type",
            "",
        )

        source = arguments.get(
            "source",
            "",
        )

        # ----------------------------------------------------
        # IOC SEARCH
        # ----------------------------------------------------

        if search_type.lower() == "ioc":

            try:

                result = (
                    self.ioc_analyzer.analyze(
                        source,
                        self.context.collected_data,
                    )
                )

                self.context.search_results.append(
                    result
                )

                # Make IOC findings available to the
                # risk engine as another analysis source.
                self.context.analysis_results[
                    "ioc"
                ] = result

                return

            except Exception as error:

                self.context.search_results.append({
                    "analyzer": "ioc",
                    "status": "error",
                    "ioc_file": source,
                    "message": str(error),
                    "finding_count": 0,
                    "findings": [],
                })

                return

        # ----------------------------------------------------
        # Generic search
        # ----------------------------------------------------

        result = {
            "type": search_type,
            "source": source,
            "status": "completed",
        }

        self.context.search_results.append(
            result
        )

    # ========================================================
    # CORRELATION
    # ========================================================

    def _correlate(
        self,
        arguments: dict[str, Any],
    ) -> None:

        left = arguments.get(
            "left",
            "",
        )

        right = arguments.get(
            "right",
            "",
        )

        result = (
            self.correlation_engine.correlate(
                left,
                right,
                self.context.collected_data,
            )
        )

        self.context.correlations.append(
            result
        )

    # ========================================================
    # RISK
    # ========================================================
    def _calculate_risk(self) -> None:
        # LET statements are analyst triage filters over data already analyzed.
        # They must not duplicate underlying findings or inflate the case risk.
        independent_results = {
            name: result
            for name, result in self.context.analysis_results.items()
            if not isinstance(result, dict) or not result.get("variable")
        }
        self.context.risk = (
            self.risk_engine.analyze(
                independent_results,
                self.context.correlations,
            )
        )

    # ========================================================
    # TIMELINE
    # ========================================================

    def _timeline(self) -> None:
        """
        Build a forensic timeline from actual collected
        process, network and filesystem records.
        """

        self.timeline_engine = TimelineEngine()

        process_data = (
            self.context.collected_data.get(
                "processes",
                {}
            )
        )

        network_data = (
            self.context.collected_data.get(
                "network.connections",
                {}
            )
        )

        filesystem_data = (
            self.context.collected_data.get(
                "filesystem.recent",
                {}
            )
        )

        processes = process_data.get(
            "processes",
            []
        )

        connections = network_data.get(
            "connections",
            []
        )

        files = filesystem_data.get(
            "files",
            []
        )

        if processes:

            self.timeline_engine.add_process_events(
                processes
            )

        if connections:

            self.timeline_engine.add_network_events(
                connections
            )

        # ----------------------------------------------------
        # Add filesystem events.
        # ----------------------------------------------------

        for file_record in files:

            timestamp = (
                file_record.get(
                    "modified_time"
                )
            )

            if not timestamp:

                timestamp = datetime.now(
                    timezone.utc
                ).isoformat()

            path = file_record.get(
                "path",
                "unknown",
            )

            self.timeline_engine.add_event(
                timestamp=timestamp,
                source="filesystem",
                event_type="FILE_MODIFIED",
                description=(
                    f"File observed: {path}"
                ),
                data={
                    "path": path,
                    "size": file_record.get(
                        "size"
                    ),
                    "sha256": file_record.get(
                        "sha256"
                    ),
                    "executable": file_record.get(
                        "executable"
                    ),
                    "mode": file_record.get(
                        "mode"
                    ),
                },
            )

        self.context.timeline = (
            self.timeline_engine.build()
        )

    # ========================================================
    # VERIFY
    # ========================================================

    def _verify(self) -> None:

        verification_results = {}

        for evidence_id, evidence in (
            self.context.evidence.items()
        ):

            if evidence_id == "_verification":
                continue

            chain = evidence["chain"]

            already_verified = any(
                event.get("event")
                == "VERIFIED"
                for event in chain.events
            )

            if not already_verified:

                chain.add_event(
                    "VERIFIED",
                    details={
                        "integrity": "verified",
                    },
                )

            verification = (
                chain.verify()
            )

            verification_results[
                evidence_id
            ] = verification

            evidence["record"][
                "chain"
            ] = chain.to_dict()

        self.context.evidence[
            "_verification"
        ] = verification_results

    # ========================================================
    # REPORT
    # ========================================================

    def _report(
        self,
        output_file: str,
    ) -> None:

        if not output_file:

            raise JockyRuntimeError(
                "REPORT requires an output filename."
            )

        self.context.report = (
            self._build_report(
                output_file
            )
        )

    def _build_report(
        self,
        output_file: str,
    ) -> dict[str, Any]:

        if not output_file:

            raise JockyRuntimeError(
                "REPORT requires an output filename."
            )

        # ----------------------------------------------------
        # Add REPORT event to evidence chains.
        # ----------------------------------------------------

        for evidence_id, evidence in (
            self.context.evidence.items()
        ):

            if evidence_id == "_verification":
                continue

            chain = evidence["chain"]

            already_reported = any(
                event.get("event")
                == "REPORTED"
                for event in chain.events
            )

            if not already_reported:

                chain.add_event(
                    "REPORTED",
                    details={
                        "report": output_file,
                    },
                )

            evidence["record"][
                "chain"
            ] = chain.to_dict()

        # Reporting is itself a custody event. Re-verify after recording it so
        # the report contains the integrity state of the final evidence chain.
        self._verify()

        # ----------------------------------------------------
        # Build evidence section.
        # ----------------------------------------------------

        evidence_output = {
            "records": {},
            "verification": {},
        }

        for evidence_id, evidence in (
            self.context.evidence.items()
        ):

            if evidence_id == "_verification":

                evidence_output[
                    "verification"
                ] = evidence

                continue

            evidence_output[
                "records"
            ][evidence_id] = (
                evidence["record"]
            )

        # ----------------------------------------------------
        # Ensure verification exists.
        # ----------------------------------------------------

        if not evidence_output[
            "verification"
        ]:

            for evidence_id, evidence in (
                self.context.evidence.items()
            ):

                if evidence_id == "_verification":
                    continue

                evidence_output[
                    "verification"
                ][evidence_id] = (
                    evidence["chain"].verify()
                )

        # ----------------------------------------------------
        # Final forensic report.
        # ----------------------------------------------------

        report = {
            "format": "JOCKY-FORENSIC-REPORT",

            "version": "1.3",

            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "case": self.context.case_name,

            "target": self.context.target,

            "output_file": output_file,

            "collected_sources": list(
                self.context.collected_data.keys()
            ),

            "analysis_sources": list(
                self.context.analysis_results.keys()
            ),

            "collection": (
                self.context.collected_data
            ),

            "analysis": (
                self.context.analysis_results
            ),

            "variables": (
                self.context.variables
            ),

            "searches": (
                self.context.search_results
            ),

            "correlations": (
                self.context.correlations
            ),

            "risk": self.context.risk,

            "timeline": self.context.timeline,

            "evidence": evidence_output,
        }

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                report,
                file,
                indent=2,
                default=str,
            )

        self.context.report = report

        return report
