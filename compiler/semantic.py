from compiler.ast import (
    Program,
    CaseStatement,
    TargetStatement,
    CollectStatement,
    AnalyzeStatement,
    LetStatement,
    SearchStatement,
    CorrelateStatement,
    TimelineStatement,
    VerifyStatement,
    ReportStatement,
    ComparisonExpr,
    LogicalExpr,
    ParenExpr,
)


class SemanticError(Exception):
    """Raised when a JOCKY program is logically invalid."""
    pass


class SemanticAnalyzer:
    """
    Performs semantic validation on the JOCKY AST.
    """

    # --------------------------------------------------------
    # Supported forensic sources
    # --------------------------------------------------------

    VALID_COLLECTIONS = {
        "processes",
        "network.connections",
        "filesystem.recent",
        "filesystem",
        "memory.indicators",
        "memory",
        "events",
        "windows.events",
        "registry",
        "services",
        "persistence",
        "drivers",
        "binaries",
        "threads",
        "hashes",
    }

    VALID_ANALYSIS = {
        "processes",
        "network.connections",
        "filesystem",
        "filesystem.recent",
        "memory",
        "memory.indicators",
        "events",
        "windows.events",
        "registry",
        "services",
        "persistence",
        "drivers",
        "binaries",
        "threads",
    }

    # --------------------------------------------------------
    # Supported condition fields
    # --------------------------------------------------------

    CONDITION_FIELDS = {
        "processes": {
            "pid",
            "ppid",
            "uid",
            "user",
            "name",
            "executable",
            "command_line",
            "threads",
            "memory",
            "cpu",
        },

        "network.connections": {
            "local_port",
            "remote_port",
            "pid",
            "uid",
        },

        "filesystem": {
            "size",
            "mtime",
            "path",
        },

        "filesystem.recent": {
            "size",
            "mtime",
            "path",
        },

        "memory": {
            "pid",
            "writable_executable",
            "deleted_executable",
            "writable_anonymous",
        },

        "memory.indicators": {
            "pid",
            "writable_executable",
            "deleted_executable",
            "writable_anonymous",
        },

        "events": {
            "timestamp",
            "pid",
            "event_type",
        },

        "windows.events": {
            "timestamp",
            "pid",
            "event_type",
        },

        "registry": {
            "path",
            "value",
        },

        "services": {
            "name",
            "pid",
            "status",
        },

        "persistence": {
            "path",
            "name",
            "type",
        },

        "drivers": {
            "name",
            "path",
            "version",
        },

        "binaries": {
            "path",
            "size",
            "sha256",
        },

        "threads": {
            "pid",
            "tid",
        },
    }

    # --------------------------------------------------------
    # Supported comparison operators
    # --------------------------------------------------------

    VALID_OPERATORS = {
        ">",
        "<",
        ">=",
        "<=",
        "==",
        "!=",
    }

    # --------------------------------------------------------
    # Supported logical operators
    # --------------------------------------------------------

    VALID_LOGICAL_OPERATORS = {
        "AND",
        "OR",
    }

    # --------------------------------------------------------
    # Constructor
    # --------------------------------------------------------

    def __init__(self):
        self.errors = []
        self.warnings = []

        self.case_name = None
        self.target = None

        self.collected_sources = set()

        self.variables = set()

    # --------------------------------------------------------
    # Main analysis
    # --------------------------------------------------------

    def analyze(self, program: Program):

        self.errors = []
        self.warnings = []

        self.case_name = None
        self.target = None

        self.collected_sources = set()
        self.variables = set()

        for statement in program.statements:
            self.visit(statement)

        self.check_required_statements()

        if self.errors:

            message = "\n".join(
                f"  - {error}"
                for error in self.errors
            )

            raise SemanticError(
                f"JOCKY semantic analysis failed:\n{message}"
            )

        return {
            "valid": True,
            "case": self.case_name,
            "target": self.target,
            "warnings": self.warnings,
        }

    # --------------------------------------------------------
    # Statement dispatcher
    # --------------------------------------------------------

    def visit(self, statement):

        if isinstance(statement, CaseStatement):
            self.visit_case(statement)

        elif isinstance(statement, TargetStatement):
            self.visit_target(statement)

        elif isinstance(statement, CollectStatement):
            self.visit_collect(statement)

        elif isinstance(statement, AnalyzeStatement):
            self.visit_analyze(statement)

        elif isinstance(statement, LetStatement):
            self.visit_let(statement)

        elif isinstance(statement, SearchStatement):
            self.visit_search(statement)

        elif isinstance(statement, CorrelateStatement):
            self.visit_correlate(statement)

        elif isinstance(statement, TimelineStatement):
            self.visit_timeline(statement)

        elif isinstance(statement, VerifyStatement):
            self.visit_verify(statement)

        elif isinstance(statement, ReportStatement):
            self.visit_report(statement)

        else:

            self.errors.append(
                f"Unknown statement: {type(statement).__name__}"
            )

    # --------------------------------------------------------
    # CASE
    # --------------------------------------------------------

    def visit_case(self, statement):

        if self.case_name is not None:

            self.errors.append(
                "Only one CASE statement is allowed."
            )

        if not statement.name.strip():

            self.errors.append(
                "CASE name cannot be empty."
            )

        self.case_name = statement.name

    # --------------------------------------------------------
    # TARGET
    # --------------------------------------------------------

    def visit_target(self, statement):

        if self.target is not None:

            self.errors.append(
                "Only one TARGET statement is allowed."
            )

        if not statement.target.strip():

            self.errors.append(
                "TARGET cannot be empty."
            )

        self.target = statement.target

    # --------------------------------------------------------
    # COLLECT
    # --------------------------------------------------------

    def visit_collect(self, statement):

        source = statement.source

        if source not in self.VALID_COLLECTIONS:

            self.errors.append(
                f"Unknown collection source: '{source}'."
            )

            return

        self.collected_sources.add(source)

    # --------------------------------------------------------
    # ANALYZE
    # --------------------------------------------------------

    def visit_analyze(self, statement):

        source = statement.source

        if source not in self.VALID_ANALYSIS:

            self.errors.append(
                f"Unknown analysis source: '{source}'."
            )

            return

        self.check_analysis_collection(source)

        self.validate_conditions(
            source,
            statement.conditions,
            context="ANALYZE",
        )

    # --------------------------------------------------------
    # LET
    # --------------------------------------------------------

    def visit_let(self, statement):

        name = statement.name.strip()

        # ----------------------------------------------------
        # Variable name
        # ----------------------------------------------------

        if not name:

            self.errors.append(
                "LET variable name cannot be empty."
            )

            return

        if name in self.variables:

            self.errors.append(
                f"Variable '{name}' is already defined."
            )

        self.variables.add(name)

        # ----------------------------------------------------
        # Operation
        # ----------------------------------------------------

        if statement.operation != "ANALYZE":

            self.errors.append(
                f"LET variable '{name}' uses unsupported "
                f"operation '{statement.operation}'."
            )

        # ----------------------------------------------------
        # Analysis source
        # ----------------------------------------------------

        source = statement.source

        if source not in self.VALID_ANALYSIS:

            self.errors.append(
                f"Unknown analysis source in LET "
                f"'{name}': '{source}'."
            )

            return

        # ----------------------------------------------------
        # Collection dependency
        # ----------------------------------------------------

        self.check_analysis_collection(source)

        # ----------------------------------------------------
        # Conditions
        # ----------------------------------------------------

        self.validate_conditions(
            source,
            statement.conditions,
            context=f"LET '{name}'",
        )

    # --------------------------------------------------------
    # Analysis collection dependency
    # --------------------------------------------------------

    def check_analysis_collection(self, source):

        if source in self.collected_sources:
            return

        compatible = {
            "memory": {
                "memory.indicators"
            },

            "memory.indicators": {
                "memory"
            },

            "filesystem": {
                "filesystem.recent"
            },

            "filesystem.recent": {
                "filesystem"
            },

            "events": {
                "windows.events"
            },

            "windows.events": {
                "events"
            },
        }

        allowed_sources = compatible.get(
            source,
            set(),
        )

        if not (
            self.collected_sources
            & allowed_sources
        ):

            self.warnings.append(
                f"ANALYZE '{source}' has no matching "
                f"COLLECT statement."
            )

    VALID_OPERATORS = {
        ">",
        "<",
        ">=",
        "<=",
        "==",
        "!=",
        "MATCHES",
        "IN",
    }

    # --------------------------------------------------------
    # Validate conditions
    # --------------------------------------------------------

    def validate_conditions(
        self,
        source,
        conditions,
        context,
    ):

        if not conditions:
            return

        valid_fields = self.CONDITION_FIELDS.get(
            source,
            set(),
        )

        def _validate_node(node):
            if node is None:
                return

            if isinstance(node, ComparisonExpr):
                field = node.field
                operator = node.operator
                value = node.value

                if not field:
                    self.errors.append(f"{context} condition is missing a field.")
                elif field not in valid_fields:
                    self.errors.append(
                        f"{context} uses unsupported field '{field}' for source '{source}' at line {node.line}, col {node.column}."
                    )

                if operator not in self.VALID_OPERATORS:
                    self.errors.append(
                        f"{context} uses unsupported operator '{operator}' at line {node.line}, col {node.column}."
                    )

                if value is None:
                    self.errors.append(
                        f"{context} condition for '{field}' is missing a value."
                    )

            elif isinstance(node, LogicalExpr):
                if node.operator not in self.VALID_LOGICAL_OPERATORS:
                    self.errors.append(
                        f"{context} uses unsupported logical operator '{node.operator}'."
                    )
                _validate_node(node.left)
                _validate_node(node.right)

            elif isinstance(node, ParenExpr):
                _validate_node(node.expression)

            elif isinstance(node, list):
                for item in node:
                    _validate_node(item)

            elif isinstance(node, dict):
                field = node.get("field")
                operator = node.get("operator")
                value = node.get("value")
                if field and field not in valid_fields:
                    self.errors.append(
                        f"{context} uses unsupported field '{field}' for source '{source}'."
                    )
                if operator and operator not in self.VALID_OPERATORS:
                    self.errors.append(
                        f"{context} uses unsupported operator '{operator}'."
                    )
                if value is None and field is not None:
                    self.errors.append(
                        f"{context} condition for '{field}' is missing a value."
                    )

        _validate_node(conditions)

    # --------------------------------------------------------
    # SEARCH
    # --------------------------------------------------------

    def visit_search(self, statement):

        if not statement.search_type.strip():

            self.errors.append(
                "SEARCH type cannot be empty."
            )

        if not statement.source.strip():

            self.errors.append(
                "SEARCH source cannot be empty."
            )

    # --------------------------------------------------------
    # CORRELATE
    # --------------------------------------------------------

    def visit_correlate(self, statement):

        if not statement.left.strip():

            self.errors.append(
                "CORRELATE left source cannot be empty."
            )

        if not statement.right.strip():

            self.errors.append(
                "CORRELATE right source cannot be empty."
            )

    # --------------------------------------------------------
    # TIMELINE
    # --------------------------------------------------------

    def visit_timeline(self, statement):

        for source in statement.sources:

            if source not in self.VALID_COLLECTIONS:

                self.errors.append(
                    f"Unknown TIMELINE source: '{source}'."
                )

    # --------------------------------------------------------
    # VERIFY
    # --------------------------------------------------------

    def visit_verify(self, statement):

        if not statement.target.strip():

            self.errors.append(
                "VERIFY target cannot be empty."
            )

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    def visit_report(self, statement):

        if not statement.output_file.strip():

            self.errors.append(
                "REPORT output file cannot be empty."
            )

    # --------------------------------------------------------
    # Required statements
    # --------------------------------------------------------

    def check_required_statements(self):

        if self.case_name is None:

            self.errors.append(
                "JOCKY program requires a CASE statement."
            )

        if self.target is None:

            self.errors.append(
                "JOCKY program requires a TARGET statement."
            )
