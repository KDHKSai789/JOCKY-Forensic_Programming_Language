from dataclasses import dataclass, field
from typing import Any


from compiler.ast import ast_to_dict

# ============================================================
# IR Instruction
# ============================================================

@dataclass
class IRInstruction:
    """
    One platform-independent JOCKY operation.
    """

    operation: str
    arguments: dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "operation": self.operation,
            "arguments": self.arguments,
        }


# ============================================================
# JOCKY IR Program
# ============================================================

@dataclass
class JockyIR:
    """
    Complete intermediate representation of a JOCKY program.
    """

    case_name: str | None = None
    target: str | None = None

    instructions: list[IRInstruction] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def add_instruction(
        self,
        operation: str,
        **arguments,
    ):
        instruction = IRInstruction(
            operation=operation,
            arguments=arguments,
        )

        self.instructions.append(instruction)

    def to_dict(self):

        return {
            "format": "JOCKY-IR",
            "version": "1.0",

            "case": self.case_name,

            "target": self.target,

            "metadata": self.metadata,

            "instructions": [
                instruction.to_dict()
                for instruction in self.instructions
            ],
        }

    def __repr__(self):

        return str(self.to_dict())


# ============================================================
# IR Builder
# ============================================================

class IRBuilder:
    """
    Converts the JOCKY AST into platform-independent IR.
    """

    def build(self, program):

        ir = JockyIR()

        for statement in program.statements:

            statement_type = (
                type(statement).__name__
            )

            # ------------------------------------------------
            # CASE
            # ------------------------------------------------

            if statement_type == "CaseStatement":

                ir.case_name = statement.name

            # ------------------------------------------------
            # TARGET
            # ------------------------------------------------

            elif statement_type == "TargetStatement":

                ir.target = statement.target

            # ------------------------------------------------
            # COLLECT
            # ------------------------------------------------

            elif statement_type == "CollectStatement":

                ir.add_instruction(
                    "COLLECT",
                    source=statement.source,
                )

            # ------------------------------------------------
            # ANALYZE
            # ------------------------------------------------

            elif statement_type == "AnalyzeStatement":

                ir.add_instruction(
                    "ANALYZE",
                    source=statement.source,
                    conditions=ast_to_dict(statement.conditions),
                )

            # ------------------------------------------------
            # LET
            # ------------------------------------------------

            elif statement_type == "LetStatement":

                ir.add_instruction(
                    "LET",
                    name=statement.name,
                    action=statement.operation,
                    source=statement.source,
                    conditions=ast_to_dict(statement.conditions),
                )

            # ------------------------------------------------
            # SEARCH
            # ------------------------------------------------

            elif statement_type == "SearchStatement":

                ir.add_instruction(
                    "SEARCH",
                    search_type=statement.search_type,
                    source=statement.source,
                )

            # ------------------------------------------------
            # CORRELATE
            # ------------------------------------------------

            elif statement_type == "CorrelateStatement":

                ir.add_instruction(
                    "CORRELATE",
                    left=statement.left,
                    right=statement.right,
                )

            # ------------------------------------------------
            # TIMELINE
            # ------------------------------------------------

            elif statement_type == "TimelineStatement":

                ir.add_instruction(
                    "TIMELINE",
                    sources=statement.sources,
                )

            # ------------------------------------------------
            # VERIFY
            # ------------------------------------------------

            elif statement_type == "VerifyStatement":

                ir.add_instruction(
                    "VERIFY",
                    target=statement.target,
                )

            # ------------------------------------------------
            # REPORT
            # ------------------------------------------------

            elif statement_type == "ReportStatement":

                ir.add_instruction(
                    "REPORT",
                    output_file=statement.output_file,
                )

            # ------------------------------------------------
            # Unsupported AST node
            # ------------------------------------------------

            else:

                raise ValueError(
                    f"Unsupported AST node: "
                    f"{statement_type}"
                )

        return ir
