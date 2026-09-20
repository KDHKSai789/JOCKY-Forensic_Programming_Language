from dataclasses import dataclass, field
from typing import Any


@dataclass
class ASTNode:
    line: int = 0
    column: int = 0


@dataclass
class Program(ASTNode):
    statements: list[ASTNode] = field(default_factory=list)


@dataclass
class CaseStatement(ASTNode):
    name: str = ""


@dataclass
class TargetStatement(ASTNode):
    target: str = ""


@dataclass
class CollectStatement(ASTNode):
    source: str = ""


@dataclass
class ComparisonExpr(ASTNode):
    field: str = ""
    operator: str = ""
    value: Any = None


@dataclass
class LogicalExpr(ASTNode):
    left: Any = None
    operator: str = ""
    right: Any = None


@dataclass
class ParenExpr(ASTNode):
    expression: Any = None


@dataclass
class AnalyzeStatement(ASTNode):
    source: str = ""
    conditions: Any = None


@dataclass
class LetStatement(ASTNode):
    name: str = ""
    operation: str = ""
    source: str = ""
    conditions: Any = None


@dataclass
class SearchStatement(ASTNode):
    search_type: str = ""
    source: str = ""


@dataclass
class CorrelateStatement(ASTNode):
    left: str = ""
    right: str = ""


@dataclass
class TimelineStatement(ASTNode):
    sources: list[str] = field(default_factory=list)


@dataclass
class VerifyStatement(ASTNode):
    target: str = "evidence"


@dataclass
class ReportStatement(ASTNode):
    output_file: str = ""


def ast_to_dict(node: Any) -> Any:
    if hasattr(node, "__dataclass_fields__"):
        result = {
            "type": node.__class__.__name__
        }

        for field_name in node.__dataclass_fields__:
            if field_name in (
                "line",
                "column",
            ):
                continue

            value = getattr(
                node,
                field_name,
            )

            result[field_name] = ast_to_dict(
                value
            )

        return result

    if isinstance(node, list):
        return [
            ast_to_dict(item)
            for item in node
        ]

    if isinstance(node, dict):
        return {
            key: ast_to_dict(value)
            for key, value in node.items()
        }

    return node
