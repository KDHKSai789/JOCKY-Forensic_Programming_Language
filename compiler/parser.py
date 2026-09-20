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


class Parser:
    """
    Converts JOCKY tokens into an Abstract Syntax Tree (AST).
    """

    def __init__(self, tokens):
        self.tokens = tokens
        self.position = 0

    def current(self):
        return self.tokens[self.position]

    def advance(self):
        token = self.current()

        if self.position < len(self.tokens) - 1:
            self.position += 1

        return token

    def check(self, token_type):
        return self.current().type == token_type

    def expect(self, token_type):
        token = self.current()

        if token.type != token_type:
            raise SyntaxError(
                f"Expected {token_type}, "
                f"got {token.type} "
                f"at line {token.line}, "
                f"column {token.column}"
            )

        self.advance()

        return token

    def parse(self):
        statements = []

        while not self.check("EOF"):
            statement = self.parse_statement()

            if statement is not None:
                statements.append(statement)

        return Program(
            statements=statements
        )

    def parse_statement(self):
        token_type = self.current().type

        if token_type == "CASE":
            return self.parse_case()

        if token_type == "TARGET":
            return self.parse_target()

        if token_type == "COLLECT":
            return self.parse_collect()

        if token_type == "ANALYZE":
            return self.parse_analyze()

        if token_type == "LET":
            return self.parse_let()

        if token_type == "SEARCH":
            return self.parse_search()

        if token_type == "CORRELATE":
            return self.parse_correlate()

        if token_type == "TIMELINE":
            return self.parse_timeline()

        if token_type == "VERIFY":
            return self.parse_verify()

        if token_type == "REPORT":
            return self.parse_report()

        raise SyntaxError(
            f"Unexpected token {self.current().value!r} "
            f"at line {self.current().line}, "
            f"column {self.current().column}"
        )

    # ========================================================
    # CASE
    # ========================================================

    def parse_case(self):
        token = self.expect("CASE")
        name = self.expect("STRING")

        return CaseStatement(
            name=name.value,
            line=token.line,
            column=token.column,
        )

    # ========================================================
    # TARGET
    # ========================================================

    def parse_target(self):
        token = self.expect("TARGET")
        target = self.expect("STRING")

        return TargetStatement(
            target=target.value,
            line=token.line,
            column=token.column,
        )

    # ========================================================
    # COLLECT
    # ========================================================

    def parse_collect(self):
        token = self.expect("COLLECT")
        source = self.expect("IDENTIFIER")

        return CollectStatement(
            source=source.value,
            line=token.line,
            column=token.column,
        )

    # ========================================================
    # ANALYZE
    # ========================================================

    # ========================================================
    # ANALYZE
    # ========================================================

    def parse_analyze(self):
        token = self.expect("ANALYZE")
        source = self.expect("IDENTIFIER")

        conditions = None
        if self.check("WHERE"):
            self.advance()
            conditions = self.parse_expression()

        return AnalyzeStatement(
            source=source.value,
            conditions=conditions,
            line=token.line,
            column=token.column,
        )

    # ========================================================
    # LET
    # ========================================================

    def parse_let(self):
        token = self.expect("LET")

        name = self.expect("IDENTIFIER")
        self.expect("EQUALS")
        self.expect("ANALYZE")
        source = self.expect("IDENTIFIER")

        conditions = None
        if self.check("WHERE"):
            self.advance()
            conditions = self.parse_expression()

        return LetStatement(
            name=name.value,
            operation="ANALYZE",
            source=source.value,
            conditions=conditions,
            line=token.line,
            column=token.column,
        )

    # ========================================================
    # EXPRESSION PARSING (Precedence: Paren > Compare > AND > OR)
    # ========================================================

    def parse_expression(self):
        return self.parse_or()

    def parse_or(self):
        left = self.parse_and()

        while self.check("OR"):
            op_token = self.advance()
            right = self.parse_and()
            left = LogicalExpr(
                left=left,
                operator="OR",
                right=right,
                line=op_token.line,
                column=op_token.column,
            )

        return left

    def parse_and(self):
        left = self.parse_primary_condition()

        while self.check("AND"):
            op_token = self.advance()
            right = self.parse_primary_condition()
            left = LogicalExpr(
                left=left,
                operator="AND",
                right=right,
                line=op_token.line,
                column=op_token.column,
            )

        return left

    def parse_primary_condition(self):
        if self.check("LPAREN"):
            lparen = self.expect("LPAREN")
            expr = self.parse_expression()
            self.expect("RPAREN")
            return ParenExpr(
                expression=expr,
                line=lparen.line,
                column=lparen.column,
            )

        return self.parse_comparison()

    def parse_comparison(self):
        field = self.expect("IDENTIFIER")

        operator_token = self.current()

        valid_operators = {
            "GREATER_THAN",
            "LESS_THAN",
            "GREATER_EQUAL",
            "LESS_EQUAL",
            "EQUAL_EQUAL",
            "NOT_EQUAL",
            "MATCHES",
            "IN",
        }

        if operator_token.type not in valid_operators:
            raise SyntaxError(
                f"Expected comparison operator, got '{operator_token.value}' "
                f"at line {operator_token.line}, column {operator_token.column}"
            )

        operator = self.advance()

        val_token = self.current()

        if val_token.type == "NUMBER":
            self.advance()
            value = int(val_token.value)
        elif val_token.type == "STRING":
            self.advance()
            value = val_token.value
        elif val_token.type == "IDENTIFIER":
            self.advance()
            value = val_token.value
        else:
            raise SyntaxError(
                f"Expected number, string or identifier value, got '{val_token.value}' "
                f"at line {val_token.line}, column {val_token.column}"
            )

        return ComparisonExpr(
            field=field.value,
            operator=operator.value,
            value=value,
            line=field.line,
            column=field.column,
        )

    # ========================================================
    # SEARCH
    # ========================================================

    def parse_search(self):
        token = self.expect("SEARCH")

        search_type = self.expect(
            "IDENTIFIER"
        )

        self.expect("FROM")

        source = self.expect(
            "STRING"
        )

        return SearchStatement(
            search_type=search_type.value,
            source=source.value,
            line=token.line,
            column=token.column,
        )

    # ========================================================
    # CORRELATE
    # ========================================================

    def parse_correlate(self):
        token = self.expect("CORRELATE")

        left = self.expect(
            "IDENTIFIER"
        )

        self.expect("WITH")

        right = self.expect(
            "IDENTIFIER"
        )

        return CorrelateStatement(
            left=left.value,
            right=right.value,
            line=token.line,
            column=token.column,
        )

    # ========================================================
    # TIMELINE
    # ========================================================

    def parse_timeline(self):
        token = self.expect("TIMELINE")

        sources = []

        while self.check("FROM"):

            self.advance()

            source = self.expect(
                "IDENTIFIER"
            )

            sources.append(
                source.value
            )

        return TimelineStatement(
            sources=sources,
            line=token.line,
            column=token.column,
        )

    # ========================================================
    # VERIFY
    # ========================================================

    def parse_verify(self):
        token = self.expect("VERIFY")

        target = self.expect(
            "IDENTIFIER"
        )

        return VerifyStatement(
            target=target.value,
            line=token.line,
            column=token.column,
        )

    # ========================================================
    # REPORT
    # ========================================================

    def parse_report(self):
        token = self.expect("REPORT")

        output_file = self.expect(
            "STRING"
        )

        return ReportStatement(
            output_file=output_file.value,
            line=token.line,
            column=token.column,
        )
