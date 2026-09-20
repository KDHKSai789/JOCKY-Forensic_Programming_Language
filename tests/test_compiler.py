"""
JOCKY Compiler Test Suite
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from compiler.lexer import Lexer
from compiler.parser import Parser
from compiler.compiler import Compiler, CompilationError
from compiler.ast import ComparisonExpr, LogicalExpr, ParenExpr


class TestLexer(unittest.TestCase):

    def _tokens(self, src):
        return Lexer(src).tokenize()

    def test_keywords(self):
        tokens = self._tokens("CASE TARGET COLLECT ANALYZE LET WHERE AND OR")
        types = [t.type for t in tokens if t.type != "EOF"]
        self.assertIn("CASE", types)
        self.assertIn("WHERE", types)
        self.assertIn("AND", types)
        self.assertIn("OR", types)

    def test_operators(self):
        tokens = self._tokens("> < >= <= == !=")
        types = [t.type for t in tokens if t.type != "EOF"]
        self.assertIn("GREATER_THAN", types)
        self.assertIn("LESS_THAN", types)
        self.assertIn("GREATER_EQUAL", types)
        self.assertIn("NOT_EQUAL", types)

    def test_parens(self):
        tokens = self._tokens("( )")
        types = [t.type for t in tokens if t.type != "EOF"]
        self.assertIn("LPAREN", types)
        self.assertIn("RPAREN", types)

    def test_string(self):
        tokens = self._tokens('"hello world"')
        strings = [t for t in tokens if t.type == "STRING"]
        self.assertEqual(len(strings), 1)
        self.assertEqual(strings[0].value, "hello world")

    def test_number(self):
        tokens = self._tokens("42 100")
        nums = [t for t in tokens if t.type == "NUMBER"]
        self.assertEqual(len(nums), 2)
        self.assertEqual(nums[0].value, "42")

    def test_comment_ignored(self):
        tokens = self._tokens("# this is a comment\nCASE")
        types = [t.type for t in tokens if t.type != "EOF"]
        self.assertEqual(types, ["CASE"])

    def test_matches_in_keywords(self):
        tokens = self._tokens("MATCHES IN")
        types = [t.type for t in tokens if t.type != "EOF"]
        self.assertIn("MATCHES", types)
        self.assertIn("IN", types)


class TestParser(unittest.TestCase):

    def _parse(self, src):
        tokens = Lexer(src).tokenize()
        return Parser(tokens).parse()

    def test_case_statement(self):
        prog = self._parse('CASE "MyCase"')
        from compiler.ast import CaseStatement
        self.assertIsInstance(prog.statements[0], CaseStatement)
        self.assertEqual(prog.statements[0].name, "MyCase")

    def test_case_requires_a_quoted_string(self):
        with self.assertRaises(SyntaxError):
            self._parse("CASE MyCase")

    def test_collect_statement(self):
        prog = self._parse("COLLECT processes")
        from compiler.ast import CollectStatement
        self.assertIsInstance(prog.statements[0], CollectStatement)

    def test_let_no_where(self):
        prog = self._parse("LET x = ANALYZE processes")
        from compiler.ast import LetStatement
        stmt = prog.statements[0]
        self.assertIsInstance(stmt, LetStatement)
        self.assertEqual(stmt.name, "x")
        self.assertIsNone(stmt.conditions)

    def test_let_simple_where(self):
        prog = self._parse("LET x = ANALYZE processes WHERE pid > 100")
        from compiler.ast import LetStatement
        stmt = prog.statements[0]
        self.assertIsInstance(stmt.conditions, ComparisonExpr)
        self.assertEqual(stmt.conditions.field, "pid")
        self.assertEqual(stmt.conditions.operator, ">")
        self.assertEqual(stmt.conditions.value, 100)

    def test_let_and_condition(self):
        prog = self._parse("LET x = ANALYZE processes WHERE pid > 100 AND threads > 5")
        from compiler.ast import LetStatement
        stmt = prog.statements[0]
        self.assertIsInstance(stmt.conditions, LogicalExpr)
        self.assertEqual(stmt.conditions.operator, "AND")

    def test_let_or_condition(self):
        prog = self._parse("LET x = ANALYZE processes WHERE pid > 100 OR threads > 5")
        from compiler.ast import LetStatement
        stmt = prog.statements[0]
        self.assertIsInstance(stmt.conditions, LogicalExpr)
        self.assertEqual(stmt.conditions.operator, "OR")

    def test_parenthesized_condition(self):
        prog = self._parse("LET x = ANALYZE processes WHERE (pid > 100 OR threads > 5) AND pid != 1")
        from compiler.ast import LetStatement
        stmt = prog.statements[0]
        # Top-level is AND
        self.assertIsInstance(stmt.conditions, LogicalExpr)
        self.assertEqual(stmt.conditions.operator, "AND")
        # Left side is ParenExpr wrapping OR
        self.assertIsInstance(stmt.conditions.left, ParenExpr)
        inner = stmt.conditions.left.expression
        self.assertIsInstance(inner, LogicalExpr)
        self.assertEqual(inner.operator, "OR")

    def test_string_comparison(self):
        prog = self._parse('LET x = ANALYZE processes WHERE uid == "root"')
        from compiler.ast import LetStatement
        cond = prog.statements[0].conditions
        self.assertIsInstance(cond, ComparisonExpr)
        self.assertEqual(cond.value, "root")

    def test_report_statement(self):
        prog = self._parse('REPORT "output.json"')
        from compiler.ast import ReportStatement
        self.assertIsInstance(prog.statements[0], ReportStatement)


class TestCompiler(unittest.TestCase):

    def _compile(self, src):
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jocky", delete=False, encoding="utf-8") as f:
            f.write(src)
            path = f.name
        try:
            return Compiler().compile_file(path)
        finally:
            os.unlink(path)

    def test_basic_compilation(self):
        ir = self._compile('CASE "Test"\nTARGET "LOCAL"\nCOLLECT processes\nANALYZE processes\nREPORT "out.json"')
        self.assertIsNotNone(ir)
        self.assertEqual(ir.case_name, "Test")

    def test_let_ir(self):
        ir = self._compile('CASE "T"\nTARGET "LOCAL"\nCOLLECT processes\nLET x = ANALYZE processes WHERE pid > 100\nREPORT "r.json"')
        ops = [i.operation for i in ir.instructions]
        self.assertIn("LET", ops)

    def test_conditions_serialized(self):
        ir = self._compile('CASE "T"\nTARGET "LOCAL"\nCOLLECT processes\nLET x = ANALYZE processes WHERE (pid > 10 OR threads > 5) AND pid != 1\nREPORT "r.json"')
        let_instr = next(i for i in ir.instructions if i.operation == "LET")
        cond = let_instr.arguments.get("conditions")
        self.assertIsNotNone(cond)
        self.assertEqual(cond.get("type"), "LogicalExpr")


class TestIR(unittest.TestCase):

    def test_ir_serializable(self):
        import json, tempfile, os
        src = 'CASE "T"\nTARGET "LOCAL"\nCOLLECT processes\nANALYZE processes\nREPORT "r.json"'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jocky", delete=False, encoding="utf-8") as f:
            f.write(src)
            path = f.name
        try:
            ir = Compiler().compile_file(path)
            serialized = json.dumps(ir.to_dict(), default=str)
            self.assertIn("COLLECT", serialized)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
