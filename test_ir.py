from compiler.lexer import Lexer
from compiler.parser import Parser
from compiler.semantic import SemanticAnalyzer
from compiler.ir import IRBuilder


# ------------------------------------------------------------
# Read JOCKY program
# ------------------------------------------------------------

with open("test.jocky", "r") as file:
    source = file.read()


# ------------------------------------------------------------
# Lexer
# ------------------------------------------------------------

tokens = Lexer(source).tokenize()


# ------------------------------------------------------------
# Parser
# ------------------------------------------------------------

ast = Parser(tokens).parse()


# ------------------------------------------------------------
# Semantic analysis
# ------------------------------------------------------------

analyzer = SemanticAnalyzer()

result = analyzer.analyze(ast)

print("=== SEMANTIC ANALYSIS ===")
print(result)


# ------------------------------------------------------------
# AST → IR
# ------------------------------------------------------------

ir = IRBuilder().build(ast)


print("\n=== JOCKY IR ===")

import pprint

pprint.pp(ir.to_dict())
