from compiler.lexer import Lexer
from compiler.parser import Parser
from compiler.ast import ast_to_dict
import pprint


with open("test.jocky", "r") as file:
    source = file.read()


tokens = Lexer(source).tokenize()

print("\n=== TOKENS ===")

for token in tokens:
    print(token)


tree = Parser(tokens).parse()

print("\n=== AST ===")

pprint.pp(ast_to_dict(tree))
