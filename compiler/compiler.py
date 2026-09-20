from compiler.lexer import Lexer
from compiler.parser import Parser
from compiler.semantic import SemanticAnalyzer
from compiler.ir import IRBuilder


class CompilationError(Exception):
    """Raised when JOCKY compilation fails."""
    pass


class Compiler:
    """
    Main JOCKY compiler.

    Pipeline:

        Source
          ↓
        Lexer
          ↓
        Parser
          ↓
        AST
          ↓
        Semantic Analyzer
          ↓
        IR Builder
          ↓
        JOCKY IR
    """

    def __init__(self):
        self.semantic_analyzer = SemanticAnalyzer()
        self.ir_builder = IRBuilder()

    def compile(self, source: str):

        if not source.strip():
            raise CompilationError(
                "JOCKY source cannot be empty."
            )

        # ----------------------------------------------------
        # 1. Lexical analysis
        # ----------------------------------------------------

        try:
            lexer = Lexer(source)
            tokens = lexer.tokenize()

        except Exception as error:
            raise CompilationError(
                f"Lexical analysis failed: {error}"
            ) from error

        # ----------------------------------------------------
        # 2. Parsing
        # ----------------------------------------------------

        try:
            parser = Parser(tokens)
            ast = parser.parse()

        except Exception as error:
            raise CompilationError(
                f"Parsing failed: {error}"
            ) from error

        # ----------------------------------------------------
        # 3. Semantic analysis
        # ----------------------------------------------------

        try:
            self.semantic_analyzer.analyze(ast)

        except Exception as error:
            raise CompilationError(
                f"Semantic analysis failed: {error}"
            ) from error

        # ----------------------------------------------------
        # 4. IR generation
        # ----------------------------------------------------

        try:
            ir = self.ir_builder.build(ast)

        except Exception as error:
            raise CompilationError(
                f"IR generation failed: {error}"
            ) from error

        return ir

    def compile_file(self, filename: str):

        try:
            with open(
                filename,
                "r",
                encoding="utf-8"
            ) as file:

                source = file.read()

        except OSError as error:

            raise CompilationError(
                f"Could not read JOCKY file "
                f"'{filename}': {error}"
            ) from error

        return self.compile(source)

    def compile_str(self, source: str):
        """Compile in-memory JOCKY source for the GUI and API consumers."""
        return self.compile(source)


def compile_source(source: str):
    """
    Convenience function for compiling JOCKY source.
    """

    compiler = Compiler()

    return compiler.compile(source)


def compile_file(filename: str):
    """
    Convenience function for compiling a JOCKY file.
    """

    compiler = Compiler()

    return compiler.compile_file(filename)
