from dataclasses import dataclass


# ============================================================
# Token
# ============================================================

@dataclass
class Token:
    type: str
    value: str
    line: int
    column: int

    def __repr__(self):
        return (
            f"Token("
            f"type={self.type!r}, "
            f"value={self.value!r}, "
            f"line={self.line}, "
            f"column={self.column}"
            f")"
        )


# ============================================================
# JOCKY Keywords
# ============================================================

KEYWORDS = {
    "CASE": "CASE",
    "TARGET": "TARGET",
    "COLLECT": "COLLECT",
    "ANALYZE": "ANALYZE",
    "LET": "LET",
    "SEARCH": "SEARCH",
    "FROM": "FROM",
    "CORRELATE": "CORRELATE",
    "WITH": "WITH",
    "TIMELINE": "TIMELINE",
    "VERIFY": "VERIFY",
    "REPORT": "REPORT",
    "WHERE": "WHERE",
    "MATCHES": "MATCHES",
    "IN": "IN",
    "AND": "AND",
    "OR": "OR",
}


# ============================================================
# Lexer
# ============================================================

class Lexer:
    """
    Converts JOCKY source code into a stream of tokens.
    """

    def __init__(self, source: str):
        self.source = source
        self.position = 0
        self.line = 1
        self.column = 1

    def current(self):
        if self.position >= len(self.source):
            return None
        return self.source[self.position]

    def peek(self, offset=1):
        position = self.position + offset
        if position >= len(self.source):
            return None
        return self.source[position]

    def advance(self):
        char = self.current()

        if char is None:
            return None

        self.position += 1

        if char == "\n":
            self.line += 1
            self.column = 1
        else:
            self.column += 1

        return char

    def skip_whitespace(self):
        while True:
            char = self.current()

            if char is None:
                return

            if char in " \t\r":
                self.advance()

            elif char == "\n":
                self.advance()

            else:
                return

    def skip_comment(self):
        if self.current() == "#":

            while self.current() is not None:

                if self.current() == "\n":
                    break

                self.advance()

    def read_identifier(self):
        start_line = self.line
        start_column = self.column

        value = ""

        while True:
            char = self.current()

            if char is None:
                break

            if char.isalnum() or char in "_-.":
                value += char
                self.advance()

            else:
                break

        upper_value = value.upper()

        if upper_value in KEYWORDS:
            token_type = KEYWORDS[upper_value]
        else:
            token_type = "IDENTIFIER"

        return Token(
            token_type,
            value,
            start_line,
            start_column,
        )

    def read_string(self):
        start_line = self.line
        start_column = self.column

        self.advance()

        value = ""

        while True:
            char = self.current()

            if char is None:
                raise SyntaxError(
                    f"Unterminated string at "
                    f"line {start_line}, "
                    f"column {start_column}"
                )

            if char == '"':
                self.advance()
                break

            if char == "\\":
                self.advance()

                next_char = self.current()

                if next_char is None:
                    raise SyntaxError(
                        "Unterminated escape sequence"
                    )

                escape_map = {
                    "n": "\n",
                    "t": "\t",
                    "r": "\r",
                    '"': '"',
                    "\\": "\\",
                }

                value += escape_map.get(
                    next_char,
                    next_char,
                )

                self.advance()

            else:
                value += char
                self.advance()

        return Token(
            "STRING",
            value,
            start_line,
            start_column,
        )

    def read_number(self):
        start_line = self.line
        start_column = self.column

        value = ""

        while True:
            char = self.current()

            if char is None:
                break

            if char.isdigit():
                value += char
                self.advance()

            else:
                break

        return Token(
            "NUMBER",
            value,
            start_line,
            start_column,
        )

    def read_operator(self):
        start_line = self.line
        start_column = self.column

        char = self.current()
        next_char = self.peek()

        two_character = f"{char}{next_char}"

        operators = {
            ">=": "GREATER_EQUAL",
            "<=": "LESS_EQUAL",
            "==": "EQUAL_EQUAL",
            "!=": "NOT_EQUAL",
        }

        if two_character in operators:

            self.advance()
            self.advance()

            return Token(
                operators[two_character],
                two_character,
                start_line,
                start_column,
            )

        one_character = {
            ">": "GREATER_THAN",
            "<": "LESS_THAN",
        }

        if char in one_character:

            self.advance()

            return Token(
                one_character[char],
                char,
                start_line,
                start_column,
            )

        raise SyntaxError(
            f"Unknown operator {char!r} "
            f"at line {start_line}, "
            f"column {start_column}"
        )

    def tokenize(self):
        tokens = []

        while self.current() is not None:

            if self.current() in " \t\r\n":
                self.skip_whitespace()
                continue

            if self.current() == "#":
                self.skip_comment()
                continue

            if self.current() == '"':
                tokens.append(
                    self.read_string()
                )
                continue

            if self.current().isdigit():
                tokens.append(
                    self.read_number()
                )
                continue

            if (
                self.current().isalpha()
                or self.current() == "_"
            ):
                tokens.append(
                    self.read_identifier()
                )
                continue

            if (
                self.current() in "<>!"
                or (self.current() == "=" and self.peek() == "=")
            ):
                tokens.append(
                    self.read_operator()
                )
                continue

            symbol = self.current()

            symbol_types = {
                "[": "LBRACKET",
                "]": "RBRACKET",
                "(": "LPAREN",
                ")": "RPAREN",
                "{": "LBRACE",
                "}": "RBRACE",
                ",": "COMMA",
                ":": "COLON",
                "=": "EQUALS",
            }

            if symbol in symbol_types:

                tokens.append(
                    Token(
                        symbol_types[symbol],
                        symbol,
                        self.line,
                        self.column,
                    )
                )

                self.advance()
                continue

            raise SyntaxError(
                f"Unexpected character {symbol!r} "
                f"at line {self.line}, "
                f"column {self.column}"
            )

        tokens.append(
            Token(
                "EOF",
                "",
                self.line,
                self.column,
            )
        )

        return tokens
