"""SPL Lexer - Tokenizes Splunk Processing Language."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Iterator

from .exceptions import SPLLexerError


class TokenType(Enum):
    """Token types for SPL."""

    # Literals
    STRING = auto()  # "quoted string" or 'single quoted'
    NUMBER = auto()  # 123, 123.45
    IDENTIFIER = auto()  # field names, command names

    # Operators
    EQUALS = auto()  # =
    NOT_EQUALS = auto()  # !=
    LESS_THAN = auto()  # <
    GREATER_THAN = auto()  # >
    LESS_THAN_EQ = auto()  # <=
    GREATER_THAN_EQ = auto()  # >=

    # Arithmetic operators
    PLUS = auto()  # +
    MINUS = auto()  # -
    STAR = auto()  # *
    SLASH = auto()  # /
    PERCENT = auto()  # %

    # Boolean operators
    AND = auto()  # AND
    OR = auto()  # OR
    NOT = auto()  # NOT

    # Delimiters
    PIPE = auto()  # |
    COMMA = auto()  # ,
    LPAREN = auto()  # (
    RPAREN = auto()  # )
    LBRACKET = auto()  # [
    RBRACKET = auto()  # ]
    DOT = auto()  # .
    COLON = auto()  # :
    BACKTICK = auto()  # `

    # Keywords (commands)
    SEARCH = auto()
    STATS = auto()
    EVAL = auto()
    WHERE = auto()
    REX = auto()
    TABLE = auto()
    FIELDS = auto()
    SORT = auto()
    HEAD = auto()
    TAIL = auto()
    DEDUP = auto()
    RENAME = auto()
    REGEX = auto()
    JOIN = auto()
    LOOKUP = auto()
    APPEND = auto()
    TRANSACTION = auto()
    EVENTSTATS = auto()
    STREAMSTATS = auto()
    TSTATS = auto()
    INPUTLOOKUP = auto()
    OUTPUTLOOKUP = auto()
    TIMECHART = auto()
    CHART = auto()
    MAP = auto()
    FOREACH = auto()
    CONVERT = auto()
    FILLNULL = auto()
    BIN = auto()
    BUCKET = auto()
    COLLECT = auto()
    SENDEMAIL = auto()

    # Stats keywords
    BY = auto()  # by
    AS = auto()  # as

    # Special
    WILDCARD = auto()  # * when used as wildcard
    EOF = auto()
    NEWLINE = auto()

    # Subsearch
    SUBSEARCH_START = auto()  # [
    SUBSEARCH_END = auto()  # ]

    # Macro
    MACRO = auto()  # `macro_name`


@dataclass
class Token:
    """A token from SPL input."""

    type: TokenType
    value: str
    position: int
    line: int
    column: int

    def __repr__(self) -> str:
        return f"Token({self.type.name}, {self.value!r}, pos={self.position})"


# Keywords mapping
KEYWORDS: dict[str, TokenType] = {
    "search": TokenType.SEARCH,
    "stats": TokenType.STATS,
    "eval": TokenType.EVAL,
    "where": TokenType.WHERE,
    "rex": TokenType.REX,
    "table": TokenType.TABLE,
    "fields": TokenType.FIELDS,
    "sort": TokenType.SORT,
    "head": TokenType.HEAD,
    "tail": TokenType.TAIL,
    "dedup": TokenType.DEDUP,
    "rename": TokenType.RENAME,
    "regex": TokenType.REGEX,
    "join": TokenType.JOIN,
    "lookup": TokenType.LOOKUP,
    "append": TokenType.APPEND,
    "transaction": TokenType.TRANSACTION,
    "eventstats": TokenType.EVENTSTATS,
    "streamstats": TokenType.STREAMSTATS,
    "tstats": TokenType.TSTATS,
    "inputlookup": TokenType.INPUTLOOKUP,
    "outputlookup": TokenType.OUTPUTLOOKUP,
    "timechart": TokenType.TIMECHART,
    "chart": TokenType.CHART,
    "map": TokenType.MAP,
    "foreach": TokenType.FOREACH,
    "convert": TokenType.CONVERT,
    "fillnull": TokenType.FILLNULL,
    "bin": TokenType.BIN,
    "bucket": TokenType.BUCKET,
    "collect": TokenType.COLLECT,
    "sendemail": TokenType.SENDEMAIL,
    "by": TokenType.BY,
    "as": TokenType.AS,
    "and": TokenType.AND,
    "or": TokenType.OR,
    "not": TokenType.NOT,
}


class SPLLexer:
    """Tokenizer for Splunk Processing Language."""

    def __init__(self, source: str) -> None:
        """
        Initialize the lexer.

        Args:
            source: SPL source code to tokenize
        """
        self.source = source
        self.position = 0
        self.line = 1
        self.column = 1
        self.tokens: list[Token] = []

    def tokenize(self) -> list[Token]:
        """
        Tokenize the SPL source.

        Returns:
            List of tokens

        Raises:
            SPLLexerError: If an invalid token is encountered
        """
        self.tokens = []
        self.position = 0
        self.line = 1
        self.column = 1

        while self.position < len(self.source):
            token = self._next_token()
            if token:
                self.tokens.append(token)

        # Add EOF token
        self.tokens.append(
            Token(TokenType.EOF, "", self.position, self.line, self.column)
        )

        return self.tokens

    def _next_token(self) -> Token | None:
        """Get the next token from the source."""
        self._skip_whitespace()

        if self.position >= len(self.source):
            return None

        char = self.source[self.position]
        start_pos = self.position
        start_line = self.line
        start_col = self.column

        # Check for comments (SPL uses ``` for multiline comments)
        if self._match("```"):
            self._skip_multiline_comment()
            return None

        # Single character tokens
        single_char_tokens = {
            "|": TokenType.PIPE,
            ",": TokenType.COMMA,
            "(": TokenType.LPAREN,
            ")": TokenType.RPAREN,
            ".": TokenType.DOT,
            ":": TokenType.COLON,
            "+": TokenType.PLUS,
            "-": TokenType.MINUS,
            "/": TokenType.SLASH,
            "%": TokenType.PERCENT,
        }

        # Handle brackets - could be subsearch
        if char == "[":
            self._advance()
            return Token(TokenType.LBRACKET, "[", start_pos, start_line, start_col)

        if char == "]":
            self._advance()
            return Token(TokenType.RBRACKET, "]", start_pos, start_line, start_col)

        # Handle backticks (macros)
        if char == "`":
            return self._read_macro()

        # Handle operators
        if char == "=" and self._peek(1) != "=":
            self._advance()
            return Token(TokenType.EQUALS, "=", start_pos, start_line, start_col)

        if char == "!" and self._peek(1) == "=":
            self._advance()
            self._advance()
            return Token(TokenType.NOT_EQUALS, "!=", start_pos, start_line, start_col)

        if char == "<":
            self._advance()
            if self._current() == "=":
                self._advance()
                return Token(
                    TokenType.LESS_THAN_EQ, "<=", start_pos, start_line, start_col
                )
            return Token(TokenType.LESS_THAN, "<", start_pos, start_line, start_col)

        if char == ">":
            self._advance()
            if self._current() == "=":
                self._advance()
                return Token(
                    TokenType.GREATER_THAN_EQ, ">=", start_pos, start_line, start_col
                )
            return Token(TokenType.GREATER_THAN, ">", start_pos, start_line, start_col)

        if char == "=":
            self._advance()
            if self._current() == "=":
                self._advance()
                return Token(TokenType.EQUALS, "==", start_pos, start_line, start_col)
            return Token(TokenType.EQUALS, "=", start_pos, start_line, start_col)

        # Handle * - could be wildcard or multiplication
        if char == "*":
            self._advance()
            return Token(TokenType.STAR, "*", start_pos, start_line, start_col)

        if char in single_char_tokens:
            self._advance()
            return Token(
                single_char_tokens[char], char, start_pos, start_line, start_col
            )

        # Quoted strings
        if char in ('"', "'"):
            return self._read_string(char)

        # Numbers
        if char.isdigit() or (char == "-" and self._peek(1).isdigit()):
            return self._read_number()

        # Identifiers and keywords
        if char.isalpha() or char == "_":
            return self._read_identifier()

        # Handle newlines
        if char == "\n":
            self._advance()
            return Token(TokenType.NEWLINE, "\n", start_pos, start_line, start_col)

        # Unknown character
        raise SPLLexerError(
            f"Unexpected character: {char!r}",
            position=self.position,
            line=self.line,
            column=self.column,
        )

    def _read_string(self, quote_char: str) -> Token:
        """Read a quoted string."""
        start_pos = self.position
        start_line = self.line
        start_col = self.column

        self._advance()  # Skip opening quote
        value = ""

        while self.position < len(self.source):
            char = self._current()

            if char == "\\":
                # Escape sequence
                self._advance()
                if self.position < len(self.source):
                    escaped = self._current()
                    escape_map = {
                        "n": "\n",
                        "t": "\t",
                        "r": "\r",
                        "\\": "\\",
                        '"': '"',
                        "'": "'",
                    }
                    value += escape_map.get(escaped, escaped)
                    self._advance()
            elif char == quote_char:
                self._advance()  # Skip closing quote
                return Token(TokenType.STRING, value, start_pos, start_line, start_col)
            else:
                value += char
                self._advance()

        raise SPLLexerError(
            f"Unterminated string starting at line {start_line}, column {start_col}",
            position=start_pos,
            line=start_line,
            column=start_col,
        )

    def _read_number(self) -> Token:
        """Read a number (integer or float)."""
        start_pos = self.position
        start_line = self.line
        start_col = self.column

        value = ""

        # Handle negative sign
        if self._current() == "-":
            value += "-"
            self._advance()

        # Read integer part
        while self.position < len(self.source) and self._current().isdigit():
            value += self._current()
            self._advance()

        # Check for decimal point
        if self.position < len(self.source) and self._current() == ".":
            next_char = self._peek(1)
            if next_char.isdigit():
                value += "."
                self._advance()

                # Read decimal part
                while self.position < len(self.source) and self._current().isdigit():
                    value += self._current()
                    self._advance()

        # Check for scientific notation
        if self.position < len(self.source) and self._current().lower() == "e":
            value += self._current()
            self._advance()

            if self.position < len(self.source) and self._current() in "+-":
                value += self._current()
                self._advance()

            while self.position < len(self.source) and self._current().isdigit():
                value += self._current()
                self._advance()

        return Token(TokenType.NUMBER, value, start_pos, start_line, start_col)

    def _read_identifier(self) -> Token:
        """Read an identifier or keyword."""
        start_pos = self.position
        start_line = self.line
        start_col = self.column

        value = ""

        # Identifiers can contain: letters, digits, underscores, dots, colons, and hyphens
        while self.position < len(self.source):
            char = self._current()
            if char.isalnum() or char in "_.-:":
                value += char
                self._advance()
            else:
                break

        # Check if value contains wildcard
        if "*" in value or "?" in value:
            return Token(TokenType.WILDCARD, value, start_pos, start_line, start_col)

        # Check if it's a keyword
        lower_value = value.lower()
        if lower_value in KEYWORDS:
            return Token(KEYWORDS[lower_value], value, start_pos, start_line, start_col)

        return Token(TokenType.IDENTIFIER, value, start_pos, start_line, start_col)

    def _read_macro(self) -> Token:
        """Read a macro reference (backtick-enclosed)."""
        start_pos = self.position
        start_line = self.line
        start_col = self.column

        self._advance()  # Skip opening backtick
        value = ""

        while self.position < len(self.source):
            char = self._current()
            if char == "`":
                self._advance()  # Skip closing backtick
                return Token(TokenType.MACRO, value, start_pos, start_line, start_col)
            elif char == "\n":
                raise SPLLexerError(
                    "Unexpected newline in macro reference",
                    position=self.position,
                    line=self.line,
                    column=self.column,
                )
            else:
                value += char
                self._advance()

        raise SPLLexerError(
            f"Unterminated macro starting at line {start_line}, column {start_col}",
            position=start_pos,
            line=start_line,
            column=start_col,
        )

    def _skip_whitespace(self) -> None:
        """Skip whitespace characters (except newlines which are tokens)."""
        while self.position < len(self.source):
            char = self._current()
            if char in " \t\r":
                self._advance()
            elif char == "\\" and self._peek(1) == "\n":
                # Line continuation
                self._advance()
                self._advance()
            else:
                break

    def _skip_multiline_comment(self) -> None:
        """Skip a multiline comment (``` ... ```)."""
        while self.position < len(self.source):
            if self._match("```"):
                break
            self._advance()

    def _current(self) -> str:
        """Get the current character."""
        if self.position < len(self.source):
            return self.source[self.position]
        return ""

    def _peek(self, offset: int = 1) -> str:
        """Peek at a character ahead."""
        pos = self.position + offset
        if pos < len(self.source):
            return self.source[pos]
        return ""

    def _advance(self) -> None:
        """Advance to the next character."""
        if self.position < len(self.source):
            if self.source[self.position] == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1
            self.position += 1

    def _match(self, text: str) -> bool:
        """Check if the current position matches the text and advance if so."""
        if self.source[self.position : self.position + len(text)] == text:
            for _ in range(len(text)):
                self._advance()
            return True
        return False

    def __iter__(self) -> Iterator[Token]:
        """Allow iteration over tokens."""
        if not self.tokens:
            self.tokenize()
        return iter(self.tokens)
