"""
PHP AST Parser - Tokenizes and parses PHP source into an AST
without requiring external PHP tools.
"""
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional


class NodeType(Enum):
    # Literals
    STRING = auto()
    INT = auto()
    FLOAT = auto()
    BOOL = auto()
    NULL = auto()
    ARRAY = auto()

    # Variables
    VARIABLE = auto()
    SUPERGLOBAL = auto()

    # Expressions
    ASSIGN = auto()
    BINARY_OP = auto()
    UNARY_OP = auto()
    CONCAT = auto()
    TERNARY = auto()
    CAST = auto()
    INSTANCEOF = auto()

    # Function/Method calls
    FUNCTION_CALL = auto()
    METHOD_CALL = auto()
    STATIC_CALL = auto()
    NEW = auto()

    # Control flow
    IF = auto()
    WHILE = auto()
    FOR = auto()
    FOREACH = auto()
    SWITCH = auto()
    CASE = auto()
    BREAK = auto()
    CONTINUE = auto()
    RETURN = auto()
    THROW = auto()
    TRY = auto()
    CATCH = auto()

    # Declarations
    FUNCTION_DEF = auto()
    CLASS_DEF = auto()
    INCLUDE = auto()
    REQUIRE = auto()
    ECHO = auto()
    PRINT = auto()

    # Access
    ARRAY_ACCESS = auto()
    PROPERTY_ACCESS = auto()
    STATIC_PROPERTY = auto()

    # Misc
    BLOCK = auto()
    EXPRESSION_STMT = auto()
    COMMENT = auto()
    UNKNOWN = auto()


@dataclass
class ASTNode:
    type: NodeType
    value: Any = None
    children: list = field(default_factory=list)
    line: int = 0
    col: int = 0
    raw: str = ""

    def __repr__(self):
        return f"ASTNode({self.type.name}, value={self.value!r}, line={self.line})"


# ─── Tokenizer ────────────────────────────────────────────────────────────────

TOKEN_PATTERNS = [
    ("INLINE_HTML",    r"<\?php|\?>"),
    ("COMMENT_BLOCK",  r"/\*[\s\S]*?\*/"),
    ("COMMENT_LINE",   r"(?://|#)[^\n]*"),
    ("HEREDOC",        r'<<<["\']?(\w+)["\']?\n[\s\S]*?\n\1;'),
    ("NOWDOC",         r"<<<'(\w+)'\n[\s\S]*?\n\1;"),
    ("DSTRING",        r'"(?:[^"\\]|\\.)*"'),
    ("SSTRING",        r"'(?:[^'\\]|\\.)*'"),
    ("FLOAT",          r"\d+\.\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?"),
    ("INT_HEX",        r"0[xX][0-9a-fA-F]+"),
    ("INT_OCT",        r"0[0-7]+"),
    ("INT_BIN",        r"0[bB][01]+"),
    ("INT",            r"\d+"),
    ("VARIABLE",       r"\$[a-zA-Z_]\w*"),
    ("KEYWORD",        r"\b(?:if|else|elseif|while|for|foreach|switch|case|default|break|continue|return|echo|print|include|include_once|require|require_once|function|class|interface|trait|extends|implements|new|throw|try|catch|finally|namespace|use|as|public|private|protected|static|abstract|final|const|null|true|false|instanceof|yield|match|fn)\b"),
    ("IDENT",          r"[a-zA-Z_]\w*"),
    ("OP",             r"===|!==|==|!=|<=>|<=|>=|&&|\|\||\.=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=|\*\*=|\?\?=|\+\+|--|->|::|=>|\?\?|\.\.\.|<<|>>|\*\*|[+\-*/%&|^~!<>=?.@]"),
    ("LPAREN",         r"\("),
    ("RPAREN",         r"\)"),
    ("LBRACE",         r"\{"),
    ("RBRACE",         r"\}"),
    ("LBRACKET",       r"\["),
    ("RBRACKET",       r"\]"),
    ("SEMICOLON",      r";"),
    ("COMMA",          r","),
    ("COLON",          r":"),
    ("BACKSLASH",      r"\\"),
    ("WHITESPACE",     r"\s+"),
    ("UNKNOWN",        r"."),
]

_TOKEN_RE = re.compile(
    "|".join(f"(?P<{name}>{pattern})" for name, pattern in TOKEN_PATTERNS),
    re.MULTILINE | re.DOTALL
)

SUPERGLOBALS = {
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SESSION",
    "$_SERVER", "$_FILES", "$_ENV", "$GLOBALS"
}


@dataclass
class Token:
    type: str
    value: str
    line: int
    col: int


def tokenize(source: str) -> list[Token]:
    tokens = []
    line = 1
    line_start = 0
    in_php = False

    for m in _TOKEN_RE.finditer(source):
        kind = m.lastgroup
        val = m.group()
        col = m.start() - line_start

        if kind == "WHITESPACE":
            line += val.count("\n")
            if "\n" in val:
                line_start = m.start() + val.rfind("\n") + 1
            continue
        if kind in ("COMMENT_LINE", "COMMENT_BLOCK"):
            line += val.count("\n")
            if "\n" in val:
                line_start = m.start() + val.rfind("\n") + 1
            continue
        if kind == "INLINE_HTML":
            in_php = (val == "<?php")
            continue

        tokens.append(Token(kind, val, line, col))

        line += val.count("\n")
        if "\n" in val:
            line_start = m.start() + val.rfind("\n") + 1

    return tokens


# ─── Parser ───────────────────────────────────────────────────────────────────

class Parser:
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def peek(self, offset=0) -> Optional[Token]:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return None

    def consume(self) -> Optional[Token]:
        tok = self.peek()
        self.pos += 1
        return tok

    def expect(self, type_: str = None, value: str = None) -> Optional[Token]:
        tok = self.peek()
        if tok is None:
            return None
        if type_ and tok.type != type_:
            return None
        if value and tok.value != value:
            return None
        return self.consume()

    def match(self, *values) -> bool:
        tok = self.peek()
        return tok is not None and tok.value in values

    def parse(self) -> ASTNode:
        block = ASTNode(NodeType.BLOCK, line=0)
        while self.peek():
            stmt = self.parse_statement()
            if stmt:
                block.children.append(stmt)
        return block

    def parse_statement(self) -> Optional[ASTNode]:
        tok = self.peek()
        if tok is None:
            return None

        # Echo / print
        if tok.type == "KEYWORD" and tok.value in ("echo", "print"):
            return self.parse_echo()

        # Include / require
        if tok.type == "KEYWORD" and tok.value in (
            "include", "include_once", "require", "require_once"
        ):
            return self.parse_include()

        # Return
        if tok.type == "KEYWORD" and tok.value == "return":
            return self.parse_return()

        # Throw
        if tok.type == "KEYWORD" and tok.value == "throw":
            return self.parse_throw()

        # If
        if tok.type == "KEYWORD" and tok.value == "if":
            return self.parse_if()

        # While
        if tok.type == "KEYWORD" and tok.value == "while":
            return self.parse_while()

        # For
        if tok.type == "KEYWORD" and tok.value == "for":
            return self.parse_for()

        # Foreach
        if tok.type == "KEYWORD" and tok.value == "foreach":
            return self.parse_foreach()

        # Function def
        if tok.type == "KEYWORD" and tok.value == "function":
            return self.parse_function_def()

        # Class def
        if tok.type == "KEYWORD" and tok.value == "class":
            return self.parse_class_def()

        # Try/catch
        if tok.type == "KEYWORD" and tok.value == "try":
            return self.parse_try()

        # Break / continue
        if tok.type == "KEYWORD" and tok.value in ("break", "continue"):
            self.consume()
            self.expect("SEMICOLON")
            return ASTNode(NodeType.BREAK if tok.value == "break" else NodeType.CONTINUE, line=tok.line)

        # Semicolon (empty statement)
        if tok.type == "SEMICOLON":
            self.consume()
            return None

        # Closing brace
        if tok.type == "RBRACE":
            return None

        # Expression statement
        expr = self.parse_expression()
        if expr:
            self.expect("SEMICOLON")
            node = ASTNode(NodeType.EXPRESSION_STMT, line=expr.line)
            node.children.append(expr)
            return node

        # Skip unknown token
        self.consume()
        return None

    def parse_block(self) -> ASTNode:
        block = ASTNode(NodeType.BLOCK)
        if self.expect("LBRACE"):
            while self.peek() and self.peek().type != "RBRACE":
                stmt = self.parse_statement()
                if stmt:
                    block.children.append(stmt)
            self.expect("RBRACE")
        return block

    def parse_echo(self) -> ASTNode:
        tok = self.consume()
        node = ASTNode(NodeType.ECHO, line=tok.line)
        node.children.append(self.parse_expression())
        while self.match(","):
            self.consume()
            node.children.append(self.parse_expression())
        self.expect("SEMICOLON")
        return node

    def parse_include(self) -> ASTNode:
        tok = self.consume()
        kind = NodeType.INCLUDE if "include" in tok.value else NodeType.REQUIRE
        node = ASTNode(kind, value=tok.value, line=tok.line)
        node.children.append(self.parse_expression())
        self.expect("SEMICOLON")
        return node

    def parse_return(self) -> ASTNode:
        tok = self.consume()
        node = ASTNode(NodeType.RETURN, line=tok.line)
        if self.peek() and self.peek().type != "SEMICOLON":
            node.children.append(self.parse_expression())
        self.expect("SEMICOLON")
        return node

    def parse_throw(self) -> ASTNode:
        tok = self.consume()
        node = ASTNode(NodeType.THROW, line=tok.line)
        node.children.append(self.parse_expression())
        self.expect("SEMICOLON")
        return node

    def parse_if(self) -> ASTNode:
        tok = self.consume()
        node = ASTNode(NodeType.IF, line=tok.line)
        self.expect("LPAREN")
        node.children.append(self.parse_expression())  # condition
        self.expect("RPAREN")
        node.children.append(self.parse_block())        # then
        while self.peek() and self.peek().value == "elseif":
            self.consume()
            self.expect("LPAREN")
            node.children.append(self.parse_expression())
            self.expect("RPAREN")
            node.children.append(self.parse_block())
        if self.peek() and self.peek().value == "else":
            self.consume()
            node.children.append(self.parse_block())
        return node

    def parse_while(self) -> ASTNode:
        tok = self.consume()
        node = ASTNode(NodeType.WHILE, line=tok.line)
        self.expect("LPAREN")
        node.children.append(self.parse_expression())
        self.expect("RPAREN")
        node.children.append(self.parse_block())
        return node

    def parse_for(self) -> ASTNode:
        tok = self.consume()
        node = ASTNode(NodeType.FOR, line=tok.line)
        self.expect("LPAREN")
        # init; cond; incr
        for _ in range(3):
            if self.peek() and self.peek().type != "SEMICOLON":
                node.children.append(self.parse_expression())
            self.expect("SEMICOLON")
        self.expect("RPAREN")
        node.children.append(self.parse_block())
        return node

    def parse_foreach(self) -> ASTNode:
        tok = self.consume()
        node = ASTNode(NodeType.FOREACH, line=tok.line)
        self.expect("LPAREN")
        node.children.append(self.parse_expression())  # iterable
        if self.peek() and self.peek().value == "as":
            self.consume()
        node.children.append(self.parse_expression())  # value (or key => val)
        self.expect("RPAREN")
        node.children.append(self.parse_block())
        return node

    def parse_function_def(self) -> ASTNode:
        tok = self.consume()
        node = ASTNode(NodeType.FUNCTION_DEF, line=tok.line)
        name_tok = self.expect("IDENT")
        node.value = name_tok.value if name_tok else "anonymous"
        self.expect("LPAREN")
        params = []
        while self.peek() and self.peek().type != "RPAREN":
            if self.peek().type == "VARIABLE":
                params.append(self.consume().value)
            elif self.peek().type == "COMMA":
                self.consume()
            else:
                self.consume()
        self.expect("RPAREN")
        node.children = [ASTNode(NodeType.VARIABLE, value=p) for p in params]
        node.children.append(self.parse_block())
        return node

    def parse_class_def(self) -> ASTNode:
        tok = self.consume()
        node = ASTNode(NodeType.CLASS_DEF, line=tok.line)
        name_tok = self.expect("IDENT")
        node.value = name_tok.value if name_tok else "Anonymous"
        # Skip extends/implements
        while self.peek() and self.peek().type not in ("LBRACE",):
            self.consume()
        node.children.append(self.parse_block())
        return node

    def parse_try(self) -> ASTNode:
        tok = self.consume()
        node = ASTNode(NodeType.TRY, line=tok.line)
        node.children.append(self.parse_block())
        while self.peek() and self.peek().value == "catch":
            self.consume()
            self.expect("LPAREN")
            while self.peek() and self.peek().type != "RPAREN":
                self.consume()
            self.expect("RPAREN")
            catch = ASTNode(NodeType.CATCH)
            catch.children.append(self.parse_block())
            node.children.append(catch)
        if self.peek() and self.peek().value == "finally":
            self.consume()
            node.children.append(self.parse_block())
        return node

    # ── Expression parsing (Pratt-style) ──────────────────────────────────────

    def parse_expression(self, min_prec: int = 0) -> Optional[ASTNode]:
        left = self.parse_unary()
        if left is None:
            return None

        while True:
            tok = self.peek()
            if tok is None:
                break

            # Assignment operators
            if tok.value in ("=", "+=", "-=", "*=", "/=", ".=", "%=",
                             "&=", "|=", "^=", "<<=", ">>=", "**=", "??="):
                self.consume()
                right = self.parse_expression()
                node = ASTNode(NodeType.ASSIGN, value=tok.value, line=tok.line)
                node.children = [left, right]
                left = node
                continue

            # Binary operators
            prec = self._precedence(tok.value)
            if prec <= min_prec:
                break

            self.consume()

            if tok.value == ".":
                right = self.parse_expression(prec)
                node = ASTNode(NodeType.CONCAT, line=tok.line)
                node.children = [left, right]
                left = node
            elif tok.value == "?":
                # Ternary
                then = self.parse_expression()
                self.expect(value=":")
                else_ = self.parse_expression()
                node = ASTNode(NodeType.TERNARY, line=tok.line)
                node.children = [left, then, else_]
                left = node
            else:
                right = self.parse_expression(prec)
                node = ASTNode(NodeType.BINARY_OP, value=tok.value, line=tok.line)
                node.children = [left, right]
                left = node

        return left

    def _precedence(self, op: str) -> int:
        table = {
            "||": 1, "or": 1,
            "&&": 2, "and": 2,
            "??": 3,
            "?": 4,
            "==": 5, "!=": 5, "===": 5, "!==": 5, "<=>": 5,
            "<": 6, ">": 6, "<=": 6, ">=": 6,
            ".": 7,
            "+": 8, "-": 8,
            "*": 9, "/": 9, "%": 9,
            "**": 10,
        }
        return table.get(op, 0)

    def parse_unary(self) -> Optional[ASTNode]:
        tok = self.peek()
        if tok is None:
            return None

        if tok.value in ("!", "-", "~", "@"):
            self.consume()
            operand = self.parse_postfix()
            node = ASTNode(NodeType.UNARY_OP, value=tok.value, line=tok.line)
            node.children = [operand] if operand else []
            return node

        if tok.value in ("++", "--"):
            self.consume()
            operand = self.parse_postfix()
            node = ASTNode(NodeType.UNARY_OP, value=f"pre{tok.value}", line=tok.line)
            node.children = [operand] if operand else []
            return node

        # Cast
        if tok.type == "LPAREN":
            next_tok = self.peek(1)
            if next_tok and next_tok.value in ("int", "float", "string", "bool", "array", "object"):
                self.consume()
                cast_type = self.consume().value
                self.expect("RPAREN")
                operand = self.parse_unary()
                node = ASTNode(NodeType.CAST, value=cast_type, line=tok.line)
                node.children = [operand] if operand else []
                return node

        return self.parse_postfix()

    def parse_postfix(self) -> Optional[ASTNode]:
        node = self.parse_primary()
        if node is None:
            return None

        while True:
            tok = self.peek()
            if tok is None:
                break

            # Array access
            if tok.type == "LBRACKET":
                self.consume()
                idx = None
                if self.peek() and self.peek().type != "RBRACKET":
                    idx = self.parse_expression()
                self.expect("RBRACKET")
                access = ASTNode(NodeType.ARRAY_ACCESS, line=tok.line)
                access.children = [node, idx] if idx else [node]
                node = access

            # Method / property access
            elif tok.value == "->":
                self.consume()
                name_tok = self.consume()
                if self.peek() and self.peek().type == "LPAREN":
                    # Method call
                    args = self.parse_args()
                    call = ASTNode(NodeType.METHOD_CALL, value=name_tok.value if name_tok else "?", line=tok.line)
                    call.children = [node] + args
                    node = call
                else:
                    prop = ASTNode(NodeType.PROPERTY_ACCESS, value=name_tok.value if name_tok else "?", line=tok.line)
                    prop.children = [node]
                    node = prop

            # Static call / property
            elif tok.value == "::":
                self.consume()
                name_tok = self.consume()
                if self.peek() and self.peek().type == "LPAREN":
                    args = self.parse_args()
                    call = ASTNode(NodeType.STATIC_CALL, value=name_tok.value if name_tok else "?", line=tok.line)
                    call.children = [node] + args
                    node = call
                else:
                    prop = ASTNode(NodeType.STATIC_PROPERTY, value=name_tok.value if name_tok else "?", line=tok.line)
                    prop.children = [node]
                    node = prop

            # Postfix increment/decrement
            elif tok.value in ("++", "--"):
                self.consume()
                post = ASTNode(NodeType.UNARY_OP, value=f"post{tok.value}", line=tok.line)
                post.children = [node]
                node = post

            else:
                break

        return node

    def parse_primary(self) -> Optional[ASTNode]:
        tok = self.peek()
        if tok is None:
            return None

        # Parenthesised expression
        if tok.type == "LPAREN":
            self.consume()
            expr = self.parse_expression()
            self.expect("RPAREN")
            return expr

        # Variable
        if tok.type == "VARIABLE":
            self.consume()
            ntype = NodeType.SUPERGLOBAL if tok.value in SUPERGLOBALS else NodeType.VARIABLE
            return ASTNode(ntype, value=tok.value, line=tok.line)

        # String literals
        if tok.type in ("SSTRING", "DSTRING", "HEREDOC", "NOWDOC"):
            self.consume()
            return ASTNode(NodeType.STRING, value=tok.value, line=tok.line, raw=tok.value)

        # Numeric literals
        if tok.type == "INT":
            self.consume()
            return ASTNode(NodeType.INT, value=int(tok.value), line=tok.line)
        if tok.type in ("INT_HEX", "INT_OCT", "INT_BIN"):
            self.consume()
            return ASTNode(NodeType.INT, value=tok.value, line=tok.line)
        if tok.type == "FLOAT":
            self.consume()
            return ASTNode(NodeType.FLOAT, value=float(tok.value), line=tok.line)

        # Keywords as values
        if tok.type == "KEYWORD":
            if tok.value in ("true", "false"):
                self.consume()
                return ASTNode(NodeType.BOOL, value=(tok.value == "true"), line=tok.line)
            if tok.value == "null":
                self.consume()
                return ASTNode(NodeType.NULL, line=tok.line)
            if tok.value == "new":
                return self.parse_new()
            if tok.value == "array":
                return self.parse_array_construct()

        # Function call or identifier
        if tok.type == "IDENT":
            self.consume()
            if self.peek() and self.peek().type == "LPAREN":
                args = self.parse_args()
                node = ASTNode(NodeType.FUNCTION_CALL, value=tok.value, line=tok.line)
                node.children = args
                return node
            # Constant / class name
            return ASTNode(NodeType.VARIABLE, value=tok.value, line=tok.line)

        # Array literal [ ]
        if tok.type == "LBRACKET":
            return self.parse_array_short()

        self.consume()
        return ASTNode(NodeType.UNKNOWN, value=tok.value, line=tok.line)

    def parse_new(self) -> ASTNode:
        tok = self.consume()
        name_tok = self.consume()
        node = ASTNode(NodeType.NEW, value=name_tok.value if name_tok else "?", line=tok.line)
        if self.peek() and self.peek().type == "LPAREN":
            node.children = self.parse_args()
        return node

    def parse_array_construct(self) -> ASTNode:
        tok = self.consume()
        node = ASTNode(NodeType.ARRAY, line=tok.line)
        self.expect("LPAREN")
        while self.peek() and self.peek().type != "RPAREN":
            el = self.parse_expression()
            if el:
                node.children.append(el)
            if self.peek() and self.peek().type == "COMMA":
                self.consume()
        self.expect("RPAREN")
        return node

    def parse_array_short(self) -> ASTNode:
        tok = self.consume()
        node = ASTNode(NodeType.ARRAY, line=tok.line)
        while self.peek() and self.peek().type != "RBRACKET":
            el = self.parse_expression()
            if el:
                node.children.append(el)
            if self.peek() and self.peek().type == "COMMA":
                self.consume()
        self.expect("RBRACKET")
        return node

    def parse_args(self) -> list[ASTNode]:
        self.expect("LPAREN")
        args = []
        while self.peek() and self.peek().type != "RPAREN":
            if self.peek().type == "COMMA":
                self.consume()
                continue
            arg = self.parse_expression()
            if arg:
                args.append(arg)
        self.expect("RPAREN")
        return args


def parse_php(source: str) -> ASTNode:
    tokens = tokenize(source)
    parser = Parser(tokens)
    return parser.parse()
