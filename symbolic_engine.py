"""
Symbolic Execution Engine for PHP
- SSA Variable Store
- Path State Management
- Constraint Solver (lightweight)
- Taint Propagation
"""
from __future__ import annotations
import copy
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional, Dict, List, Set, Tuple

from php_ast import ASTNode, NodeType


# ─── Taint Labels ─────────────────────────────────────────────────────────────

class Taint(Enum):
    CLEAN     = auto()  # Sanitised / literal
    USER_GET  = auto()  # $_GET
    USER_POST = auto()  # $_POST
    USER_REQ  = auto()  # $_REQUEST
    USER_COOK = auto()  # $_COOKIE
    USER_SRV  = auto()  # $_SERVER
    USER_FILE = auto()  # $_FILES
    ENV       = auto()  # $_ENV / $GLOBALS
    DB_READ   = auto()  # Value read from DB (secondary)
    UNKNOWN   = auto()  # Indeterminate

TAINTED = {
    Taint.USER_GET, Taint.USER_POST, Taint.USER_REQ,
    Taint.USER_COOK, Taint.USER_SRV, Taint.USER_FILE,
    Taint.ENV, Taint.UNKNOWN
}

SUPERGLOBAL_TAINT: Dict[str, Taint] = {
    "$_GET":     Taint.USER_GET,
    "$_POST":    Taint.USER_POST,
    "$_REQUEST": Taint.USER_REQ,
    "$_COOKIE":  Taint.USER_COOK,
    "$_SERVER":  Taint.USER_SRV,
    "$_FILES":   Taint.USER_FILE,
    "$_ENV":     Taint.ENV,
    "$GLOBALS":  Taint.ENV,
}

# ─── Symbolic Value ────────────────────────────────────────────────────────────

@dataclass
class SymVal:
    """A symbolic value carrying both a concrete approximation and taint set."""
    concrete: Any = None          # Best-effort concrete value
    taints: Set[Taint] = field(default_factory=lambda: {Taint.CLEAN})
    expr: str = ""                # Human-readable symbolic expression
    sanitised_by: Set[str] = field(default_factory=set)

    def is_tainted(self) -> bool:
        return bool(self.taints & TAINTED)

    def merge(self, other: "SymVal") -> "SymVal":
        """Meet of two SymVals (join point in CFG)."""
        new_taints = self.taints | other.taints
        new_san = self.sanitised_by & other.sanitised_by
        concrete = self.concrete if self.concrete == other.concrete else None
        return SymVal(concrete=concrete, taints=new_taints,
                      sanitised_by=new_san, expr=f"φ({self.expr},{other.expr})")

    def __repr__(self):
        ts = ",".join(t.name for t in self.taints)
        return f"SymVal(concrete={self.concrete!r}, taints={{{ts}}}, san={self.sanitised_by})"

    @staticmethod
    def literal(v: Any) -> "SymVal":
        return SymVal(concrete=v, taints={Taint.CLEAN}, expr=repr(v))

    @staticmethod
    def tainted(source: Taint, expr: str = "") -> "SymVal":
        return SymVal(concrete=None, taints={source}, expr=expr)


# ─── SSA Variable Store ────────────────────────────────────────────────────────

class VarStore:
    """Static Single Assignment store — each write creates a new version."""

    def __init__(self):
        self._store: Dict[str, List[SymVal]] = {}
        self._version: Dict[str, int] = {}

    def read(self, name: str) -> SymVal:
        if name in SUPERGLOBAL_TAINT:
            return SymVal.tainted(SUPERGLOBAL_TAINT[name], expr=f"{name}[*]")
        versions = self._store.get(name)
        if not versions:
            return SymVal(concrete=None, taints={Taint.UNKNOWN}, expr=f"undef({name})")
        return versions[-1]

    def write(self, name: str, val: SymVal):
        if name not in self._store:
            self._store[name] = []
        self._store[name].append(val)
        self._version[name] = self._version.get(name, 0) + 1

    def snapshot(self) -> Dict[str, List[SymVal]]:
        return {k: list(v) for k, v in self._store.items()}

    def restore(self, snap: Dict[str, List[SymVal]]):
        self._store = {k: list(v) for k, v in snap.items()}

    def clone(self) -> "VarStore":
        vs = VarStore()
        vs._store = self.snapshot()
        vs._version = dict(self._version)
        return vs

    def merge_from(self, other: "VarStore"):
        """Merge another store (join point — take latest from both, merge taint)."""
        for name, vals in other._store.items():
            if vals:
                our_val = self.read(name)
                merged = our_val.merge(vals[-1])
                self.write(name, merged)


# ─── Constraint ────────────────────────────────────────────────────────────────

@dataclass
class Constraint:
    expr: str
    truth: bool = True

    def negate(self) -> "Constraint":
        return Constraint(self.expr, not self.truth)

    def __repr__(self):
        prefix = "" if self.truth else "NOT "
        return f"{prefix}({self.expr})"


# ─── Path State ────────────────────────────────────────────────────────────────

@dataclass
class PathState:
    """One execution path through the program."""
    vars: VarStore = field(default_factory=VarStore)
    constraints: List[Constraint] = field(default_factory=list)
    call_stack: List[str] = field(default_factory=list)
    depth: int = 0

    def clone(self) -> "PathState":
        ps = PathState(
            vars=self.vars.clone(),
            constraints=list(self.constraints),
            call_stack=list(self.call_stack),
            depth=self.depth,
        )
        return ps


# ─── Sanitiser & Sink Registries ──────────────────────────────────────────────

# Functions that sanitise input and what they protect against
SANITISERS: Dict[str, Set[str]] = {
    # XSS
    "htmlspecialchars":      {"xss"},
    "htmlentities":          {"xss"},
    "strip_tags":            {"xss"},
    "nl2br":                 set(),
    # SQLi
    "mysqli_real_escape_string":  {"sqli"},
    "mysql_real_escape_string":   {"sqli"},
    "pg_escape_string":           {"sqli"},
    "addslashes":                 {"sqli"},
    # Path traversal
    "basename":              {"path_traversal"},
    "realpath":              {"path_traversal"},
    # Command injection
    "escapeshellarg":        {"cmdi"},
    "escapeshellcmd":        {"cmdi"},
    # General
    "intval":                {"sqli", "xss"},
    "floatval":              {"sqli", "xss"},
    "abs":                   {"sqli", "xss"},
    "ctype_digit":           {"sqli", "xss"},
    "filter_var":            {"sqli", "xss", "ssrf"},
    "filter_input":          {"sqli", "xss", "ssrf"},
    "preg_quote":            {"sqli"},
    "prepared_statement":    {"sqli"},  # PDO/mysqli prepared stmts
}

# Dangerous sinks mapped to vuln type
SINKS: Dict[str, str] = {
    # XSS
    "echo":                   "xss",
    "print":                  "xss",
    "printf":                 "xss",
    "vprintf":                "xss",
    "sprintf":                "xss",  # only when echoed
    # SQLi
    "mysql_query":            "sqli",
    "mysqli_query":           "sqli",
    "pg_query":               "sqli",
    "mssql_query":            "sqli",
    "sqlite_query":           "sqli",
    # Command injection
    "exec":                   "cmdi",
    "shell_exec":             "cmdi",
    "system":                 "cmdi",
    "passthru":               "cmdi",
    "popen":                  "cmdi",
    "proc_open":              "cmdi",
    # LFI / path traversal
    "include":                "lfi",
    "require":                "lfi",
    "include_once":           "lfi",
    "require_once":           "lfi",
    "file_get_contents":      "path_traversal",
    "file_put_contents":      "path_traversal",
    "fopen":                  "path_traversal",
    "readfile":               "path_traversal",
    "file":                   "path_traversal",
    # SSRF
    "curl_setopt":            "ssrf",
    "file_get_contents_url":  "ssrf",
    # XXE / unsafe deserial
    "unserialize":            "insecure_deserial",
    "simplexml_load_string":  "xxe",
    "simplexml_load_file":    "xxe",
    # Open redirect
    "header":                 "open_redirect",
    # Code exec
    "eval":                   "code_exec",
    "preg_replace_e":         "code_exec",
    "assert":                 "code_exec",
    "call_user_func":         "code_exec",
    "call_user_func_array":   "code_exec",
    "create_function":        "code_exec",
}


# ─── Lightweight Constraint Solver ────────────────────────────────────────────

class ConstraintSolver:
    """
    Determines whether a set of path constraints is satisfiable.
    Uses simple symbolic reasoning — not a full SMT solver.
    """

    def is_satisfiable(self, constraints: List[Constraint]) -> bool:
        """Attempt to detect obvious contradictions."""
        # Build a simple fact set
        facts: Dict[str, bool] = {}
        for c in constraints:
            key = c.expr
            if key in facts:
                if facts[key] != c.truth:
                    return False  # Contradiction
            else:
                facts[key] = c.truth
        return True  # Assume satisfiable if no contradiction found

    def simplify(self, constraints: List[Constraint]) -> List[Constraint]:
        seen = {}
        result = []
        for c in constraints:
            if c.expr not in seen:
                seen[c.expr] = c.truth
                result.append(c)
        return result


# ─── Symbolic Executor ────────────────────────────────────────────────────────

MAX_PATH_DEPTH   = 30
MAX_LOOP_ITER    = 3
MAX_PATHS        = 200


@dataclass
class Finding:
    vuln_type: str
    sink: str
    taint_sources: Set[Taint]
    constraints: List[Constraint]
    line: int
    sanitised_by: Set[str]
    confidence: str  # HIGH / MEDIUM / LOW
    description: str = ""

    def __repr__(self):
        return (f"[{self.confidence}] {self.vuln_type} via {self.sink} "
                f"at line {self.line} | taints={self.taint_sources} | san={self.sanitised_by}")


class SymbolicExecutor:

    def __init__(self, functions: Dict[str, ASTNode] = None):
        self.functions = functions or {}  # name → FUNCTION_DEF node
        self.findings: List[Finding] = []
        self.solver = ConstraintSolver()
        self._visited_funcs: Set[str] = set()
        self.includes: List[Tuple[int, SymVal]] = []  # (line, path_val)

    def execute(self, ast: ASTNode) -> List[Finding]:
        """Entry point — execute the top-level block."""
        initial_state = PathState()
        self._collect_functions(ast)
        self._exec_block(ast, initial_state)
        return self.findings

    # ── Function collection ───────────────────────────────────────────────────

    def _collect_functions(self, node: ASTNode):
        if node.type == NodeType.FUNCTION_DEF:
            self.functions[node.value] = node
        for child in node.children:
            self._collect_functions(child)

    # ── Block / Statement execution ───────────────────────────────────────────

    def _exec_block(self, node: ASTNode, state: PathState) -> List[PathState]:
        """Execute a block node, returning list of successor states."""
        if state.depth > MAX_PATH_DEPTH:
            return [state]

        states = [state]

        stmts = node.children if node.type == NodeType.BLOCK else [node]

        for stmt in stmts:
            if not states:
                break
            next_states = []
            for s in states:
                ns = self._exec_stmt(stmt, s)
                next_states.extend(ns)
            states = next_states[:MAX_PATHS]

        return states

    def _exec_stmt(self, node: ASTNode, state: PathState) -> List[PathState]:
        if node is None:
            return [state]

        t = node.type

        if t == NodeType.EXPRESSION_STMT:
            return self._exec_stmt(node.children[0] if node.children else None, state) \
                if node.children else [state]

        if t == NodeType.ASSIGN:
            return self._exec_assign(node, state)

        if t in (NodeType.ECHO, NodeType.PRINT):
            return self._exec_echo(node, state)

        if t in (NodeType.INCLUDE, NodeType.REQUIRE):
            return self._exec_include(node, state)

        if t == NodeType.FUNCTION_CALL:
            val, new_states = self._exec_call(node, state)
            return new_states

        if t == NodeType.METHOD_CALL:
            val, new_states = self._exec_call(node, state)
            return new_states

        if t == NodeType.IF:
            return self._exec_if(node, state)

        if t in (NodeType.WHILE, NodeType.FOR, NodeType.FOREACH):
            return self._exec_loop(node, state)

        if t == NodeType.FUNCTION_DEF:
            self.functions[node.value] = node
            return [state]

        if t == NodeType.BLOCK:
            return self._exec_block(node, state)

        if t == NodeType.RETURN:
            val = self._eval_expr(node.children[0], state) if node.children else SymVal.literal(None)
            state.vars.write("__return__", val)
            return [state]

        return [state]

    # ── Assignment ────────────────────────────────────────────────────────────

    def _exec_assign(self, node: ASTNode, state: PathState) -> List[PathState]:
        if len(node.children) < 2:
            return [state]
        target, value_node = node.children[0], node.children[1]
        val = self._eval_expr(value_node, state)

        if target.type in (NodeType.VARIABLE, NodeType.SUPERGLOBAL):
            state.vars.write(target.value, val)
        elif target.type == NodeType.ARRAY_ACCESS:
            # Simplified: taint the whole array variable
            arr = target.children[0] if target.children else None
            if arr and arr.type in (NodeType.VARIABLE, NodeType.SUPERGLOBAL):
                state.vars.write(arr.value, val)
        return [state]

    # ── Echo / print (XSS sink) ───────────────────────────────────────────────

    def _exec_echo(self, node: ASTNode, state: PathState) -> List[PathState]:
        for child in node.children:
            val = self._eval_expr(child, state)
            if val.is_tainted() and "xss" not in val.sanitised_by:
                self._report(
                    vuln_type="xss",
                    sink="echo/print",
                    val=val,
                    constraints=state.constraints,
                    line=node.line,
                )
        return [state]

    # ── Include / require (LFI sink) ─────────────────────────────────────────

    def _exec_include(self, node: ASTNode, state: PathState) -> List[PathState]:
        if not node.children:
            return [state]
        val = self._eval_expr(node.children[0], state)
        self.includes.append((node.line, val))
        if val.is_tainted() and "path_traversal" not in val.sanitised_by:
            self._report("lfi", "include/require", val, state.constraints, node.line)
        return [state]

    # ── If / branching ────────────────────────────────────────────────────────

    def _exec_if(self, node: ASTNode, state: PathState) -> List[PathState]:
        if not node.children:
            return [state]

        cond_node = node.children[0]
        cond_str = self._node_to_str(cond_node)

        # True branch
        true_state = state.clone()
        true_state.depth += 1
        true_state.constraints.append(Constraint(cond_str, True))
        true_block = node.children[1] if len(node.children) > 1 else None

        # False / else branch
        false_state = state.clone()
        false_state.depth += 1
        false_state.constraints.append(Constraint(cond_str, False))
        false_block = node.children[2] if len(node.children) > 2 else None

        results = []
        if true_block and self.solver.is_satisfiable(true_state.constraints):
            results.extend(self._exec_block(true_block, true_state))
        if false_block and self.solver.is_satisfiable(false_state.constraints):
            results.extend(self._exec_block(false_block, false_state))
        elif self.solver.is_satisfiable(false_state.constraints):
            results.append(false_state)

        return results or [state]

    # ── Loop (bounded) ────────────────────────────────────────────────────────

    def _exec_loop(self, node: ASTNode, state: PathState) -> List[PathState]:
        body = node.children[-1] if node.children else None
        if body is None:
            return [state]

        states = [state]
        for _ in range(MAX_LOOP_ITER):
            next_states = []
            for s in states:
                ns = self._exec_block(body, s.clone())
                next_states.extend(ns)
            # Merge loop states into single state
            if next_states:
                merged = next_states[0]
                for ns in next_states[1:]:
                    merged.vars.merge_from(ns.vars)
                states = [merged]
            else:
                break

        return states

    # ── Function calls ────────────────────────────────────────────────────────

    def _exec_call(self, node: ASTNode, state: PathState) -> Tuple[SymVal, List[PathState]]:
        func_name = node.value or ""
        # Collect arguments
        arg_nodes = node.children if node.type == NodeType.FUNCTION_CALL else node.children[1:]
        args = [self._eval_expr(a, state) for a in arg_nodes]

        # Check if this is a sink
        if func_name in SINKS:
            vuln = SINKS[func_name]
            for arg in args:
                if arg.is_tainted() and vuln not in arg.sanitised_by:
                    self._report(vuln, func_name, arg, state.constraints, node.line)

        # Apply sanitisation
        if func_name in SANITISERS:
            protected = SANITISERS[func_name]
            if args:
                new_val = copy.deepcopy(args[0])
                new_val.sanitised_by |= protected
                new_val.taints -= TAINTED  # Mark as clean after sanitisation
                return new_val, [state]

        # PDO / MySQLi prepared statement detection
        if func_name in ("prepare", "bindParam", "bindValue", "execute"):
            if args:
                new_val = copy.deepcopy(args[0])
                new_val.sanitised_by.add("sqli")
                return new_val, [state]

        # header() → check for open redirect
        if func_name == "header" and args:
            arg0 = args[0]
            if arg0.is_tainted() and "open_redirect" not in arg0.sanitised_by:
                concrete = arg0.concrete or ""
                if isinstance(concrete, str) and "Location:" in concrete:
                    self._report("open_redirect", "header()", arg0, state.constraints, node.line)
                elif not isinstance(concrete, str):
                    self._report("open_redirect", "header()", arg0, state.constraints, node.line)

        # eval() → code exec
        if func_name == "eval" and args and args[0].is_tainted():
            self._report("code_exec", "eval()", args[0], state.constraints, node.line)

        # Inline user-defined function call
        if func_name in self.functions and func_name not in self._visited_funcs:
            self._visited_funcs.add(func_name)
            fn_node = self.functions[func_name]
            fn_state = state.clone()
            fn_state.depth += 1
            fn_state.call_stack.append(func_name)
            # Bind params
            param_nodes = [c for c in fn_node.children if c.type == NodeType.VARIABLE]
            for i, param in enumerate(param_nodes):
                fn_state.vars.write(param.value, args[i] if i < len(args) else SymVal.literal(None))
            body = fn_node.children[-1] if fn_node.children else None
            if body:
                end_states = self._exec_block(body, fn_state)
                # Get return value
                ret_vals = [s.vars.read("__return__") for s in end_states]
                merged_ret = ret_vals[0] if ret_vals else SymVal.literal(None)
                for rv in ret_vals[1:]:
                    merged_ret = merged_ret.merge(rv)
                self._visited_funcs.discard(func_name)
                return merged_ret, [state]
            self._visited_funcs.discard(func_name)

        # Unknown function — propagate taint conservatively
        if args:
            merged = args[0]
            for a in args[1:]:
                merged = merged.merge(a)
            return merged, [state]

        return SymVal.literal(None), [state]

    # ── Expression evaluation ─────────────────────────────────────────────────

    def _eval_expr(self, node: ASTNode, state: PathState) -> SymVal:
        if node is None:
            return SymVal.literal(None)

        t = node.type

        if t == NodeType.STRING:
            raw = node.value or ""
            # Check for taint markers in interpolated strings
            taints: Set[Taint] = {Taint.CLEAN}
            for sg, taint in SUPERGLOBAL_TAINT.items():
                if sg in raw:
                    taints.add(taint)
            if taints != {Taint.CLEAN}:
                return SymVal(concrete=raw, taints=taints, expr=raw)
            return SymVal.literal(raw)

        if t in (NodeType.INT, NodeType.FLOAT, NodeType.BOOL, NodeType.NULL):
            return SymVal.literal(node.value)

        if t == NodeType.SUPERGLOBAL:
            return SymVal.tainted(SUPERGLOBAL_TAINT.get(node.value, Taint.UNKNOWN),
                                  expr=f"{node.value}[?]")

        if t == NodeType.VARIABLE:
            return state.vars.read(node.value)

        if t == NodeType.ARRAY_ACCESS:
            if node.children:
                arr_val = self._eval_expr(node.children[0], state)
                # Array element inherits array taint
                return arr_val
            return SymVal.literal(None)

        if t == NodeType.ASSIGN:
            if len(node.children) >= 2:
                val = self._eval_expr(node.children[1], state)
                target = node.children[0]
                if target.type in (NodeType.VARIABLE, NodeType.SUPERGLOBAL):
                    state.vars.write(target.value, val)
                return val
            return SymVal.literal(None)

        if t == NodeType.CONCAT:
            vals = [self._eval_expr(c, state) for c in node.children]
            merged = vals[0] if vals else SymVal.literal("")
            for v in vals[1:]:
                merged = merged.merge(v)
            # Attempt concrete concat
            if all(isinstance(v.concrete, str) for v in vals):
                merged.concrete = "".join(v.concrete for v in vals)
            return merged

        if t == NodeType.BINARY_OP:
            if len(node.children) >= 2:
                left = self._eval_expr(node.children[0], state)
                right = self._eval_expr(node.children[1], state)
                return left.merge(right)
            return SymVal.literal(None)

        if t == NodeType.UNARY_OP:
            if node.children:
                return self._eval_expr(node.children[0], state)
            return SymVal.literal(None)

        if t == NodeType.CAST:
            val = self._eval_expr(node.children[0], state) if node.children else SymVal.literal(None)
            # (int), (float) casts are sanitising for sqli/xss
            if node.value in ("int", "float"):
                new_val = copy.deepcopy(val)
                new_val.sanitised_by |= {"sqli", "xss"}
                new_val.taints -= TAINTED
                return new_val
            return val

        if t == NodeType.TERNARY:
            if len(node.children) >= 3:
                then_val = self._eval_expr(node.children[1], state)
                else_val = self._eval_expr(node.children[2], state)
                return then_val.merge(else_val)
            return SymVal.literal(None)

        if t in (NodeType.FUNCTION_CALL, NodeType.METHOD_CALL, NodeType.STATIC_CALL):
            val, _ = self._exec_call(node, state)
            return val

        if t == NodeType.NEW:
            return SymVal.literal(f"new {node.value}()")

        if t == NodeType.ARRAY:
            vals = [self._eval_expr(c, state) for c in node.children]
            merged = SymVal.literal([])
            for v in vals:
                merged = merged.merge(v)
            return merged

        if t == NodeType.PROPERTY_ACCESS:
            obj = self._eval_expr(node.children[0], state) if node.children else SymVal.literal(None)
            return obj  # Property access propagates object taint

        return SymVal(concrete=None, taints={Taint.UNKNOWN}, expr="?")

    # ── Reporting ─────────────────────────────────────────────────────────────

    def _report(self, vuln_type: str, sink: str, val: SymVal,
                constraints: List[Constraint], line: int):
        san = val.sanitised_by
        taints = val.taints & TAINTED

        # Confidence based on sanitisation and constraints
        if not san:
            confidence = "HIGH"
        elif vuln_type not in san:
            confidence = "MEDIUM"
        else:
            return  # Properly sanitised

        # Avoid duplicates
        for f in self.findings:
            if f.line == line and f.sink == sink and f.vuln_type == vuln_type:
                return

        self.findings.append(Finding(
            vuln_type=vuln_type,
            sink=sink,
            taint_sources=taints,
            constraints=self.solver.simplify(list(constraints)),
            line=line,
            sanitised_by=san,
            confidence=confidence,
            description=self._describe(vuln_type, sink, val, san),
        ))

    def _describe(self, vuln: str, sink: str, val: SymVal, san: Set[str]) -> str:
        sources = ", ".join(t.name for t in val.taints & TAINTED)
        if vuln == "xss":
            return (f"User-controlled input ({sources}) reaches {sink} without "
                    f"HTML encoding. Attacker can inject arbitrary JS.")
        if vuln == "sqli":
            return (f"User-controlled input ({sources}) concatenated into SQL query "
                    f"via {sink}. Use prepared statements.")
        if vuln == "lfi":
            return (f"User-controlled input ({sources}) used in {sink}. "
                    f"Attacker can include arbitrary files.")
        if vuln == "cmdi":
            return (f"User-controlled input ({sources}) passed to shell via {sink}. "
                    f"Use escapeshellarg().")
        if vuln == "open_redirect":
            return (f"User-controlled input ({sources}) in header() Location redirect. "
                    f"Validate URLs against allowlist.")
        if vuln == "code_exec":
            return f"User-controlled input ({sources}) passed to {sink} for execution."
        if vuln == "ssrf":
            return f"User-controlled URL ({sources}) passed to {sink}. Validate against allowlist."
        if vuln == "insecure_deserial":
            return f"User-controlled data ({sources}) passed to unserialize(). Use JSON instead."
        if vuln == "xxe":
            return f"Potentially unsafe XML parsing via {sink}. Disable external entities."
        if vuln == "path_traversal":
            return (f"User-controlled path ({sources}) in {sink}. "
                    f"Use basename() and realpath() to validate.")
        return f"Tainted data ({sources}) reaches dangerous sink {sink}."

    def _node_to_str(self, node: ASTNode) -> str:
        """Best-effort string representation of a node for constraint labels."""
        if node is None:
            return "?"
        if node.type in (NodeType.VARIABLE, NodeType.SUPERGLOBAL):
            return node.value
        if node.type in (NodeType.STRING, NodeType.INT, NodeType.FLOAT, NodeType.BOOL):
            return repr(node.value)
        if node.type == NodeType.BINARY_OP and node.children:
            l = self._node_to_str(node.children[0])
            r = self._node_to_str(node.children[1]) if len(node.children) > 1 else "?"
            return f"{l} {node.value} {r}"
        if node.type == NodeType.FUNCTION_CALL:
            return f"{node.value}(...)"
        return node.type.name
