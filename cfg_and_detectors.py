"""
Control Flow Graph (CFG), Include Resolver, and Vulnerability Detector
"""
from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from php_ast import ASTNode, NodeType


# ═══════════════════════════════════════════════════════════════════════════════
# Control Flow Graph
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class CFGNode:
    id: int
    stmts: List[ASTNode] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    label: str = ""

    def __repr__(self):
        return f"CFGNode(id={self.id}, label={self.label!r}, stmts={len(self.stmts)})"


class CFGBuilder:
    """Builds a Control Flow Graph from a PHP AST."""

    def __init__(self):
        self._nodes: Dict[int, CFGNode] = {}
        self._next_id = 0

    def _new_node(self, label: str = "") -> CFGNode:
        n = CFGNode(id=self._next_id, label=label)
        self._nodes[self._next_id] = n
        self._next_id += 1
        return n

    def _link(self, src: CFGNode, dst: CFGNode):
        if dst.id not in src.successors:
            src.successors.append(dst.id)
        if src.id not in dst.predecessors:
            dst.predecessors.append(src.id)

    def build(self, ast: ASTNode) -> Tuple[CFGNode, Dict[int, CFGNode]]:
        entry = self._new_node("ENTRY")
        exit_node = self._new_node("EXIT")
        self._build_block(ast, entry, exit_node)
        return entry, self._nodes

    def _build_block(self, node: ASTNode, current: CFGNode,
                     exit_node: CFGNode) -> CFGNode:
        stmts = node.children if node.type == NodeType.BLOCK else [node]
        for stmt in stmts:
            if stmt is None:
                continue
            current = self._build_stmt(stmt, current, exit_node)
        return current

    def _build_stmt(self, node: ASTNode, current: CFGNode,
                    exit_node: CFGNode) -> CFGNode:
        t = node.type

        if t == NodeType.IF:
            return self._build_if(node, current, exit_node)
        if t in (NodeType.WHILE, NodeType.FOR, NodeType.FOREACH):
            return self._build_loop(node, current, exit_node)
        if t == NodeType.RETURN:
            current.stmts.append(node)
            self._link(current, exit_node)
            return self._new_node("UNREACHABLE")
        if t == NodeType.BLOCK:
            return self._build_block(node, current, exit_node)

        current.stmts.append(node)
        return current

    def _build_if(self, node: ASTNode, current: CFGNode,
                  exit_node: CFGNode) -> CFGNode:
        cond_node = CFGNode(id=self._next_id, label="IF_COND",
                            stmts=[node.children[0]] if node.children else [])
        self._nodes[self._next_id] = cond_node
        self._next_id += 1
        self._link(current, cond_node)

        merge = self._new_node("IF_MERGE")

        # True branch
        true_entry = self._new_node("IF_TRUE")
        self._link(cond_node, true_entry)
        true_exit = self._build_block(
            node.children[1] if len(node.children) > 1 else ASTNode(NodeType.BLOCK),
            true_entry, exit_node
        )
        self._link(true_exit, merge)

        # False / else branch
        false_entry = self._new_node("IF_FALSE")
        self._link(cond_node, false_entry)
        if len(node.children) > 2:
            false_exit = self._build_block(node.children[2], false_entry, exit_node)
        else:
            false_exit = false_entry
        self._link(false_exit, merge)

        return merge

    def _build_loop(self, node: ASTNode, current: CFGNode,
                    exit_node: CFGNode) -> CFGNode:
        header = self._new_node("LOOP_HEADER")
        self._link(current, header)

        body_entry = self._new_node("LOOP_BODY")
        self._link(header, body_entry)

        body_exit = self._build_block(
            node.children[-1] if node.children else ASTNode(NodeType.BLOCK),
            body_entry, exit_node
        )
        self._link(body_exit, header)   # back-edge

        loop_exit = self._new_node("LOOP_EXIT")
        self._link(header, loop_exit)   # can skip body
        return loop_exit

    def to_dot(self) -> str:
        lines = ["digraph CFG {", '  node [shape=box fontname="Courier"];']
        for n in self._nodes.values():
            stmts_preview = " | ".join(
                n.type.name for n in n.stmts[:3]
            ) if n.stmts else ""
            label = f"{n.label}\\n{stmts_preview}"
            lines.append(f'  n{n.id} [label="{label}"];')
        for n in self._nodes.values():
            for s in n.successors:
                lines.append(f"  n{n.id} -> n{s};")
        lines.append("}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# Include Resolver
# ═══════════════════════════════════════════════════════════════════════════════

class IncludeResolver:
    """
    Resolves static include/require paths and crawls the include graph.
    Also flags dynamic (tainted) includes as LFI candidates.
    """

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.resolved: Dict[str, str] = {}   # node path → abs path
        self.failed: List[str] = []
        self.dynamic_includes: List[Tuple[int, str]] = []  # (line, expr)

    def resolve_all(self, ast: ASTNode, current_file: str) -> List[str]:
        """Walk AST and collect include targets; return list of resolved paths."""
        resolved_paths = []
        self._walk(ast, current_file, resolved_paths)
        return resolved_paths

    def _walk(self, node: ASTNode, current_file: str, out: List[str]):
        if node.type in (NodeType.INCLUDE, NodeType.REQUIRE):
            if node.children:
                arg = node.children[0]
                path = self._resolve_path(arg, current_file)
                if path:
                    out.append(path)
                    self.resolved[current_file] = path
                else:
                    # Dynamic include — record for LFI reporting
                    self.dynamic_includes.append((node.line, self._node_repr(arg)))
        for child in node.children:
            self._walk(child, current_file, out)

    def _resolve_path(self, node: ASTNode, current_file: str) -> Optional[str]:
        """Try to resolve a static string path."""
        if node.type == NodeType.STRING:
            raw = node.value.strip("'\"")
            # Relative to current file
            base = os.path.dirname(current_file)
            candidate = os.path.normpath(os.path.join(base, raw))
            if os.path.isfile(candidate):
                return candidate
            # Relative to project root
            candidate2 = os.path.normpath(os.path.join(self.base_dir, raw))
            if os.path.isfile(candidate2):
                return candidate2
            self.failed.append(raw)
        return None

    @staticmethod
    def _node_repr(node: ASTNode) -> str:
        if node.type == NodeType.STRING:
            return node.value
        if node.type in (NodeType.VARIABLE, NodeType.SUPERGLOBAL):
            return node.value
        return node.type.name


# ═══════════════════════════════════════════════════════════════════════════════
# Vulnerability Detector (pattern-based, complements symbolic exec)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PatternFinding:
    vuln_type: str
    description: str
    line: int
    snippet: str
    confidence: str = "MEDIUM"


VULN_PATTERNS = [
    # SQL injection patterns
    ("sqli", re.compile(
        r'(mysql_query|mysqli_query|pg_query|sqlite_query)\s*\(\s*[^)]*\$_(GET|POST|REQUEST|COOKIE)',
        re.IGNORECASE
    ), "SQL query with direct superglobal input — likely SQLi"),

    # XSS patterns
    ("xss", re.compile(
        r'echo\s+\$_(GET|POST|REQUEST|COOKIE)',
        re.IGNORECASE
    ), "Direct echo of superglobal without encoding — XSS"),

    ("xss", re.compile(
        r'echo\s+.*\$_(GET|POST|REQUEST|COOKIE)',
        re.IGNORECASE
    ), "Echo with superglobal in expression — possible XSS"),

    # LFI patterns
    ("lfi", re.compile(
        r'(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)',
        re.IGNORECASE
    ), "Dynamic include/require with superglobal — LFI"),

    # Command injection
    ("cmdi", re.compile(
        r'(exec|system|shell_exec|passthru|popen)\s*\(\s*[^)]*\$_(GET|POST|REQUEST)',
        re.IGNORECASE
    ), "Shell execution with user input — command injection"),

    # Eval
    ("code_exec", re.compile(
        r'eval\s*\(\s*[^)]*\$_(GET|POST|REQUEST|COOKIE)',
        re.IGNORECASE
    ), "eval() with user input — remote code execution"),

    # Unsafe deserialization
    ("insecure_deserial", re.compile(
        r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
        re.IGNORECASE
    ), "unserialize() with user input — object injection"),

    # Open redirect
    ("open_redirect", re.compile(
        r'header\s*\(\s*["\']?Location\s*:\s*["\']?\s*\.\s*\$_(GET|POST|REQUEST)',
        re.IGNORECASE
    ), "header(Location:) with user input — open redirect"),

    # SSRF
    ("ssrf", re.compile(
        r'(curl_setopt|file_get_contents)\s*\([^)]*\$_(GET|POST|REQUEST)',
        re.IGNORECASE
    ), "HTTP fetch with user-controlled URL — SSRF"),

    # Weak crypto
    ("weak_crypto", re.compile(
        r'\b(md5|sha1)\s*\(\s*\$',
        re.IGNORECASE
    ), "Weak hash function (MD5/SHA1) used on user data"),

    # Insecure session
    ("session_fixation", re.compile(
        r'session_id\s*\(\s*\$_(GET|POST|REQUEST)',
        re.IGNORECASE
    ), "session_id() set from user input — session fixation"),

    # Path traversal
    ("path_traversal", re.compile(
        r'(file_get_contents|file_put_contents|fopen|readfile)\s*\([^)]*\$_(GET|POST|REQUEST)',
        re.IGNORECASE
    ), "File operation with user-controlled path — path traversal"),

    # XXE
    ("xxe", re.compile(
        r'simplexml_load_(string|file)\s*\(',
        re.IGNORECASE
    ), "SimpleXML load — ensure external entities are disabled"),

    # Hardcoded secrets
    ("hardcoded_secret", re.compile(
        r'(password|passwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{6,}["\']',
        re.IGNORECASE
    ), "Possible hardcoded credential or secret"),

    # Debug/info exposure
    ("info_exposure", re.compile(
        r'(phpinfo\s*\(\s*\)|var_dump\s*\(\s*\$_(GET|POST|REQUEST|SERVER)|print_r\s*\(\s*\$_)',
        re.IGNORECASE
    ), "Debug function exposing server/user data"),

    # Error display
    ("info_exposure", re.compile(
        r'display_errors\s*=\s*(On|1|true)',
        re.IGNORECASE
    ), "display_errors enabled — stack traces exposed to users"),

    # CSRF
    ("csrf_missing", re.compile(
        r'<form[^>]*(method=["\']post["\'])',
        re.IGNORECASE
    ), "HTML form without obvious CSRF token check"),
]


class VulnerabilityDetector:
    """Pattern-based scanner that runs regex checks over PHP source lines."""

    def __init__(self):
        self.findings: List[PatternFinding] = []

    def scan(self, source: str, filepath: str = "") -> List[PatternFinding]:
        self.findings = []
        lines = source.splitlines()

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                continue
            for vuln_type, pattern, description in VULN_PATTERNS:
                if pattern.search(line):
                    self.findings.append(PatternFinding(
                        vuln_type=vuln_type,
                        description=description,
                        line=lineno,
                        snippet=line.strip()[:120],
                        confidence="HIGH" if "$_GET" in line or "$_POST" in line else "MEDIUM",
                    ))

        return self.findings
