"""
Advanced PHP Security Scanner
Main orchestrator — crawls files, runs AST parser, symbolic executor,
CFG builder, include resolver, and pattern detector. Produces a rich report.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from php_ast import parse_php
from symbolic_engine import Finding, SymbolicExecutor
from cfg_and_detectors import CFGBuilder, IncludeResolver, PatternFinding, VulnerabilityDetector


# ─── Severity mapping ─────────────────────────────────────────────────────────

SEVERITY_MAP = {
    "code_exec":         "CRITICAL",
    "sqli":              "CRITICAL",
    "cmdi":              "CRITICAL",
    "lfi":               "HIGH",
    "insecure_deserial": "HIGH",
    "xxe":               "HIGH",
    "xss":               "HIGH",
    "ssrf":              "HIGH",
    "open_redirect":     "MEDIUM",
    "path_traversal":    "MEDIUM",
    "session_fixation":  "MEDIUM",
    "csrf_missing":      "LOW",
    "weak_crypto":       "LOW",
    "hardcoded_secret":  "MEDIUM",
    "info_exposure":     "LOW",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[34m",
    "INFO":     "\033[36m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
    "GREEN":    "\033[92m",
    "CYAN":     "\033[96m",
}


def c(color: str, text: str, no_color: bool = False) -> str:
    if no_color:
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"


# ─── Unified result ───────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    filepath: str
    symbolic_findings: List[Finding] = field(default_factory=list)
    pattern_findings: List[PatternFinding] = field(default_factory=list)
    includes: List[str] = field(default_factory=list)
    dynamic_includes: list = field(default_factory=list)
    cfg_node_count: int = 0
    parse_error: Optional[str] = None
    scan_time_ms: float = 0.0
    lines: int = 0


@dataclass
class ScanReport:
    target: str
    files_scanned: int = 0
    results: List[ScanResult] = field(default_factory=list)
    total_symbolic: int = 0
    total_pattern: int = 0
    total_time_ms: float = 0.0
    severity_counts: Dict[str, int] = field(default_factory=dict)


# ─── Per-file scanner ─────────────────────────────────────────────────────────

class FileScanner:

    def __init__(self, base_dir: str, build_cfg: bool = True,
                 pattern_only: bool = False):
        self.base_dir = base_dir
        self.build_cfg = build_cfg
        self.pattern_only = pattern_only

    def scan_file(self, filepath: str) -> ScanResult:
        result = ScanResult(filepath=filepath)
        t0 = time.time()

        try:
            source = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            result.parse_error = f"Cannot read file: {e}"
            return result

        result.lines = source.count("\n") + 1

        # ── Pattern scan (always) ──────────────────────────────────────────
        detector = VulnerabilityDetector()
        result.pattern_findings = detector.scan(source, filepath)

        if self.pattern_only:
            result.scan_time_ms = (time.time() - t0) * 1000
            return result

        # ── Parse PHP ─────────────────────────────────────────────────────
        try:
            ast = parse_php(source)
        except Exception as e:
            result.parse_error = f"Parse error: {e}"
            result.scan_time_ms = (time.time() - t0) * 1000
            return result

        # ── CFG ───────────────────────────────────────────────────────────
        if self.build_cfg:
            try:
                builder = CFGBuilder()
                _, nodes = builder.build(ast)
                result.cfg_node_count = len(nodes)
            except Exception:
                result.cfg_node_count = 0

        # ── Include resolver ──────────────────────────────────────────────
        resolver = IncludeResolver(self.base_dir)
        try:
            result.includes = resolver.resolve_all(ast, filepath)
            result.dynamic_includes = resolver.dynamic_includes
        except Exception:
            pass

        # ── Symbolic execution ────────────────────────────────────────────
        try:
            executor = SymbolicExecutor()
            result.symbolic_findings = executor.execute(ast)
        except Exception as e:
            result.parse_error = (result.parse_error or "") + f" | SymExec error: {e}"

        result.scan_time_ms = (time.time() - t0) * 1000
        return result


# ─── Multi-file orchestrator ──────────────────────────────────────────────────

PHP_EXTENSIONS = {".php", ".php3", ".php4", ".php5", ".phtml", ".inc"}

EXCLUDE_DIRS = {
    "vendor", "node_modules", ".git", ".svn",
    "tests", "test", "spec", "docs",
}


class Scanner:

    def __init__(self,
                 target: str,
                 pattern_only: bool = False,
                 build_cfg: bool = True,
                 max_files: int = 5000,
                 no_color: bool = False,
                 output_json: Optional[str] = None,
                 output_html: Optional[str] = None,
                 exclude_dirs: Set[str] = None,
                 severity_filter: Optional[str] = None):
        self.target = os.path.abspath(target)
        self.pattern_only = pattern_only
        self.build_cfg = build_cfg
        self.max_files = max_files
        self.no_color = no_color
        self.output_json = output_json
        self.output_html = output_html
        self.exclude_dirs = (exclude_dirs or set()) | EXCLUDE_DIRS
        self.severity_filter = severity_filter
        self.report = ScanReport(target=self.target)

    def run(self) -> ScanReport:
        t0 = time.time()

        if os.path.isfile(self.target):
            files = [self.target]
            base_dir = os.path.dirname(self.target)
        else:
            files = self._collect_files(self.target)
            base_dir = self.target

        print(c("BOLD", f"\n  🔍 Advanced PHP Security Scanner", self.no_color))
        print(c("DIM", f"  Target : {self.target}", self.no_color))
        print(c("DIM", f"  Files  : {len(files)}", self.no_color))
        print(c("DIM", f"  Mode   : {'pattern-only' if self.pattern_only else 'full (symbolic + pattern + CFG)'}\n", self.no_color))

        file_scanner = FileScanner(base_dir, self.build_cfg, self.pattern_only)

        for i, fp in enumerate(files[:self.max_files], 1):
            rel = os.path.relpath(fp, self.target if os.path.isdir(self.target) else base_dir)
            print(f"  [{i:4d}/{len(files)}] {rel[:70]}", end="\r", flush=True)
            result = file_scanner.scan_file(fp)
            self.report.results.append(result)
            self.report.files_scanned += 1
            self.report.total_symbolic += len(result.symbolic_findings)
            self.report.total_pattern += len(result.pattern_findings)

        self.report.total_time_ms = (time.time() - t0) * 1000
        self._count_severities()
        print(" " * 80, end="\r")  # clear progress line
        return self.report

    def _collect_files(self, base: str) -> List[str]:
        files = []
        for root, dirs, fnames in os.walk(base):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            for fn in fnames:
                if Path(fn).suffix.lower() in PHP_EXTENSIONS:
                    files.append(os.path.join(root, fn))
        return sorted(files)

    def _count_severities(self):
        counts: Dict[str, int] = {}
        for res in self.report.results:
            for f in res.symbolic_findings:
                sev = SEVERITY_MAP.get(f.vuln_type, "INFO")
                counts[sev] = counts.get(sev, 0) + 1
            for f in res.pattern_findings:
                sev = SEVERITY_MAP.get(f.vuln_type, "INFO")
                counts[sev] = counts.get(sev, 0) + 1
        self.report.severity_counts = counts

    # ── Output ────────────────────────────────────────────────────────────────

    def print_report(self):
        r = self.report
        nc = self.no_color

        print(c("BOLD", "\n" + "═" * 70, nc))
        print(c("BOLD", "  SCAN REPORT", nc))
        print(c("BOLD", "═" * 70, nc))
        print(f"  Files scanned : {r.files_scanned}")
        print(f"  Symbolic hits : {r.total_symbolic}")
        print(f"  Pattern hits  : {r.total_pattern}")
        print(f"  Scan time     : {r.total_time_ms:.0f} ms\n")

        # Severity summary bar
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cnt = r.severity_counts.get(sev, 0)
            if cnt:
                bar = "█" * min(cnt, 40)
                print(f"  {c(sev, f'{sev:<10}', nc)} {bar} {cnt}")
        print()

        # Per-file findings
        for res in r.results:
            all_findings = (
                [(f.vuln_type, f.confidence, f.line, f.description, "symbolic")
                 for f in res.symbolic_findings] +
                [(f.vuln_type, f.confidence, f.line, f.description, "pattern")
                 for f in res.pattern_findings]
            )

            if not all_findings and not res.parse_error:
                continue

            rel = os.path.relpath(
                res.filepath,
                self.target if os.path.isdir(self.target) else os.path.dirname(self.target)
            )
            print(c("BOLD", f"  ┌─ {rel}", nc))
            print(c("DIM", f"  │  Lines: {res.lines}  |  CFG nodes: {res.cfg_node_count}  |  "
                    f"Time: {res.scan_time_ms:.0f}ms", nc))

            if res.parse_error:
                print(c("DIM", f"  │  ⚠ {res.parse_error}", nc))

            # Sort by severity then line
            all_findings.sort(key=lambda x: (SEVERITY_ORDER.get(SEVERITY_MAP.get(x[0], "INFO"), 99), x[2]))

            for vuln_type, confidence, line, desc, engine in all_findings:
                sev = SEVERITY_MAP.get(vuln_type, "INFO")

                # Apply filter
                if self.severity_filter:
                    if SEVERITY_ORDER.get(sev, 99) > SEVERITY_ORDER.get(self.severity_filter, 99):
                        continue

                tag = c(sev, f"[{sev}]", nc)
                vtag = c("CYAN", f"[{vuln_type.upper()}]", nc)
                etag = c("DIM", f"({engine})", nc)
                print(f"  │  {tag} {vtag} line {line} {etag}")
                print(f"  │      {desc[:100]}")

            if res.dynamic_includes:
                for line, expr in res.dynamic_includes:
                    print(c("DIM", f"  │  ⚠ Dynamic include at line {line}: {expr}", nc))

            print(c("DIM", "  └" + "─" * 60, nc))

        # Stats footer
        print(c("BOLD", "\n" + "═" * 70, nc))

        if self.output_json:
            self._write_json()
        if self.output_html:
            self._write_html()

    def _write_json(self):
        def _serialise(obj):
            if hasattr(obj, "__dataclass_fields__"):
                return {k: _serialise(v) for k, v in asdict(obj).items()}
            if hasattr(obj, "name"):   # Enum
                return obj.name
            if isinstance(obj, set):
                return list(obj)
            return obj

        data = {
            "target": self.report.target,
            "files_scanned": self.report.files_scanned,
            "total_symbolic": self.report.total_symbolic,
            "total_pattern": self.report.total_pattern,
            "severity_counts": self.report.severity_counts,
            "scan_time_ms": self.report.total_time_ms,
            "results": [],
        }
        for res in self.report.results:
            data["results"].append({
                "file": res.filepath,
                "lines": res.lines,
                "cfg_nodes": res.cfg_node_count,
                "parse_error": res.parse_error,
                "symbolic": [
                    {
                        "type": f.vuln_type,
                        "severity": SEVERITY_MAP.get(f.vuln_type, "INFO"),
                        "sink": f.sink,
                        "line": f.line,
                        "confidence": f.confidence,
                        "taint_sources": [t.name for t in f.taint_sources],
                        "sanitised_by": list(f.sanitised_by),
                        "description": f.description,
                        "constraints": [str(c) for c in f.constraints],
                    }
                    for f in res.symbolic_findings
                ],
                "pattern": [
                    {
                        "type": f.vuln_type,
                        "severity": SEVERITY_MAP.get(f.vuln_type, "INFO"),
                        "line": f.line,
                        "confidence": f.confidence,
                        "description": f.description,
                        "snippet": f.snippet,
                    }
                    for f in res.pattern_findings
                ],
            })

        Path(self.output_json).write_text(json.dumps(data, indent=2))
        print(f"\n  JSON report → {self.output_json}")

    def _write_html(self):
        sev_colors = {
            "CRITICAL": "#e74c3c", "HIGH": "#c0392b", "MEDIUM": "#f39c12",
            "LOW": "#3498db", "INFO": "#95a5a6",
        }
        rows = []
        for res in self.report.results:
            all_f = (
                [(f.vuln_type, SEVERITY_MAP.get(f.vuln_type, "INFO"), f.line, f.description, "symbolic")
                 for f in res.symbolic_findings] +
                [(f.vuln_type, SEVERITY_MAP.get(f.vuln_type, "INFO"), f.line, f.description, "pattern")
                 for f in res.pattern_findings]
            )
            for vt, sev, line, desc, engine in all_f:
                sc = sev_colors.get(sev, "#ccc")
                rows.append(
                    f"<tr>"
                    f"<td>{os.path.relpath(res.filepath, self.target)}</td>"
                    f"<td style='color:{sc};font-weight:bold'>{sev}</td>"
                    f"<td><span class='vtag'>{vt.upper()}</span></td>"
                    f"<td>{line}</td>"
                    f"<td>{engine}</td>"
                    f"<td>{desc[:120]}</td>"
                    f"</tr>"
                )

        def _badge(s):
            bg = sev_colors.get(s, "#999")
            cnt = self.report.severity_counts.get(s, 0)
            return f"<span class='badge' style='background:{bg}'>{s}: {cnt}</span>"
        counts_html = " ".join(_badge(s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>PHP Scanner Report – {os.path.basename(self.target)}</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
  h1{{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:10px}}
  .meta{{color:#8b949e;margin-bottom:20px}}
  .badge{{display:inline-block;padding:3px 10px;border-radius:4px;color:#fff;font-size:12px;margin:2px}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{background:#161b22;color:#8b949e;text-align:left;padding:8px 12px;border-bottom:2px solid #30363d}}
  td{{padding:7px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
  tr:hover td{{background:#161b22}}
  .vtag{{background:#1f6feb;color:#fff;padding:2px 6px;border-radius:3px;font-size:11px}}
</style>
</head>
<body>
<h1>🔍 PHP Security Scanner Report</h1>
<div class="meta">
  <strong>Target:</strong> {self.target}<br/>
  <strong>Files:</strong> {self.report.files_scanned} &nbsp;
  <strong>Time:</strong> {self.report.total_time_ms:.0f} ms
</div>
<div style="margin-bottom:20px">{counts_html}</div>
<table>
<thead><tr>
  <th>File</th><th>Severity</th><th>Type</th><th>Line</th><th>Engine</th><th>Description</th>
</tr></thead>
<tbody>
{"".join(rows) if rows else '<tr><td colspan="6" style="text-align:center;color:#3fb950">✓ No findings</td></tr>'}
</tbody>
</table>
</body>
</html>"""
        Path(self.output_html).write_text(html)
        print(f"  HTML report → {self.output_html}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        prog="php-scanner",
        description="Advanced PHP Security Scanner — symbolic execution + pattern analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  php-scanner /var/www/html
  php-scanner app/ --severity HIGH --json report.json
  php-scanner vuln.php --pattern-only --no-color
  php-scanner app/ --html report.html --exclude-dir tests
        """
    )
    ap.add_argument("target", help="PHP file or directory to scan")
    ap.add_argument("--pattern-only", action="store_true",
                    help="Skip symbolic execution (faster, less accurate)")
    ap.add_argument("--no-cfg", action="store_true",
                    help="Skip CFG construction")
    ap.add_argument("--max-files", type=int, default=5000,
                    help="Maximum files to scan (default: 5000)")
    ap.add_argument("--no-color", action="store_true",
                    help="Disable terminal colours")
    ap.add_argument("--json", metavar="FILE",
                    help="Write JSON report to FILE")
    ap.add_argument("--html", metavar="FILE",
                    help="Write HTML report to FILE")
    ap.add_argument("--severity", choices=["CRITICAL","HIGH","MEDIUM","LOW","INFO"],
                    help="Only show findings at or above this severity")
    ap.add_argument("--exclude-dir", metavar="DIR", action="append", default=[],
                    help="Directory names to exclude (can repeat)")

    args = ap.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: target not found: {args.target}", file=sys.stderr)
        sys.exit(1)

    scanner = Scanner(
        target=args.target,
        pattern_only=args.pattern_only,
        build_cfg=not args.no_cfg,
        max_files=args.max_files,
        no_color=args.no_color,
        output_json=args.json,
        output_html=args.html,
        exclude_dirs=set(args.exclude_dir),
        severity_filter=args.severity,
    )

    scanner.run()
    scanner.print_report()

    # Exit code: non-zero if any HIGH+ finding
    high_plus = sum(
        scanner.report.severity_counts.get(s, 0)
        for s in ("CRITICAL", "HIGH")
    )
    sys.exit(1 if high_plus else 0)


if __name__ == "__main__":
    main()
