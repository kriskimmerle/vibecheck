#!/usr/bin/env python3
"""vibecheck — AI-Generated Code Security Meta-Auditor.

One command to catch the security patterns AI-generated code consistently gets wrong.
Zero dependencies. AST-based. Focused on the top failure modes of vibe-coded projects.

Usage:
    vibecheck path/to/file.py
    vibecheck path/to/project/
    vibecheck --check path/to/project/    # CI mode (exit 1 if grade < C)
    vibecheck --json path/to/project/     # JSON output
    cat file.py | vibecheck -             # stdin

Research basis:
    - 24.7% of AI-generated code has security flaws
    - 1.75x more logic errors vs human code
    - 2.74x more XSS vulnerabilities
    - 45% of AI code contains security issues
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

# ── Check definitions ──────────────────────────────────────────────

CHECKS: dict[str, dict[str, str]] = {
    "VC01": {"name": "SQL Injection", "severity": "CRITICAL",
             "desc": "User input formatted into SQL queries"},
    "VC02": {"name": "Command Injection", "severity": "CRITICAL",
             "desc": "User input passed to shell commands"},
    "VC03": {"name": "Path Traversal", "severity": "HIGH",
             "desc": "User input used in file paths without sanitization"},
    "VC04": {"name": "XSS / Unsafe Output", "severity": "HIGH",
             "desc": "Unsanitized data rendered in HTML responses"},
    "VC05": {"name": "Hardcoded Secrets", "severity": "CRITICAL",
             "desc": "API keys, passwords, or tokens in source code"},
    "VC06": {"name": "Insecure Crypto", "severity": "HIGH",
             "desc": "Weak hashing, insecure random, or broken crypto patterns"},
    "VC07": {"name": "Missing Auth", "severity": "HIGH",
             "desc": "Route handlers without authentication checks"},
    "VC08": {"name": "Debug Mode", "severity": "MEDIUM",
             "desc": "Debug settings left enabled in production code"},
    "VC09": {"name": "Unsafe Deserialization", "severity": "CRITICAL",
             "desc": "Untrusted data passed to pickle, eval, yaml.load, etc."},
    "VC10": {"name": "Missing Error Handling", "severity": "MEDIUM",
             "desc": "Silent exception swallowing or overly broad catch"},
    "VC11": {"name": "Resource Leaks", "severity": "MEDIUM",
             "desc": "Files, sockets, or connections opened without cleanup"},
    "VC12": {"name": "Missing Timeouts", "severity": "MEDIUM",
             "desc": "Network calls without timeout parameters"},
    "VC13": {"name": "SSRF", "severity": "HIGH",
             "desc": "User input used in outbound HTTP requests"},
    "VC14": {"name": "Prompt Injection", "severity": "HIGH",
             "desc": "User input formatted directly into LLM prompts"},
    "VC15": {"name": "Insecure Defaults", "severity": "MEDIUM",
             "desc": "SSL verify disabled, CORS wildcard, permissive settings"},
}

SEVERITY_WEIGHT = {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 1}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ── Patterns ────────────────────────────────────────────────────────

# Secret patterns (regex on source text)
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "GitHub token"),
    (r'github_pat_[A-Za-z0-9_]{22,}', "GitHub PAT"),
    (r'sk-[A-Za-z0-9]{20,}', "OpenAI API key"),
    (r'sk-ant-[A-Za-z0-9_-]{20,}', "Anthropic API key"),
    (r'sk-proj-[A-Za-z0-9_-]{20,}', "OpenAI project key"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key"),
    (r'xox[bpsa]-[A-Za-z0-9-]{10,}', "Slack token"),
    (r'sk_live_[A-Za-z0-9]{24,}', "Stripe secret key"),
    (r'sq0atp-[A-Za-z0-9_-]{22,}', "Square token"),
    (r'SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}', "SendGrid key"),
    (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', "Private key"),
]

# SQL execution methods
SQL_EXEC_NAMES = {
    "execute", "executemany", "executescript", "raw",
    "execute_sql", "run_sql",
}

# Network call patterns (for timeout/SSRF checks)
NETWORK_FUNCS = {
    "get", "post", "put", "patch", "delete", "head", "options",
    "request", "urlopen", "urlretrieve",
}
NETWORK_MODULES = {"requests", "httpx", "urllib", "aiohttp", "http"}

# LLM client patterns
LLM_CALL_ATTRS = {
    "chat", "completions", "create", "generate", "invoke",
    "send_message", "generate_content",
}
LLM_MODULES = {
    "openai", "anthropic", "langchain", "google", "cohere",
    "huggingface", "litellm", "ollama", "groq", "mistralai",
}

# Auth decorator patterns
AUTH_DECORATORS = {
    "login_required", "permission_required", "auth_required",
    "requires_auth", "authenticated", "jwt_required",
    "token_required", "api_key_required", "requires_login",
    "admin_required", "superuser_required", "staff_member_required",
    "permission_classes", "authentication_classes",
}

# Sensitive route patterns
SENSITIVE_ROUTES = re.compile(
    r'(?:/admin|/api/users|/api/auth|/settings|/config|'
    r'/upload|/delete|/payments?|/billing|/tokens?|'
    r'/secrets?|/credentials?|/keys?|/internal)',
    re.IGNORECASE,
)

# ── AST Helpers ─────────────────────────────────────────────────────


def _get_name(node: ast.AST) -> str:
    """Extract a dotted name from an AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _is_fstring_or_format(node: ast.AST) -> bool:
    """Check if a node is an f-string or .format() call."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    return False


def _has_keyword(call: ast.Call, name: str) -> bool:
    """Check if a Call node has a specific keyword argument."""
    return any(kw.arg == name for kw in call.keywords)


def _node_in_with(node: ast.AST, parents: dict[int, ast.AST]) -> bool:
    """Check if a node is inside a with statement managing its result."""
    p = parents.get(id(node))
    while p:
        if isinstance(p, ast.With):
            return True
        p = parents.get(id(p))
    return False


def _node_in_try(node: ast.AST, parents: dict[int, ast.AST]) -> bool:
    """Check if a node is inside a try/except block."""
    p = parents.get(id(node))
    while p:
        if isinstance(p, (ast.Try, ast.ExceptHandler)):
            return True
        # Python 3.11+
        if hasattr(ast, "TryStar") and isinstance(p, ast.TryStar):
            return True
        p = parents.get(id(p))
    return False


def _collect_imports(tree: ast.Module) -> dict[str, str]:
    """Collect import aliases → module mappings."""
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                imports[name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                name = alias.asname or alias.name
                imports[name] = f"{mod}.{alias.name}" if mod else alias.name
    return imports


def _build_parent_map(tree: ast.AST) -> dict[int, ast.AST]:
    """Build child-id → parent mapping."""
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


class Finding:
    """A single security finding."""

    __slots__ = ("rule", "file", "line", "message", "severity", "fix")

    def __init__(self, rule: str, file: str, line: int, message: str,
                 severity: str, fix: str = ""):
        self.rule = rule
        self.file = file
        self.line = line
        self.message = message
        self.severity = severity
        self.fix = fix

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule": self.rule,
            "name": CHECKS[self.rule]["name"],
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
        }
        if self.fix:
            d["fix"] = self.fix
        return d


# ── Analyzer ────────────────────────────────────────────────────────


class VibeChecker:
    """AST-based security analyzer targeting AI-generated code patterns."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def check_file(self, filepath: str, source: str) -> None:
        """Run all checks on a single file."""
        # Text-based checks (secrets, debug patterns)
        self._check_secrets(filepath, source)
        self._check_debug_mode(filepath, source)
        self._check_insecure_defaults(filepath, source)

        # AST-based checks
        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError:
            return

        imports = _collect_imports(tree)
        parents = _build_parent_map(tree)

        self._check_sql_injection(filepath, tree, imports, parents)
        self._check_command_injection(filepath, tree, imports, parents)
        self._check_path_traversal(filepath, tree, imports, parents)
        self._check_xss(filepath, tree, imports, parents)
        self._check_insecure_crypto(filepath, tree, imports)
        self._check_missing_auth(filepath, tree, imports)
        self._check_unsafe_deserialization(filepath, tree, imports)
        self._check_error_handling(filepath, tree, parents)
        self._check_resource_leaks(filepath, tree, imports, parents)
        self._check_missing_timeouts(filepath, tree, imports, parents)
        self._check_ssrf(filepath, tree, imports, parents)
        self._check_prompt_injection(filepath, tree, imports)

    # ── VC01: SQL Injection ──────────────────────────────────────

    def _check_sql_injection(self, fp: str, tree: ast.Module,
                             imports: dict, parents: dict) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # cursor.execute(...), db.raw(...), etc.
            if isinstance(node.func, ast.Attribute):
                if node.func.attr not in SQL_EXEC_NAMES:
                    continue
            elif isinstance(node.func, ast.Name):
                if node.func.id not in SQL_EXEC_NAMES:
                    continue
            else:
                continue

            if not node.args:
                continue

            arg = node.args[0]
            if _is_fstring_or_format(arg):
                self.findings.append(Finding(
                    "VC01", fp, node.lineno,
                    "SQL query built with string formatting — SQL injection risk",
                    "CRITICAL",
                    "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = ?', (id,))",
                ))
            # Check if the first arg is a variable that was assigned a formatted string
            elif isinstance(arg, ast.Name):
                self._check_formatted_variable(
                    fp, tree, arg.id, node.lineno,
                    "VC01", "SQL query variable built with string formatting",
                    "Use parameterized queries instead of string formatting",
                )

    def _check_formatted_variable(self, fp: str, tree: ast.Module,
                                   var_name: str, use_line: int,
                                   rule: str, msg: str, fix: str) -> None:
        """Check if a variable was assigned a formatted string."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == var_name:
                        if _is_fstring_or_format(node.value):
                            self.findings.append(Finding(
                                rule, fp, use_line, msg, "CRITICAL", fix))
                            return
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name) and node.target.id == var_name:
                    if isinstance(node.op, ast.Add):
                        self.findings.append(Finding(
                            rule, fp, use_line, msg, "CRITICAL", fix))
                        return

    # ── VC02: Command Injection ──────────────────────────────────

    def _check_command_injection(self, fp: str, tree: ast.Module,
                                 imports: dict, parents: dict) -> None:
        dangerous_calls = {
            "os.system", "os.popen", "os.exec", "os.execl", "os.execle",
            "os.execlp", "os.execv", "os.execve", "os.execvp", "os.execvpe",
            "os.spawn", "os.spawnl", "os.spawnle",
        }
        subprocess_calls = {
            "subprocess.run", "subprocess.call", "subprocess.check_output",
            "subprocess.check_call", "subprocess.Popen",
        }

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = _get_name(node.func)

            # os.system(f"cmd {user_input}")
            if name in dangerous_calls or any(name.startswith(d) for d in dangerous_calls):
                if node.args and _is_fstring_or_format(node.args[0]):
                    self.findings.append(Finding(
                        "VC02", fp, node.lineno,
                        f"{name}() with formatted string — command injection risk",
                        "CRITICAL",
                        "Use subprocess.run() with a list of arguments instead",
                    ))

            # subprocess.run(f"cmd {input}", shell=True)
            if name in subprocess_calls or any(name.startswith(s) for s in subprocess_calls):
                has_shell = False
                for kw in node.keywords:
                    if kw.arg == "shell":
                        if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            has_shell = True
                if has_shell and node.args and _is_fstring_or_format(node.args[0]):
                    self.findings.append(Finding(
                        "VC02", fp, node.lineno,
                        f"{name}() with shell=True and formatted command — command injection",
                        "CRITICAL",
                        "Remove shell=True and pass command as list: subprocess.run(['cmd', arg])",
                    ))

            # eval() with non-constant argument
            if name == "eval" and node.args:
                arg = node.args[0]
                if not isinstance(arg, ast.Constant):
                    self.findings.append(Finding(
                        "VC02", fp, node.lineno,
                        "eval() with dynamic argument — code injection risk",
                        "CRITICAL",
                        "Use ast.literal_eval() for data parsing, or avoid eval() entirely",
                    ))

    # ── VC03: Path Traversal ─────────────────────────────────────

    def _check_path_traversal(self, fp: str, tree: ast.Module,
                               imports: dict, parents: dict) -> None:
        file_funcs = {"open", "Path", "os.path.join"}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = _get_name(node.func)
            if name not in file_funcs:
                continue

            if not node.args:
                continue

            arg = node.args[0] if name != "os.path.join" else None
            # For os.path.join, check any argument
            args_to_check = node.args if name == "os.path.join" else [node.args[0]]

            for arg in args_to_check:
                if _is_fstring_or_format(arg):
                    # Check if any FormattedValue in f-string references request/user vars
                    if isinstance(arg, ast.JoinedStr):
                        for val in arg.values:
                            if isinstance(val, ast.FormattedValue):
                                vname = _get_name(val.value)
                                if any(s in vname.lower() for s in (
                                    "request", "user", "input", "param",
                                    "query", "filename", "path", "name",
                                )):
                                    self.findings.append(Finding(
                                        "VC03", fp, node.lineno,
                                        f"User-controlled input in file path ({name}) — path traversal risk",
                                        "HIGH",
                                        "Sanitize paths: os.path.basename() or resolve and check against allowed directory",
                                    ))
                                    break

    # ── VC04: XSS / Unsafe Output ────────────────────────────────

    def _check_xss(self, fp: str, tree: ast.Module,
                    imports: dict, parents: dict) -> None:
        # Check for HTML string construction with user input
        html_patterns = {"text/html", "Content-Type", "innerHTML",
                         "<script", "<div", "<span", "<p>", "<form"}

        for node in ast.walk(tree):
            # make_response(f"<html>{user_input}</html>")
            if isinstance(node, ast.Call):
                name = _get_name(node.func)
                if name in ("make_response", "HTMLResponse", "Response"):
                    if node.args and isinstance(node.args[0], ast.JoinedStr):
                        # Check if the f-string contains HTML-like content
                        fstr = node.args[0]
                        for val in fstr.values:
                            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                                if any(p in val.value for p in ("<", "html", "div", "script")):
                                    self.findings.append(Finding(
                                        "VC04", fp, node.lineno,
                                        "HTML response built with f-string — XSS risk",
                                        "HIGH",
                                        "Use a template engine (Jinja2) with auto-escaping, or markupsafe.escape()",
                                    ))
                                    break

            # return f"<html>..." in route handler
            if isinstance(node, ast.Return) and node.value:
                if isinstance(node.value, ast.JoinedStr):
                    for val in node.value.values:
                        if isinstance(val, ast.Constant) and isinstance(val.value, str):
                            if "<" in val.value and any(
                                t in val.value.lower() for t in
                                ("html", "div", "script", "body", "head",
                                 "form", "input", "span", "table", "style")
                            ):
                                has_dynamic = any(
                                    isinstance(v, ast.FormattedValue)
                                    for v in node.value.values
                                )
                                if has_dynamic:
                                    self.findings.append(Finding(
                                        "VC04", fp, node.lineno,
                                        "Returning HTML f-string with dynamic content — XSS risk",
                                        "HIGH",
                                        "Use a template engine with auto-escaping",
                                    ))
                                break

            # Markup(f"...{user}...")  — bypasses escaping
            if isinstance(node, ast.Call):
                name = _get_name(node.func)
                if name in ("Markup", "markupsafe.Markup", "jinja2.Markup"):
                    if node.args and isinstance(node.args[0], ast.JoinedStr):
                        self.findings.append(Finding(
                            "VC04", fp, node.lineno,
                            "Markup() with f-string — bypasses template auto-escaping (XSS)",
                            "HIGH",
                            "Escape user input before wrapping in Markup()",
                        ))

    # ── VC05: Hardcoded Secrets ──────────────────────────────────

    def _check_secrets(self, fp: str, source: str) -> None:
        # Skip test files
        basename = os.path.basename(fp).lower()
        if basename.startswith("test_") or basename.endswith("_test.py"):
            return

        for line_num, line in enumerate(source.splitlines(), 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for pattern, label in SECRET_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    # Skip patterns in string patterns/regex definitions
                    if "re.compile" in line or "Pattern" in line:
                        continue
                    # Skip example/placeholder markers
                    matched_text = match.group(0)
                    if any(p in matched_text.lower() for p in
                           ("example", "placeholder", "changeme", "xxx")):
                        continue
                    self.findings.append(Finding(
                        "VC05", fp, line_num,
                        f"Possible {label} found in source code",
                        "CRITICAL",
                        "Move secrets to environment variables or a secrets manager",
                    ))
                    break  # One finding per line

    # ── VC06: Insecure Crypto ────────────────────────────────────

    def _check_insecure_crypto(self, fp: str, tree: ast.Module,
                                imports: dict) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = _get_name(node.func)

            # hashlib.md5() / hashlib.sha1()
            if name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1"):
                # Check for usedforsecurity=False (Python 3.9+)
                if _has_keyword(node, "usedforsecurity"):
                    for kw in node.keywords:
                        if kw.arg == "usedforsecurity":
                            if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                                continue
                self.findings.append(Finding(
                    "VC06", fp, node.lineno,
                    f"{name}() — weak hash algorithm, vulnerable to collision attacks",
                    "HIGH",
                    "Use hashlib.sha256() or hashlib.blake2b() for security purposes",
                ))

            # random.randint() etc. for security
            if name.startswith("random.") and name.split(".")[-1] in (
                "randint", "random", "choice", "choices", "sample",
                "randrange", "getrandbits",
            ):
                # Check context — is this near security-related code?
                parent = None
                for n in ast.walk(tree):
                    for child in ast.iter_child_nodes(n):
                        if child is node:
                            parent = n
                            break
                if parent and isinstance(parent, ast.Assign):
                    for t in parent.targets:
                        tname = _get_name(t).lower()
                        if any(s in tname for s in (
                            "token", "secret", "key", "password", "otp",
                            "code", "nonce", "salt", "session", "csrf",
                        )):
                            self.findings.append(Finding(
                                "VC06", fp, node.lineno,
                                f"{name}() used for security-sensitive value — predictable output",
                                "HIGH",
                                "Use secrets.token_hex() or secrets.token_urlsafe() instead",
                            ))

            # DES, Blowfish, RC4
            if any(weak in name for weak in ("DES", "Blowfish", "RC4", "ARC4")):
                if "new" in name or "cipher" in name.lower():
                    self.findings.append(Finding(
                        "VC06", fp, node.lineno,
                        f"Weak cipher algorithm: {name}",
                        "HIGH",
                        "Use AES-256-GCM or ChaCha20-Poly1305",
                    ))

    # ── VC07: Missing Auth ───────────────────────────────────────

    def _check_missing_auth(self, fp: str, tree: ast.Module,
                             imports: dict) -> None:
        # Check for Flask/FastAPI route decorators on functions handling sensitive paths
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            route_path = None
            has_auth = False

            for decorator in node.decorator_list:
                # @app.route("/admin/...")
                if isinstance(decorator, ast.Call):
                    dec_name = _get_name(decorator.func)
                    if any(r in dec_name for r in (".route", ".get", ".post",
                                                    ".put", ".delete", ".patch")):
                        if decorator.args and isinstance(decorator.args[0], ast.Constant):
                            route_path = str(decorator.args[0].value)

                    # Check for auth decorators
                    if any(a in dec_name for a in AUTH_DECORATORS):
                        has_auth = True

                    # FastAPI Depends() with auth
                    for kw in decorator.keywords:
                        if kw.arg == "dependencies":
                            has_auth = True
                        # Check for Depends(get_current_user) etc.
                        if isinstance(kw.value, ast.Call):
                            dep_name = _get_name(kw.value.func)
                            if "auth" in dep_name.lower() or "user" in dep_name.lower():
                                has_auth = True

                # @login_required etc.
                dec_name = _get_name(decorator) if not isinstance(decorator, ast.Call) else ""
                if any(a in dec_name for a in AUTH_DECORATORS):
                    has_auth = True

            # Check function params for Depends()
            if not has_auth:
                for arg in node.args.args:
                    if arg.annotation and isinstance(arg.annotation, ast.Call):
                        ann_name = _get_name(arg.annotation.func)
                        if "Depends" in ann_name:
                            has_auth = True
                    # Default value is Depends(...)
                    # Check defaults
                for default in node.args.defaults + node.args.kw_defaults:
                    if default and isinstance(default, ast.Call):
                        def_name = _get_name(default.func)
                        if "Depends" in def_name:
                            dep_arg = default.args[0] if default.args else None
                            if dep_arg:
                                dep_func = _get_name(dep_arg)
                                if any(s in dep_func.lower() for s in
                                       ("auth", "user", "current", "token", "session")):
                                    has_auth = True

            if route_path and not has_auth and SENSITIVE_ROUTES.search(route_path):
                self.findings.append(Finding(
                    "VC07", fp, node.lineno,
                    f"Sensitive route '{route_path}' has no authentication decorator",
                    "HIGH",
                    "Add @login_required or Depends(get_current_user) to protect this endpoint",
                ))

    # ── VC08: Debug Mode ─────────────────────────────────────────

    @staticmethod
    def _is_inside_string(line: str) -> bool:
        """Heuristic: skip lines that are primarily string content (assignments to string vars, dict values, etc.)."""
        stripped = line.strip()
        # Line is a string assignment: var = "..."
        if re.match(r'^["\']', stripped):
            return True
        # Line is a dict/list string value
        if re.match(r'^["\'].*["\'],?\s*$', stripped):
            return True
        # Line starts with common string-only patterns (inside function call, etc.)
        if re.match(r'^\s*"[^"]*"\s*,?\s*$', line):
            return True
        return False

    def _check_debug_mode(self, fp: str, source: str) -> None:
        basename = os.path.basename(fp).lower()
        if basename.startswith("test_") or "test" in basename:
            return

        for line_num, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if self._is_inside_string(stripped):
                continue

            # DEBUG = True
            if re.match(r'^DEBUG\s*=\s*True\b', stripped):
                self.findings.append(Finding(
                    "VC08", fp, line_num,
                    "DEBUG = True — should be False in production",
                    "MEDIUM",
                    "Set DEBUG = False or use environment variable: DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'",
                ))

            # app.run(debug=True)
            if re.search(r'\.run\([^)]*debug\s*=\s*True', stripped):
                self.findings.append(Finding(
                    "VC08", fp, line_num,
                    "App running with debug=True — exposes debugger in production",
                    "MEDIUM",
                    "Remove debug=True or gate it: debug=os.getenv('FLASK_DEBUG', 'false') == 'true'",
                ))

    # ── VC09: Unsafe Deserialization ─────────────────────────────

    def _check_unsafe_deserialization(self, fp: str, tree: ast.Module,
                                       imports: dict) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = _get_name(node.func)

            # pickle.loads() / pickle.load()
            if name in ("pickle.loads", "pickle.load", "cPickle.loads",
                         "cPickle.load", "shelve.open", "marshal.loads",
                         "marshal.load"):
                self.findings.append(Finding(
                    "VC09", fp, node.lineno,
                    f"{name}() — deserializing untrusted data enables arbitrary code execution",
                    "CRITICAL",
                    "Use json.loads() for data interchange, or verify data source integrity",
                ))

            # yaml.load() without SafeLoader
            if name in ("yaml.load", "yaml.unsafe_load"):
                if name == "yaml.unsafe_load":
                    self.findings.append(Finding(
                        "VC09", fp, node.lineno,
                        "yaml.unsafe_load() — arbitrary code execution via YAML",
                        "CRITICAL",
                        "Use yaml.safe_load() instead",
                    ))
                elif not _has_keyword(node, "Loader"):
                    self.findings.append(Finding(
                        "VC09", fp, node.lineno,
                        "yaml.load() without Loader= — defaults to unsafe loading",
                        "CRITICAL",
                        "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
                    ))
                else:
                    for kw in node.keywords:
                        if kw.arg == "Loader":
                            loader_name = _get_name(kw.value)
                            if "Unsafe" in loader_name or "Full" in loader_name:
                                self.findings.append(Finding(
                                    "VC09", fp, node.lineno,
                                    f"yaml.load() with {loader_name} — unsafe YAML loading",
                                    "CRITICAL",
                                    "Use yaml.SafeLoader or yaml.safe_load()",
                                ))

            # exec() with variable
            if name == "exec" and node.args:
                arg = node.args[0]
                if not isinstance(arg, ast.Constant):
                    self.findings.append(Finding(
                        "VC09", fp, node.lineno,
                        "exec() with dynamic content — code injection risk",
                        "CRITICAL",
                        "Avoid exec() entirely, or use a sandboxed execution environment",
                    ))

    # ── VC10: Missing Error Handling ─────────────────────────────

    def _check_error_handling(self, fp: str, tree: ast.Module,
                               parents: dict) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue

            # Bare except or except Exception with just 'pass'
            is_broad = (node.type is None or
                        (isinstance(node.type, ast.Name) and
                         node.type.id in ("Exception", "BaseException")))

            if is_broad:
                body = node.body
                if len(body) == 1 and isinstance(body[0], ast.Pass):
                    self.findings.append(Finding(
                        "VC10", fp, node.lineno,
                        "except block silently swallows errors with 'pass' — hides bugs",
                        "MEDIUM",
                        "At minimum, log the exception: except Exception as e: logger.error(e)",
                    ))
                elif len(body) == 1 and isinstance(body[0], ast.Expr):
                    if isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                        self.findings.append(Finding(
                            "VC10", fp, node.lineno,
                            "except block with just a string expression — error is silently lost",
                            "MEDIUM",
                            "Log the exception or re-raise it",
                        ))

            # Bare except (no type at all)
            if node.type is None:
                self.findings.append(Finding(
                    "VC10", fp, node.lineno,
                    "Bare 'except:' catches everything including KeyboardInterrupt and SystemExit",
                    "MEDIUM",
                    "Catch specific exceptions: except (ValueError, TypeError) as e:",
                ))

    # ── VC11: Resource Leaks ─────────────────────────────────────

    def _check_resource_leaks(self, fp: str, tree: ast.Module,
                               imports: dict, parents: dict) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = _get_name(node.func)

            # open() without with statement
            if name == "open":
                if not _node_in_with(node, parents):
                    # Check if assigned and closed later (simple heuristic)
                    parent = parents.get(id(node))
                    if isinstance(parent, ast.Assign):
                        # Check if it's a simple pattern, not in with
                        self.findings.append(Finding(
                            "VC11", fp, node.lineno,
                            "open() without 'with' statement — file may not be closed on exception",
                            "MEDIUM",
                            "Use: with open(path) as f:",
                        ))

            # socket.socket() without with
            if name in ("socket.socket", "socket"):
                if not _node_in_with(node, parents):
                    parent = parents.get(id(node))
                    if isinstance(parent, ast.Assign):
                        self.findings.append(Finding(
                            "VC11", fp, node.lineno,
                            "Socket created without 'with' statement — may leak file descriptors",
                            "MEDIUM",
                            "Use: with socket.socket() as sock:",
                        ))

    # ── VC12: Missing Timeouts ───────────────────────────────────

    def _check_missing_timeouts(self, fp: str, tree: ast.Module,
                                  imports: dict, parents: dict) -> None:
        has_network_import = any(
            mod.split(".")[0] in NETWORK_MODULES
            for mod in imports.values()
        )

        if not has_network_import:
            return

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = _get_name(node.func)
            method = name.split(".")[-1] if "." in name else name

            if method in NETWORK_FUNCS:
                # Check if it's actually a network call (module-aware)
                if "." in name:
                    module_part = name.rsplit(".", 1)[0]
                    is_network = any(
                        nm in module_part or
                        imports.get(module_part, "").split(".")[0] in NETWORK_MODULES
                        for nm in NETWORK_MODULES
                    )
                    if not is_network:
                        continue
                else:
                    # Bare function name — check imports
                    imported_from = imports.get(method, "")
                    if not any(nm in imported_from for nm in NETWORK_MODULES):
                        continue

                if not _has_keyword(node, "timeout"):
                    self.findings.append(Finding(
                        "VC12", fp, node.lineno,
                        f"{name}() without timeout= — can hang indefinitely",
                        "MEDIUM",
                        f"Add timeout parameter: {name}(..., timeout=30)",
                    ))

    # ── VC13: SSRF ───────────────────────────────────────────────

    def _check_ssrf(self, fp: str, tree: ast.Module,
                     imports: dict, parents: dict) -> None:
        has_network_import = any(
            mod.split(".")[0] in NETWORK_MODULES
            for mod in imports.values()
        )
        if not has_network_import:
            return

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = _get_name(node.func)
            method = name.split(".")[-1] if "." in name else name

            if method in NETWORK_FUNCS and node.args:
                url_arg = node.args[0]
                if isinstance(url_arg, ast.JoinedStr):
                    # f-string URL — check if it includes user-controlled vars
                    for val in url_arg.values:
                        if isinstance(val, ast.FormattedValue):
                            vname = _get_name(val.value)
                            if any(s in vname.lower() for s in (
                                "request", "user", "input", "param",
                                "url", "host", "target", "redirect",
                                "callback", "next", "return",
                            )):
                                self.findings.append(Finding(
                                    "VC13", fp, node.lineno,
                                    f"User-controlled input in URL ({name}) — SSRF risk",
                                    "HIGH",
                                    "Validate URLs against an allowlist of permitted hosts",
                                ))
                                break

    # ── VC14: Prompt Injection ───────────────────────────────────

    def _check_prompt_injection(self, fp: str, tree: ast.Module,
                                 imports: dict) -> None:
        has_llm_import = any(
            mod.split(".")[0] in LLM_MODULES
            for mod in imports.values()
        )
        if not has_llm_import:
            return

        # Find variables from user input
        user_vars: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    tname = _get_name(target)
                    if isinstance(node.value, ast.Call):
                        call_name = _get_name(node.value.func)
                        if any(s in call_name.lower() for s in
                               ("input", "request", "form", "args", "json",
                                "query", "body", "params")):
                            user_vars.add(tname)
                    # request.form["x"], request.args.get("x")
                    if isinstance(node.value, ast.Subscript):
                        sub_name = _get_name(node.value.value)
                        if "request" in sub_name.lower():
                            user_vars.add(tname)

        # Check for user vars formatted into strings passed to LLM calls
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = _get_name(node.func)

            # Check all arguments for f-strings containing user vars
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):
                    for val in arg.values:
                        if isinstance(val, ast.FormattedValue):
                            vname = _get_name(val.value)
                            if vname in user_vars:
                                self.findings.append(Finding(
                                    "VC14", fp, node.lineno,
                                    f"User input '{vname}' formatted directly into string passed to LLM call — prompt injection risk",
                                    "HIGH",
                                    "Separate system prompts from user content; use structured message format with user role",
                                ))
                                break

            # Check keyword arguments (content=f"...{user_input}...")
            for kw in node.keywords:
                if kw.arg in ("content", "prompt", "text", "message", "query"):
                    if isinstance(kw.value, ast.JoinedStr):
                        for val in kw.value.values:
                            if isinstance(val, ast.FormattedValue):
                                vname = _get_name(val.value)
                                if vname in user_vars:
                                    self.findings.append(Finding(
                                        "VC14", fp, node.lineno,
                                        f"User input '{vname}' in LLM prompt keyword — prompt injection risk",
                                        "HIGH",
                                        "Use structured messages: [{'role':'system','content':...}, {'role':'user','content':user_input}]",
                                    ))
                                    break

    # ── VC15: Insecure Defaults ──────────────────────────────────

    def _check_insecure_defaults(self, fp: str, source: str) -> None:
        for line_num, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if self._is_inside_string(stripped):
                continue

            # verify=False
            if re.search(r'verify\s*=\s*False\b', stripped):
                if "ssl" in stripped.lower() or "request" in stripped.lower() or "get(" in stripped or "post(" in stripped:
                    self.findings.append(Finding(
                        "VC15", fp, line_num,
                        "SSL verification disabled (verify=False) — vulnerable to MITM attacks",
                        "MEDIUM",
                        "Remove verify=False; fix SSL certificate issues instead",
                    ))

            # CORS allow all
            if re.search(r'(?:allow_origins|CORS_ORIGINS|cors_allowed_origins)\s*=\s*\[\s*["\']?\*["\']?\s*\]', stripped):
                self.findings.append(Finding(
                    "VC15", fp, line_num,
                    "CORS allows all origins ('*') — any website can make requests to this API",
                    "MEDIUM",
                    "Restrict to specific domains: allow_origins=['https://yourdomain.com']",
                ))

            # ALLOWED_HOSTS = ['*']
            if re.search(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]?\*['\"]?\s*\]", stripped):
                self.findings.append(Finding(
                    "VC15", fp, line_num,
                    "ALLOWED_HOSTS = ['*'] — accepts requests for any hostname",
                    "MEDIUM",
                    "Set specific hostnames: ALLOWED_HOSTS = ['yourdomain.com']",
                ))

            # SECRET_KEY with weak/default value
            if re.match(r"SECRET_KEY\s*=\s*['\"](.+?)['\"]", stripped):
                match = re.match(r"SECRET_KEY\s*=\s*['\"](.+?)['\"]", stripped)
                if match:
                    val = match.group(1).lower()
                    if any(weak in val for weak in (
                        "changeme", "secret", "password", "default",
                        "insecure", "dev", "test", "your-secret",
                        "replace", "todo", "fixme",
                    )) or len(match.group(1)) < 20:
                        self.findings.append(Finding(
                            "VC15", fp, line_num,
                            "Weak or default SECRET_KEY — sessions and tokens are compromisable",
                            "MEDIUM",
                            "Generate a strong key: python -c 'import secrets; print(secrets.token_hex(32))'",
                        ))


# ── Scanning and Output ─────────────────────────────────────────────


def scan_path(path: str, checker: VibeChecker) -> int:
    """Scan a file or directory. Returns number of files scanned."""
    p = Path(path)
    count = 0

    if p.is_file():
        if p.suffix == ".py":
            try:
                source = p.read_text(encoding="utf-8", errors="ignore")
                checker.check_file(str(p), source)
                count = 1
            except OSError:
                pass
    elif p.is_dir():
        skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv",
                     ".tox", ".eggs", "build", "dist", ".mypy_cache",
                     ".pytest_cache", ".ruff_cache", "egg-info"}
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".egg-info")]
            for fname in files:
                if fname.endswith(".py"):
                    fpath = os.path.join(root, fname)
                    try:
                        source = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                        checker.check_file(fpath, source)
                        count += 1
                    except OSError:
                        pass
    return count


def compute_score(findings: list[Finding]) -> int:
    """Compute a 0-100 safety score."""
    deductions = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    return max(0, 100 - deductions)


def grade(score: int) -> str:
    """Convert score to letter grade."""
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def severity_color(severity: str) -> str:
    """ANSI color for severity."""
    colors = {
        "CRITICAL": "\033[91m",  # red
        "HIGH": "\033[93m",     # yellow
        "MEDIUM": "\033[33m",   # orange-ish
        "LOW": "\033[36m",      # cyan
        "INFO": "\033[90m",     # grey
    }
    return colors.get(severity, "")


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def print_results(checker: VibeChecker, files_scanned: int,
                  verbose: bool = False, severity_filter: str | None = None,
                  ignore_rules: set[str] | None = None) -> tuple[int, str]:
    """Print results and return (score, grade)."""
    findings = checker.findings

    # Apply filters
    if severity_filter:
        sev_idx = SEVERITY_ORDER.get(severity_filter.upper(), 99)
        findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= sev_idx]
    if ignore_rules:
        findings = [f for f in findings if f.rule not in ignore_rules]

    # Sort by severity, then file, then line
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))

    score = compute_score(findings)
    g = grade(score)

    # Header
    print(f"\n{BOLD}⚡ vibecheck{RESET} — AI Code Security Audit")
    print(f"{DIM}{'─' * 60}{RESET}")
    print(f"  Files scanned: {files_scanned}")
    print(f"  Findings: {len(findings)}")
    print(f"  Score: {BOLD}{score}/100{RESET}  Grade: {BOLD}{g}{RESET}")
    print(f"{DIM}{'─' * 60}{RESET}")

    if not findings:
        print(f"\n  {BOLD}✅ No security issues found. Ship it!{RESET}\n")
        return score, g

    # Summary by severity
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    print()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in by_sev:
            color = severity_color(sev)
            print(f"  {color}{sev}{RESET}: {by_sev[sev]}")

    # Summary by check
    by_check: dict[str, int] = {}
    for f in findings:
        by_check[f.rule] = by_check.get(f.rule, 0) + 1
    print(f"\n{DIM}{'─' * 60}{RESET}")
    for rule in sorted(by_check.keys()):
        check = CHECKS[rule]
        color = severity_color(check["severity"])
        print(f"  {color}{rule}{RESET} {check['name']}: {by_check[rule]}")

    # Findings
    print(f"\n{DIM}{'─' * 60}{RESET}")
    current_file = ""
    for f in findings:
        if f.file != current_file:
            current_file = f.file
            print(f"\n  {BOLD}{current_file}{RESET}")

        color = severity_color(f.severity)
        print(f"    {DIM}L{f.line:<4}{RESET} {color}{f.severity:<8}{RESET} "
              f"{color}{f.rule}{RESET} {f.message}")
        if verbose and f.fix:
            print(f"         {DIM}Fix: {f.fix}{RESET}")

    print()
    return score, g


def print_json(checker: VibeChecker, files_scanned: int,
               severity_filter: str | None = None,
               ignore_rules: set[str] | None = None) -> tuple[int, str]:
    """Print JSON output."""
    findings = checker.findings
    if severity_filter:
        sev_idx = SEVERITY_ORDER.get(severity_filter.upper(), 99)
        findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= sev_idx]
    if ignore_rules:
        findings = [f for f in findings if f.rule not in ignore_rules]

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))
    score = compute_score(findings)
    g = grade(score)

    result = {
        "tool": "vibecheck",
        "version": __version__,
        "files_scanned": files_scanned,
        "score": score,
        "grade": g,
        "summary": {sev: sum(1 for f in findings if f.severity == sev)
                     for sev in SEVERITY_ORDER if any(f.severity == sev for f in findings)},
        "findings": [f.to_dict() for f in findings],
    }
    print(json.dumps(result, indent=2))
    return score, g


# ── CLI ──────────────────────────────────────────────────────────────


def main() -> int:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="vibecheck",
        description="⚡ AI-Generated Code Security Meta-Auditor — one command to catch what AI gets wrong",
    )
    parser.add_argument("paths", nargs="*", default=["."],
                        help="Files or directories to scan (default: current directory)")
    parser.add_argument("--check", action="store_true",
                        help="CI mode: exit 1 if grade below threshold (default: C)")
    parser.add_argument("--threshold", default="C",
                        help="Minimum passing grade for --check (default: C)")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to report")
    parser.add_argument("--ignore", action="append", default=[],
                        help="Rules to ignore (e.g., --ignore VC08)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show fix suggestions for each finding")
    parser.add_argument("--version", action="version", version=f"vibecheck {__version__}")

    args = parser.parse_args()

    checker = VibeChecker()
    total_files = 0
    ignore_rules = set(args.ignore)

    for path in args.paths:
        if path == "-":
            source = sys.stdin.read()
            checker.check_file("<stdin>", source)
            total_files += 1
        else:
            total_files += scan_path(path, checker)

    if total_files == 0:
        print("No Python files found.", file=sys.stderr)
        return 1

    if args.json_output:
        score, g = print_json(checker, total_files, args.severity, ignore_rules)
    else:
        score, g = print_results(checker, total_files, args.verbose,
                                  args.severity, ignore_rules)

    if args.check:
        threshold_score = {"A+": 95, "A": 90, "B": 80, "C": 70, "D": 60, "F": 0}
        min_score = threshold_score.get(args.threshold.upper(), 70)
        if score < min_score:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
