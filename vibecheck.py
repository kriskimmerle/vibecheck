#!/usr/bin/env python3
"""
vibecheck - Security scanner for AI/vibe-coded Python
Detects common security anti-patterns in AI-generated code.
"""

import ast
import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import List, Dict, Tuple, Set

VERSION = "1.0.0"

# Rule definitions
RULES = {
    "VC001": {
        "name": "Placeholder credentials",
        "severity": "ERROR",
        "description": "AI-generated placeholder secrets detected",
    },
    "VC002": {
        "name": "Insecure defaults left in",
        "severity": "ERROR",
        "description": "Debug mode, weak secrets, or overly permissive settings",
    },
    "VC003": {
        "name": "Insecure random for security",
        "severity": "ERROR",
        "description": "Using random module instead of secrets for security context",
    },
    "VC004": {
        "name": "Unsafe deserialization",
        "severity": "ERROR",
        "description": "Dangerous deserialization functions (pickle, yaml.load, eval)",
    },
    "VC005": {
        "name": "Hardcoded URLs/endpoints",
        "severity": "WARNING",
        "description": "API endpoints hardcoded as literals instead of config",
    },
    "VC006": {
        "name": "Missing error handling",
        "severity": "WARNING",
        "description": "Network/IO operations without try/except",
    },
    "VC007": {
        "name": "Deprecated library usage",
        "severity": "WARNING",
        "description": "Importing deprecated Python modules",
    },
    "VC008": {
        "name": "SQL string formatting",
        "severity": "ERROR",
        "description": "SQL queries built with f-strings or .format() instead of parameters",
    },
    "VC009": {
        "name": "Weak hashing",
        "severity": "ERROR",
        "description": "MD5 or SHA1 used for passwords or security",
    },
    "VC010": {
        "name": "Unrestricted file operations",
        "severity": "WARNING",
        "description": "File operations with user-controlled paths",
    },
    "VC011": {
        "name": "Repeated vulnerability pattern",
        "severity": "WARNING",
        "description": "Same security issue appears 3+ times (AI copy-paste)",
    },
    "VC012": {
        "name": "Missing input validation",
        "severity": "WARNING",
        "description": "Web framework endpoints use request data without validation",
    },
    "VC013": {
        "name": "Subprocess with shell=True",
        "severity": "ERROR",
        "description": "Shell injection risk in subprocess calls",
    },
    "VC014": {
        "name": "Broad exception suppression",
        "severity": "WARNING",
        "description": "except: pass silently swallows errors",
    },
    "VC015": {
        "name": "Insecure temp files",
        "severity": "WARNING",
        "description": "tempfile.mktemp() has race condition vulnerability",
    },
}


class Finding:
    """Represents a single security finding"""

    def __init__(self, rule_id: str, line: int, column: int, message: str, code: str = ""):
        self.rule_id = rule_id
        self.line = line
        self.column = column
        self.message = message
        self.code = code
        self.severity = RULES[rule_id]["severity"]

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "code": self.code,
        }


class VibeChecker(ast.NodeVisitor):
    """AST visitor that detects AI-coded security anti-patterns"""

    def __init__(self, source_code: str, filename: str):
        self.source_code = source_code
        self.filename = filename
        self.lines = source_code.split("\n")
        self.findings: List[Finding] = []
        self.imports: Set[str] = set()
        self.random_imported = False
        self.secrets_imported = False
        self.function_has_try = defaultdict(bool)
        self.current_function = None

    def add_finding(self, rule_id: str, node: ast.AST, message: str):
        """Add a finding with context"""
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        code = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        self.findings.append(Finding(rule_id, line, col, message, code.strip()))

    def visit_Import(self, node: ast.Import):
        """Track imports for deprecated modules and random/secrets usage"""
        for alias in node.names:
            self.imports.add(alias.name)
            
            # VC007: Deprecated library usage
            deprecated = {
                "urllib2": "Use urllib.request instead",
                "optparse": "Use argparse instead",
                "imp": "Use importlib instead",
                "cgi": "Deprecated in Python 3.11",
                "CGIHTTPServer": "Use http.server instead",
                "SimpleHTTPServer": "Use http.server instead",
            }
            
            if alias.name in deprecated:
                self.add_finding(
                    "VC007", node, f"Deprecated module '{alias.name}': {deprecated[alias.name]}"
                )

            # Track random/secrets for VC003
            if alias.name == "random":
                self.random_imported = True
            if alias.name == "secrets":
                self.secrets_imported = True

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track from X import Y patterns"""
        if node.module:
            self.imports.add(node.module)
            
            # Track random/secrets
            if node.module == "random":
                self.random_imported = True
            if node.module == "secrets":
                self.secrets_imported = True

        self.generic_visit(node)

    def visit_Str(self, node: ast.Str):
        """Check string literals for various patterns"""
        self._check_string_value(node, node.s)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        """Check constant values (Python 3.8+)"""
        if isinstance(node.value, str):
            self._check_string_value(node, node.value)
        self.generic_visit(node)

    def _check_string_value(self, node: ast.AST, value: str):
        """Common string checking logic"""
        # VC001: Placeholder credentials
        placeholder_patterns = [
            r"your[_-]?api[_-]?key",
            r"sk-[x]{4,}",
            r"TODO:?\s*(replace|add|insert)",
            r"INSERT[_-]?(YOUR|KEY|TOKEN|SECRET)",
            r"CHANGE[_-]?ME",
            r"example[_-]?(key|token|secret|password)",
            r"test123",
            r"password123",
            r"admin",
            r"<[^>]*(key|token|secret|password)[^>]*>",
        ]
        
        for pattern in placeholder_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                self.add_finding(
                    "VC001", node, f"Placeholder credential detected: '{value[:50]}...'"
                )
                break

        # VC005: Hardcoded URLs (http/https endpoints)
        if re.match(r"https?://", value) and "localhost" not in value and "127.0.0.1" not in value:
            # Skip if it looks like documentation
            if not any(x in value.lower() for x in ["example.com", "example.org", "api.example"]):
                self.add_finding(
                    "VC005", node, f"Hardcoded URL: {value[:50]}"
                )

        # VC008: SQL patterns in strings
        sql_keywords = r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b"
        if re.search(sql_keywords, value, re.IGNORECASE):
            # Check if it's an f-string or uses .format() - this would be in parent context
            # For now, flag any SQL with format markers
            if "{" in value or "%" in value:
                self.add_finding(
                    "VC008", node, "SQL query using string formatting - use parameterized queries"
                )

    def visit_JoinedStr(self, node: ast.JoinedStr):
        """Check f-strings for SQL injection"""
        # Reconstruct approximate f-string content
        content_parts = []
        for val in node.values:
            if isinstance(val, ast.Constant):
                content_parts.append(str(val.value))
            else:
                content_parts.append("{}")
        
        content = "".join(content_parts)
        
        # VC008: SQL in f-strings - but not in logger/error messages
        # Skip if this looks like a log message or error string
        if any(x in content.lower() for x in ["error:", "failed", "warning:", "info:", "debug:"]):
            self.generic_visit(node)
            return
        
        sql_keywords = r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b"
        # Only flag if it has SQL keywords AND looks like a query (has FROM, WHERE, SET, INTO, etc.)
        if re.search(sql_keywords, content, re.IGNORECASE):
            query_patterns = r"\b(FROM|WHERE|SET|INTO|VALUES|JOIN|ORDER BY)\b"
            if re.search(query_patterns, content, re.IGNORECASE):
                self.add_finding(
                    "VC008", node, "SQL query in f-string - use parameterized queries"
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Check assignments for insecure defaults"""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                
                # VC002: Insecure defaults
                if isinstance(node.value, ast.Constant):
                    val = node.value.value
                    
                    # DEBUG = True
                    if var_name.upper() == "DEBUG" and val is True:
                        self.add_finding(
                            "VC002", node, "debug=True should not be in production code"
                        )
                    
                    # SECRET_KEY with obvious defaults
                    if "SECRET" in var_name.upper() and isinstance(val, str):
                        weak_secrets = ["secret", "changeme", "test", "default", "key", "password"]
                        if any(s in val.lower() for s in weak_secrets) or len(val) < 16:
                            self.add_finding(
                                "VC002", node, f"Weak/default SECRET_KEY: '{val[:20]}...'"
                            )

                # Check for ALLOWED_HOSTS = ["*"]
                if var_name == "ALLOWED_HOSTS" and isinstance(node.value, ast.List):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and elt.value == "*":
                            self.add_finding(
                                "VC002", node, "ALLOWED_HOSTS=['*'] is insecure"
                            )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Check function calls for security issues"""
        func_name = self._get_call_name(node)
        
        # VC003: Insecure random for security
        security_contexts = ["token", "password", "secret", "key", "session", "nonce"]
        if func_name and "random." in func_name:
            # Check if variable name or nearby context suggests security use
            parent_context = self._get_context_hint(node)
            if any(ctx in parent_context.lower() for ctx in security_contexts):
                self.add_finding(
                    "VC003", node, f"Using random.{func_name.split('.')[-1]} for security - use secrets module"
                )

        # VC004: Unsafe deserialization
        unsafe_deserial = {
            "pickle.loads": "Use safer serialization (JSON) or validate input",
            "pickle.load": "Use safer serialization (JSON) or validate input",
            "marshal.loads": "Marshal is unsafe for untrusted data",
            "marshal.load": "Marshal is unsafe for untrusted data",
            "yaml.load": "Use yaml.safe_load() instead",
            "eval": "eval() on user input is extremely dangerous",
            "exec": "exec() on user input is extremely dangerous",
        }
        
        if func_name in unsafe_deserial:
            self.add_finding(
                "VC004", node, f"{func_name}(): {unsafe_deserial[func_name]}"
            )

        # VC009: Weak hashing
        if func_name in ["hashlib.md5", "hashlib.sha1"]:
            self.add_finding(
                "VC009", node, f"{func_name}() is cryptographically weak - use SHA-256+ or bcrypt/scrypt"
            )

        # VC010: Unrestricted file operations
        file_ops = ["open", "os.remove", "os.rmdir", "os.unlink"]
        if func_name in file_ops:
            # Check if path argument looks dynamic/user-controlled
            if node.args and isinstance(node.args[0], (ast.Name, ast.Attribute, ast.Call)):
                self.add_finding(
                    "VC010", node, f"{func_name}() with dynamic path - validate/sanitize user input"
                )

        # VC013: Subprocess with shell=True
        if "subprocess." in func_name:
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    self.add_finding(
                        "VC013", node, "subprocess with shell=True is a shell injection risk"
                    )

        # VC015: Insecure temp files
        if func_name == "tempfile.mktemp":
            self.add_finding(
                "VC015", node, "tempfile.mktemp() has race condition - use mkstemp() or NamedTemporaryFile"
            )

        # VC002: verify=False in requests
        if "request" in func_name.lower():
            for keyword in node.keywords:
                if keyword.arg == "verify" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                    self.add_finding(
                        "VC002", node, "verify=False disables SSL certificate verification"
                    )

        # VC012: Missing input validation in web frameworks
        web_patterns = {
            "request.json": "Validate request.json before use",
            "request.form": "Validate form data before use",
            "request.args": "Validate query parameters before use",
            "request.data": "Validate request data before use",
        }
        
        if func_name in web_patterns:
            # Simple heuristic: if accessed directly without validation
            self.add_finding(
                "VC012", node, web_patterns[func_name]
            )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track functions for error handling analysis"""
        prev_func = self.current_function
        self.current_function = node.name
        
        # VC006: Check for missing error handling
        has_risky_ops = self._has_risky_operations(node)
        has_try = self._has_try_except(node)
        
        if has_risky_ops and not has_try:
            self.add_finding(
                "VC006", node, f"Function '{node.name}' has network/IO operations but no try/except"
            )

        # Check decorators for web framework routes (VC012)
        self._check_route_validation(node)

        self.generic_visit(node)
        self.current_function = prev_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Same as FunctionDef for async functions"""
        self.visit_FunctionDef(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        """Check for broad exception suppression"""
        # VC014: except: pass or except Exception: pass
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            if node.type is None:
                self.add_finding(
                    "VC014", node, "Bare 'except: pass' silently swallows all errors"
                )
            elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                self.add_finding(
                    "VC014", node, "'except Exception: pass' silently swallows errors"
                )

        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract full call name like 'os.path.join'"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _get_context_hint(self, node: ast.AST) -> str:
        """Get variable names in context for heuristics"""
        # Walk up to find assignment target
        line = getattr(node, "lineno", 0)
        if 0 < line <= len(self.lines):
            return self.lines[line - 1]
        return ""

    def _has_risky_operations(self, func_node: ast.FunctionDef) -> bool:
        """Check if function contains network/IO operations"""
        risky_calls = {
            "requests.", "urllib.", "httpx.", "http.client", "socket.",
            "open", "os.open", "io.open",
            "sqlite3.", "psycopg2.", "pymongo.", "mysql.",
        }
        
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if any(risk in call_name for risk in risky_calls):
                    return True
        return False

    def _has_try_except(self, func_node: ast.FunctionDef) -> bool:
        """Check if function has try/except"""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Try):
                return True
        return False

    def _check_route_validation(self, func_node: ast.FunctionDef):
        """Check if route handlers validate input"""
        # Look for Flask/FastAPI route decorators
        is_route = False
        for decorator in func_node.decorator_list:
            if isinstance(decorator, ast.Call):
                name = self._get_call_name(decorator)
                if any(x in name for x in ["route", "get", "post", "put", "delete", "patch"]):
                    is_route = True
                    break
            elif isinstance(decorator, ast.Attribute):
                if decorator.attr in ["route", "get", "post", "put", "delete", "patch"]:
                    is_route = True
                    break

        if is_route:
            # Check if request.json/form/args accessed without validation
            uses_request = False
            has_validation = False
            
            for node in ast.walk(func_node):
                if isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name) and node.value.id == "request":
                        if node.attr in ["json", "form", "args", "data"]:
                            uses_request = True
                
                # Simple heuristic: Pydantic model or schema validation present
                if isinstance(node, ast.Call):
                    call_name = self._get_call_name(node)
                    if "validate" in call_name or "schema" in call_name.lower():
                        has_validation = True

            if uses_request and not has_validation:
                # Already caught by visit_Call, so skip duplicate


                pass

    def detect_repeated_patterns(self):
        """VC011: Detect if same issue appears 3+ times (AI copy-paste)"""
        rule_counts = defaultdict(int)
        for finding in self.findings:
            rule_counts[finding.rule_id] += 1

        for rule_id, count in rule_counts.items():
            if count >= 3 and rule_id != "VC011":  # Don't recurse
                # Add one VC011 finding
                self.findings.append(
                    Finding(
                        "VC011",
                        0,
                        0,
                        f"Rule {rule_id} triggered {count} times - possible AI copy-paste pattern",
                    )
                )


def scan_file(filepath: str) -> Tuple[List[Finding], str]:
    """Scan a single Python file"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
    except Exception as e:
        return [], f"Error reading file: {e}"

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as e:
        return [], f"Syntax error: {e}"

    checker = VibeChecker(source, filepath)
    checker.visit(tree)
    checker.detect_repeated_patterns()

    return checker.findings, ""


def calculate_vibe_score(findings: List[Finding]) -> Tuple[int, str, str]:
    """Calculate vibe score and verdict"""
    score = 100
    
    for finding in findings:
        if finding.severity == "ERROR":
            score -= 10
        else:  # WARNING
            score -= 5

    score = max(0, score)

    if score >= 90:
        grade = "A"
        verdict = "Ship it 🚀"
    elif score >= 70:
        grade = "B"
        verdict = "Review before deploying 🔍"
    elif score >= 50:
        grade = "C"
        verdict = "Needs security hardening ⚠️"
    else:
        grade = "F"
        verdict = "Do not deploy 🛑"

    return score, grade, verdict


def format_text_output(results: Dict, quiet: bool = False) -> str:
    """Format results as human-readable text"""
    output = []
    
    total_files = len(results["files"])
    total_findings = sum(len(f["findings"]) for f in results["files"])
    
    if not quiet:
        output.append(f"vibecheck v{VERSION}")
        output.append("=" * 60)
        output.append("")

    for file_result in results["files"]:
        filepath = file_result["path"]
        findings = file_result["findings"]
        error = file_result.get("error")

        if error:
            output.append(f"❌ {filepath}")
            output.append(f"   {error}")
            output.append("")
            continue

        if not findings and not quiet:
            output.append(f"✅ {filepath}")
            output.append("   No issues detected")
            output.append("")
            continue

        if findings:
            output.append(f"⚠️  {filepath}")
            
            for finding in sorted(findings, key=lambda x: (x.line, x.column)):
                severity_icon = "🔴" if finding.severity == "ERROR" else "🟡"
                output.append(f"   {severity_icon} Line {finding.line}:{finding.column} [{finding.rule_id}] {finding.message}")
                if finding.code and not quiet:
                    output.append(f"      > {finding.code}")
            
            output.append("")

    # Summary
    output.append("=" * 60)
    output.append(f"Vibe Score: {results['vibe_score']}/100 (Grade: {results['grade']})")
    output.append(f"Verdict: {results['verdict']}")
    output.append("")
    output.append(f"Files scanned: {total_files}")
    output.append(f"Issues found: {total_findings}")
    
    errors = sum(1 for f in results["files"] for finding in f["findings"] if finding.severity == "ERROR")
    warnings = total_findings - errors
    
    if errors:
        output.append(f"  🔴 Errors: {errors}")
    if warnings:
        output.append(f"  🟡 Warnings: {warnings}")

    return "\n".join(output)


def format_json_output(results: Dict) -> str:
    """Format results as JSON"""
    # Convert Finding objects to dicts
    output = {
        "version": results["version"],
        "vibe_score": results["vibe_score"],
        "grade": results["grade"],
        "verdict": results["verdict"],
        "files": []
    }
    
    for file_result in results["files"]:
        output["files"].append({
            "path": file_result["path"],
            "error": file_result.get("error"),
            "findings": [f.to_dict() for f in file_result["findings"]]
        })

    return json.dumps(output, indent=2)


def list_rules():
    """Print all available rules"""
    print(f"vibecheck v{VERSION} - Security Rules\n")
    print("=" * 70)
    
    for rule_id in sorted(RULES.keys()):
        rule = RULES[rule_id]
        severity_icon = "🔴" if rule["severity"] == "ERROR" else "🟡"
        print(f"{severity_icon} {rule_id}: {rule['name']}")
        print(f"   Severity: {rule['severity']}")
        print(f"   {rule['description']}")
        print()


def collect_files(paths: List[str], recursive: bool) -> List[str]:
    """Collect all Python files from given paths"""
    files = []
    
    for path in paths:
        p = Path(path)
        
        if p.is_file():
            if p.suffix == ".py":
                files.append(str(p))
        elif p.is_dir():
            if recursive:
                files.extend(str(f) for f in p.rglob("*.py"))
            else:
                files.extend(str(f) for f in p.glob("*.py"))
    
    return sorted(set(files))


def main():
    parser = argparse.ArgumentParser(
        description="vibecheck - Security scanner for AI/vibe-coded Python",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vibecheck myapp.py
  vibecheck --recursive src/
  vibecheck --format json --severity error myapp.py
  vibecheck --check --min-score 80 src/  # CI mode

For more info: https://github.com/kriskimmerle/vibecheck
        """
    )
    
    parser.add_argument("paths", nargs="*", help="Files or directories to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--severity", choices=["warning", "error"], default="warning",
                        help="Minimum severity to report (default: warning)")
    parser.add_argument("--ignore", action="append", dest="ignored_rules",
                        help="Ignore specific rule ID (repeatable)")
    parser.add_argument("--check", action="store_true",
                        help="Exit with code 1 if score below threshold (CI mode)")
    parser.add_argument("--min-score", type=int, default=70,
                        help="Minimum vibe score for --check mode (default: 70)")
    parser.add_argument("--list-rules", action="store_true",
                        help="Show all available rules and exit")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="Scan directories recursively")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Only show score and errors")
    parser.add_argument("--version", action="version", version=f"vibecheck {VERSION}")

    args = parser.parse_args()

    if args.list_rules:
        list_rules()
        return 0

    # Check that paths were provided
    if not args.paths:
        parser.error("the following arguments are required: paths")

    # Collect files
    files = collect_files(args.paths, args.recursive)
    
    if not files:
        print("No Python files found", file=sys.stderr)
        return 1

    # Scan all files
    results = {
        "version": VERSION,
        "files": [],
        "vibe_score": 100,
        "grade": "A",
        "verdict": "Ship it 🚀"
    }

    all_findings = []
    
    for filepath in files:
        findings, error = scan_file(filepath)
        
        # Filter by severity
        if args.severity == "error":
            findings = [f for f in findings if f.severity == "ERROR"]
        
        # Filter by ignored rules
        if args.ignored_rules:
            findings = [f for f in findings if f.rule_id not in args.ignored_rules]
        
        results["files"].append({
            "path": filepath,
            "findings": findings,
            "error": error if error else None
        })
        
        all_findings.extend(findings)

    # Calculate overall vibe score
    score, grade, verdict = calculate_vibe_score(all_findings)
    results["vibe_score"] = score
    results["grade"] = grade
    results["verdict"] = verdict

    # Output
    if args.format == "json":
        print(format_json_output(results))
    else:
        print(format_text_output(results, args.quiet))

    # CI mode: exit 1 if below threshold
    if args.check and score < args.min_score:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
