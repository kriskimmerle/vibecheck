# ⚡ vibecheck

**AI-Generated Code Security Meta-Auditor** — one command to catch the security patterns vibe-coded projects consistently get wrong.

Research shows 24.7% of AI-generated code has security flaws, with 1.75x more logic errors and 2.74x more XSS vulnerabilities than human-written code. Instead of installing 10+ individual security tools, run `vibecheck` for a fast, focused audit of the patterns AI gets wrong most.

## What It Checks

| Rule | Category | Severity | What It Catches |
|------|----------|----------|-----------------|
| VC01 | SQL Injection | CRITICAL | f-strings/format() in SQL queries |
| VC02 | Command Injection | CRITICAL | User input in os.system(), eval(), shell commands |
| VC03 | Path Traversal | HIGH | User-controlled input in file paths |
| VC04 | XSS | HIGH | Dynamic content in HTML responses without escaping |
| VC05 | Hardcoded Secrets | CRITICAL | API keys, tokens, private keys in source |
| VC06 | Insecure Crypto | HIGH | MD5/SHA1, random for tokens, weak ciphers |
| VC07 | Missing Auth | HIGH | Sensitive routes without auth decorators |
| VC08 | Debug Mode | MEDIUM | DEBUG=True, app.run(debug=True) |
| VC09 | Unsafe Deserialization | CRITICAL | pickle.loads(), yaml.load(), eval() |
| VC10 | Error Handling | MEDIUM | Bare except, silent exception swallowing |
| VC11 | Resource Leaks | MEDIUM | open() without with statement |
| VC12 | Missing Timeouts | MEDIUM | HTTP calls without timeout= |
| VC13 | SSRF | HIGH | User input in outbound URLs |
| VC14 | Prompt Injection | HIGH | User input formatted into LLM prompts |
| VC15 | Insecure Defaults | MEDIUM | verify=False, CORS *, weak SECRET_KEY |

## Install

```bash
# Just download and run — zero dependencies
curl -O https://raw.githubusercontent.com/kriskimmerle/vibecheck/main/vibecheck.py
chmod +x vibecheck.py

# Or clone
git clone https://github.com/kriskimmerle/vibecheck.git
cd vibecheck
```

## Usage

```bash
# Scan a file
python3 vibecheck.py app.py

# Scan a project
python3 vibecheck.py src/

# Scan with fix suggestions
python3 vibecheck.py -v app.py

# CI mode — fail if grade below B
python3 vibecheck.py --check --threshold B src/

# JSON output for automation
python3 vibecheck.py --json src/

# Filter by severity
python3 vibecheck.py --severity HIGH src/

# Ignore specific rules
python3 vibecheck.py --ignore VC08 --ignore VC12 src/

# Scan from stdin
cat app.py | python3 vibecheck.py -
```

## Example Output

```
⚡ vibecheck — AI Code Security Audit
────────────────────────────────────────────────────────────
  Files scanned: 1
  Findings: 28
  Score: 0/100  Grade: F
────────────────────────────────────────────────────────────

  CRITICAL: 8
  HIGH: 9
  MEDIUM: 11

────────────────────────────────────────────────────────────
  VC01 SQL Injection: 2
  VC02 Command Injection: 2
  VC04 XSS / Unsafe Output: 2
  VC05 Hardcoded Secrets: 1
  ...

────────────────────────────────────────────────────────────

  examples/vulnerable.py
    L21   CRITICAL VC05 Possible OpenAI project key found in source code
    L31   CRITICAL VC01 SQL query variable built with string formatting
    L41   CRITICAL VC01 SQL query built with string formatting — SQL injection risk
    L82   CRITICAL VC02 os.system() with formatted string — command injection risk
    ...
```

## Why Not Just Use Bandit/Semgrep/etc.?

Those are great general-purpose tools. vibecheck is different:

- **Focused**: Only the ~15 categories AI code fails on most — not 500 generic rules
- **Fast**: Single-file AST analysis, no config files needed
- **Zero deps**: Works anywhere Python 3.9+ exists
- **AI-aware**: Checks for prompt injection, LLM-specific patterns
- **Actionable**: Every finding includes a concrete fix suggestion

Use vibecheck as a fast first pass on AI-generated code. Use Bandit/Semgrep for comprehensive audits.

## CI Integration

### GitHub Actions

```yaml
- name: Security check (vibecheck)
  run: python3 vibecheck.py --check --threshold B src/
```

### Pre-commit

```yaml
- repo: local
  hooks:
    - id: vibecheck
      name: vibecheck
      entry: python3 vibecheck.py --check
      language: system
      types: [python]
```

## JSON Output

```json
{
  "tool": "vibecheck",
  "version": "1.0.0",
  "files_scanned": 1,
  "score": 0,
  "grade": "F",
  "summary": {
    "CRITICAL": 8,
    "HIGH": 9,
    "MEDIUM": 11
  },
  "findings": [
    {
      "rule": "VC01",
      "name": "SQL Injection",
      "severity": "CRITICAL",
      "file": "app.py",
      "line": 31,
      "message": "SQL query built with string formatting — SQL injection risk",
      "fix": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = ?', (id,))"
    }
  ]
}
```

## Grading

| Grade | Score | Meaning |
|-------|-------|---------|
| A+ | 95-100 | Ship it! |
| A | 90-94 | Very good, minor issues |
| B | 80-89 | Good, some patterns to fix |
| C | 70-79 | Needs attention |
| D | 60-69 | Significant issues |
| F | 0-59 | Major security problems |

## Requirements

- Python 3.9+
- Zero external dependencies

## Research Basis

- [Replit: AI can't reliably audit its own output](https://blog.replit.com/) (2025)
- [CodeRabbit: 24.7% of AI code has security flaws](https://www.coderabbit.ai/) (2026)
- [Addy Osmani: Code Review in the Age of AI](https://addyosmani.com/) (2025)
- [Unit42: Layered SAST for AI-generated code](https://unit42.paloaltonetworks.com/) (2025)
- [OWASP: LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

## License

MIT
