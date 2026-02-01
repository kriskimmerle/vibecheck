# vibecheck 🔍

**Security scanner for AI/vibe-coded Python**

Detects security anti-patterns commonly produced by AI code generators (ChatGPT, Copilot, Claude, Cursor, etc.)

## The Problem

"Vibe coding" — writing code via AI prompts — is increasingly common. But AI code generators have dangerous tendencies:

- 📋 **They copy-paste vulnerabilities** across multiple functions
- 🔑 **They love placeholder credentials** ("your-api-key-here", "sk-xxxx")  
- 🐛 **They skip error handling** (only the "happy path")
- 🔓 **They use insecure defaults** (debug=True, verify=False)
- 🎲 **They confuse `random` with `secrets`** for security contexts
- 💉 **They generate SQL injection** with f-strings
- 🧂 **They use weak hashing** (MD5/SHA1 for passwords)

**Research findings:**
- Palo Alto Unit 42 found **69 vulnerabilities across 15 AI-generated apps** [source needed]
- arXiv 2512.03262: ["Is Vibe Coding Safe?"](https://arxiv.org/abs/2512.03262) benchmarks security risks
- OWASP warns about blindly trusting AI-generated code

**Existing tools like Bandit and Semgrep catch generic issues.** `vibecheck` is calibrated specifically for patterns AI tends to produce.

## Installation

Zero dependencies. Just Python 3.8+.

```bash
# Download
curl -o vibecheck.py https://raw.githubusercontent.com/kriskimmerle/vibecheck/main/vibecheck.py
chmod +x vibecheck.py

# Or clone
git clone https://github.com/kriskimmerle/vibecheck.git
cd vibecheck
```

## Usage

```bash
# Scan a file
./vibecheck.py myapp.py

# Scan a directory recursively
./vibecheck.py --recursive src/

# JSON output
./vibecheck.py --format json myapp.py

# CI mode: exit 1 if score below 80
./vibecheck.py --check --min-score 80 src/

# Show only errors, skip warnings
./vibecheck.py --severity error myapp.py

# Ignore specific rules
./vibecheck.py --ignore VC005 --ignore VC007 myapp.py
```

## The Vibe Score

Every scan produces a **Vibe Score** (0-100):
- Start at 100
- Each ERROR: -10 points  
- Each WARNING: -5 points

**Grades:**
- 90-100: **Ship it 🚀**
- 70-89: **Review before deploying 🔍**  
- 50-69: **Needs security hardening ⚠️**
- 0-49: **Do not deploy 🛑**

## Detection Rules

`vibecheck` implements 15 rules targeting AI-coded patterns:

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| VC001 | Placeholder credentials | ERROR | Detects "your-api-key-here", "sk-xxxx", "TODO: replace", etc. |
| VC002 | Insecure defaults left in | ERROR | debug=True, SECRET_KEY="secret", verify=False |
| VC003 | Insecure random for security | ERROR | Using `random` instead of `secrets` for tokens/passwords |
| VC004 | Unsafe deserialization | ERROR | pickle.loads(), yaml.load(), eval() on user data |
| VC005 | Hardcoded URLs/endpoints | WARNING | API endpoints as string literals instead of config |
| VC006 | Missing error handling | WARNING | Network/IO operations without try/except |
| VC007 | Deprecated library usage | WARNING | urllib2, optparse, imp, cgi, md5, sha |
| VC008 | SQL string formatting | ERROR | SQL with f-strings/.format() instead of parameters |
| VC009 | Weak hashing | ERROR | MD5/SHA1 for password hashing |
| VC010 | Unrestricted file operations | WARNING | open()/os.remove() with user-controlled paths |
| VC011 | Repeated vulnerability pattern | WARNING | Same issue 3+ times (AI copy-paste) |
| VC012 | Missing input validation | WARNING | Flask/FastAPI using request.json without validation |
| VC013 | Subprocess with shell=True | ERROR | Shell injection risk |
| VC014 | Broad exception suppression | WARNING | `except: pass` silently swallows errors |
| VC015 | Insecure temp files | WARNING | tempfile.mktemp() race condition |

### See all rules
```bash
./vibecheck.py --list-rules
```

## Example Output

```
vibecheck v1.0.0
============================================================

⚠️  examples/vibe_coded.py
   🔴 Line 12:7 [VC007] Deprecated module 'optparse': Use argparse instead
   🔴 Line 32:0 [VC001] Placeholder credential detected: 'your-api-key-here'
   🔴 Line 55:4 [VC003] Using random.choice for security - use secrets module
   🔴 Line 78:11 [VC008] SQL query in f-string - use parameterized queries
   🟡 Line 102:8 [VC006] Function 'fetch_user_data' has network/IO operations but no try/except
   ...

============================================================
Vibe Score: 15/100 (Grade: F)
Verdict: Do not deploy 🛑

Files scanned: 1
Issues found: 42
  🔴 Errors: 28
  🟡 Warnings: 14
```

## CI Integration

Exit with code 1 if score is below threshold:

```yaml
# .github/workflows/security.yml
- name: Vibe Check
  run: |
    curl -o vibecheck.py https://raw.githubusercontent.com/kriskimmerle/vibecheck/main/vibecheck.py
    python vibecheck.py --check --min-score 70 --recursive src/
```

## How It Works

`vibecheck` uses Python's AST (Abstract Syntax Tree) module to parse and analyze code:
- **Zero dependencies** - stdlib only
- **Pattern matching** on AST nodes for suspicious constructs
- **Context-aware** - distinguishes `random` for games vs. security
- **Heuristics** - detects repeated patterns (AI copy-paste indicator)

It does NOT:
- Execute your code
- Send code anywhere (fully offline)
- Require any configuration

## Why Not Just Use Bandit/Semgrep?

Great tools! But they're not tuned for AI-generated code:

| Tool | Focus | AI-Specific Patterns |
|------|-------|---------------------|
| Bandit | General Python security | ❌ |
| Semgrep | Multi-language patterns | ❌ |
| **vibecheck** | AI vibe-coded anti-patterns | ✅ |

Use `vibecheck` **alongside** Bandit/Semgrep for comprehensive coverage.

## Examples

See `examples/` directory:
- `vibe_coded.py` - Typical AI-generated code (triggers all rules, Vibe Score ~15)
- `secure_app.py` - Well-written code (Vibe Score 95+)

```bash
./vibecheck.py examples/vibe_coded.py
./vibecheck.py examples/secure_app.py
```

## False Positives?

AI patterns overlap with human mistakes. That's fine! If `vibecheck` flags it, it's worth reviewing.

Ignore specific rules if needed:
```bash
./vibecheck.py --ignore VC005 myapp.py  # Skip hardcoded URL warnings
```

## Contributing

Ideas for more AI-coded anti-patterns? Open an issue or PR!

Potential additions:
- Overly broad `import *`
- Missing type hints (AI rarely adds them)
- Inconsistent error handling styles
- Unusually repetitive code structure

## References

- [Palo Alto Unit 42: AI-Generated Code Vulnerabilities](#) (placeholder link)
- [arXiv 2512.03262: "Is Vibe Coding Safe?"](https://arxiv.org/abs/2512.03262)
- [OWASP: AI-Assisted Coding Risks](https://owasp.org)
- [The discourse on "vibe coding"](#) (Twitter/HN threads)

## License

MIT License - see [LICENSE](LICENSE)

## Author

Built by [@kriskimmerle](https://github.com/kriskimmerle)

**Ship responsibly. Check the vibes.** ✨
