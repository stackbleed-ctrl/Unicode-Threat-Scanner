# unicode-threat-scanner

**Zero-dependency Python tool to detect Unicode-based supply-chain attacks in source code.**

[![PyPI](https://img.shields.io/pypi/v/unicode-threat-scanner)](https://pypi.org/project/unicode-threat-scanner/)
[![Python](https://img.shields.io/pypi/pyversions/unicode-threat-scanner)](https://pypi.org/project/unicode-threat-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## What it detects

| Threat | Severity | CVE / Reference |
|--------|----------|-----------------|
| Bidi override controls (RLO, LRO, RLI…) | 🔴 CRITICAL | CVE-2021-42574 (Trojan Source) |
| Unbalanced bidi at EOF | 🔴 CRITICAL | CVE-2021-42574 |
| Tag-block payload encoding (U+E0000) | 🔴 CRITICAL | Glassworm steganography |
| Null bytes embedded in source | 🔴 CRITICAL | C-string / parser attack |
| Homoglyph / confusable identifiers | 🟠 HIGH | Unicode TR39 |
| NFKC normalization collisions | 🟠 HIGH | PEP 3131 shadow attack |
| Supplementary variation selector payload | 🟠 HIGH | VS17-VS256 bit-packing |
| Base variation selectors (U+FE00-FE0F) | 🟠 HIGH | 4-bit steganography |
| Invisible / zero-width characters | 🔵–🟠 | ZWSP, soft-hyphen, etc. |
| Fullwidth ASCII substitutions | 🟡 MEDIUM | U+FF01-FF5E |

---

## Install

```bash
pip install unicode-threat-scanner
```

Or run without installing:

```bash
python unicode_threat_scanner.py .
```

---

## Usage

```bash
# Scan a directory
unicode-scan /path/to/repo

# Scan a single file
unicode-scan --file src/auth.py

# CI hard-fail gate (exits 1 if any HIGH/CRITICAL found)
unicode-scan --json --min-severity HIGH . | jq '.total_findings'

# Sanitise suspicious files in-place (writes .bak backup)
unicode-scan --fix src/suspicious.py

# Preview what --fix would change without writing
unicode-scan --fix --dry-run .

# Scan only commits introduced since a git ref
unicode-scan --diff HEAD~10

# Install as a git pre-commit hook (blocks HIGH/CRITICAL on every commit)
unicode-scan --install-hook

# Refresh the confusables table from Unicode TR39
unicode-scan --update-confusables
```

### Options

```
positional:
  path                  Directory to scan (default: .)

optional:
  --file FILE           Scan a single file
  --json                Emit JSON output (for CI/SIEM ingestion)
  --min-severity LEVEL  LOW | MEDIUM | HIGH | CRITICAL  (default: LOW)
  --fix                 Sanitise file(s) in-place
  --dry-run             Show what --fix would change without writing
  --diff GIT_REF        Scan new threats introduced since GIT_REF
  --install-hook        Add a pre-commit hook to the current git repo
  --update-confusables  Fetch latest Unicode TR39 confusables.txt
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Clean — no findings above threshold |
| `1`  | Threats found above threshold |
| `2`  | Tool/invocation error |

---

## CI/CD integration

### GitHub Actions

```yaml
- name: Unicode threat scan
  run: |
    pip install unicode-threat-scanner
    unicode-scan --json --min-severity HIGH . > scan.json
    python -c "
    import json, sys
    d = json.load(open('scan.json'))
    if d['total_findings']:
        print(f\"BLOCKED: {d['total_findings']} threat(s)\")
        sys.exit(1)
    "
```

### Pre-commit (automatic)

```bash
unicode-scan --install-hook   # run once in your repo root
```

This installs `.git/hooks/pre-commit` that blocks commits introducing
HIGH or CRITICAL threats. Bypass with `git commit --no-verify`.

### JSON output for SIEM

```json
{
  "root": "/repo",
  "files_scanned": 142,
  "total_findings": 3,
  "severity_counts": { "CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0 },
  "files": {
    "src/auth.py": [
      {
        "line": 42,
        "col": 7,
        "category": "bidi",
        "severity": "CRITICAL",
        "detail": "RLO (Right-to-Left Override) [opener]",
        "visible_context": "□# access granted□",
        "payload_hint": null,
        "bidi_depth": 1
      }
    ]
  }
}
```

---

## The --fix sanitiser

Runs 8 ordered removal passes:

1. **Null bytes** — raw-bytes layer before decode
2. **Bidi controls** — all 12 directional control codepoints
3. **Tag-block payload chars** — U+E0000-E007F (decodes and reports hidden message)
4. **Supplementary VS payload** — U+E0100-E01EF
5. **Base variation selectors** — U+FE00-FE0F, U+180B-180E
6. **Remaining invisible/format chars** — ZWSP, soft-hyphen, word-joiner, etc.
7. **Fullwidth ASCII** — replaces U+FF01-FF5E with narrow ASCII equivalents
8. **Confusable identifiers** — replaces with ASCII skeleton via Unicode TR39 map

A `.bak` backup is always written before any file is modified.

---

## Keeping confusables current

The static table ships ~300 high-signal Cyrillic/Greek/math/fullwidth mappings.
Pull the full Unicode TR39 table (~7 000 entries) and cache it locally:

```bash
unicode-scan --update-confusables
# Cached to ~/.cache/unicode_threat_scanner/confusables.json
```

The cached table is merged at startup; static entries always win on conflicts.

---

## Comparison

| Feature | **unicode-threat-scanner** | anti-trojan-source | confusable-homoglyphs |
|---------|---------------------------|--------------------|-----------------------|
| Bidi depth tracking + EOF check | ✅ | Partial | ❌ |
| Tag-block payload decode | ✅ | ❌ | ❌ |
| Variation-selector steganography | ✅ | ❌ | ❌ |
| Null byte detection | ✅ | ❌ | ❌ |
| NFKC collision detection | ✅ | ❌ | ❌ |
| Severity tiers | ✅ | ❌ | ❌ |
| Doc-file false-positive reduction | ✅ | ❌ | ❌ |
| In-place sanitiser (`--fix`) | ✅ | ❌ | ❌ |
| Git diff / new-threat-only scan | ✅ | ❌ | ❌ |
| Pre-commit hook installer | ✅ | Separate plugin | ❌ |
| JSON output for CI/SIEM | ✅ | ✅ | ❌ |
| Zero runtime dependencies | ✅ | ❌ (npm) | ❌ |

---

## License

MIT
