# Changelog

## 1.0.0 — Initial release

### Detection
- Bidi controls with whole-file stack tracking and EOF unbalanced check (CVE-2021-42574)
- Invisible/zero-width character sequences with Glassworm tag-block payload decoding
- Variation-selector steganography (U+FE00-FE0F base, U+E0100-E01EF supplementary)
- Null bytes detected at raw-bytes layer before UTF-8 decode
- Homoglyph/confusable identifiers (~300 static mappings; full TR39 via --update-confusables)
- NFKC normalization collision detection
- Fullwidth ASCII substitutions (U+FF01-FF5E)
- Context-aware severity: doc files (.md/.rst/.txt) reduce severity of ambiguous findings

### Sanitiser (`--fix`)
- 8-pass ordered removal: null bytes, bidi, tag-block, supp. VS, base VS,
  invisible chars, fullwidth ASCII, confusable identifiers
- Decodes and reports hidden tag-block payload before removing
- Always writes `.bak` backup before modifying

### Workflow
- `--diff GIT_REF`: scan only newly introduced threats vs a git ref
- `--install-hook`: install POSIX pre-commit hook, appends safely to existing hooks
- `--update-confusables`: fetch and cache latest Unicode TR39 confusables.txt
- `--json`: structured JSON output for CI/SIEM ingestion
- `--min-severity`: filter findings by tier (LOW/MEDIUM/HIGH/CRITICAL)

### Runtime
- Zero dependencies (stdlib only)
- Python 3.9+
- 10 MB file size cap in both scanner and sanitiser
- Skips: .git, node_modules, __pycache__, .venv, dist, build, vendor, .cargo
