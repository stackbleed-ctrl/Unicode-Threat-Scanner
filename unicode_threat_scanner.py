#!/usr/bin/env python3
"""
unicode_threat_scanner.py — Comprehensive Unicode threat detector for source-code repositories.

Detects:
  ▸ Invisible / zero-width characters     (steganography, hidden logic injection)
  ▸ Bidi control characters               (Trojan Source CVE-2021-42574 & variants)
  ▸ Homoglyphs / confusable identifiers   (supply-chain IDN-style spoofing)
  ▸ Tag-character payload encoding        (Glassworm / U+E0000 steganography)
  ▸ Variation-selector steganography      (U+FE00-FE0F / U+180B-180D bit-packing)
  ▸ Null bytes embedded in source         (C-string truncation, parser confusion)
  ▸ Fullwidth ASCII substitutions         (U+FF01-U+FF5E)
  ▸ NFKC normalization collisions         (identifier shadowing across runtimes)
  ▸ Mixed-script identifiers              (Latin + Cyrillic/Greek/Armenian blend)

Usage:
  python unicode_threat_scanner.py [path]                    # scan directory
  python unicode_threat_scanner.py --file foo.py             # scan single file
  python unicode_threat_scanner.py --json                    # CI-friendly JSON output
  python unicode_threat_scanner.py --min-severity HIGH       # filter noise
  python unicode_threat_scanner.py --fix foo.py              # sanitise file in-place
  python unicode_threat_scanner.py --diff HEAD~5             # scan git history range
  python unicode_threat_scanner.py --install-hook            # install pre-commit hook
  python unicode_threat_scanner.py --update-confusables      # pull latest Unicode TR39

Exit codes:
  0  clean   |  1  findings above threshold   |  2  tool/invocation error
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import urllib.request
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# ==============================================================================
# 1.  SEVERITY
# ==============================================================================

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"

_SEV_RANK: Dict[Severity, int] = {
    Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1,
}
_SEV_ICON: Dict[str, str] = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵",
}

# ==============================================================================
# 2.  INVISIBLE / FORMAT CHARACTER DETECTION
# ==============================================================================

_INVISIBLE_CATS: FrozenSet[str] = frozenset({'Cf', 'Cc', 'Cs', 'Co'})

_INVISIBLE_CPS: FrozenSet[int] = frozenset({
    0x00, 0xAD, 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5,
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF,
    0x2061, 0x2062, 0x2063, 0x2064,
    0x3164, 0xFFA0,
    *range(0x180B, 0x180F),
    *range(0x200B, 0x200F),
    *range(0x206A, 0x2070),
    *range(0xFE00, 0xFE10),
    *range(0xFE20, 0xFE30),
    *range(0xE0000, 0xE0080),
    *range(0xE0100, 0xE01F0),
})

_INVIS_NAME_FRAGS: FrozenSet[str] = frozenset({
    'ZERO WIDTH', 'SOFT HYPHEN', 'WORD JOINER', 'INVISIBLE TIMES',
    'INVISIBLE SEPARATOR', 'INVISIBLE PLUS', 'FUNCTION APPLICATION',
    'OBJECT REPLACEMENT', 'REPLACEMENT CHARACTER',
})

# File-type context: doc files get lower severity on ambiguous invisible chars
_DOC_EXTS:  FrozenSet[str] = frozenset({'.md', '.rst', '.txt', '.adoc', '.wiki', '.tex'})

def is_invisible(c: str) -> bool:
    cp = ord(c)
    if cp in _INVISIBLE_CPS:
        return True
    cat = unicodedata.category(c)
    if cat in _INVISIBLE_CATS and cp > 0x20:
        return True
    return any(frag in unicodedata.name(c, '') for frag in _INVIS_NAME_FRAGS)

def invisible_severity(seq: str, in_code_ctx: bool, file_is_doc: bool) -> Severity:
    """Rate a run of invisible chars; doc files reduce severity of ambiguous cases."""
    for c in seq:
        cp = ord(c)
        if 0xE0000 <= cp < 0xE0080 or 0xE0100 <= cp < 0xE01F0:
            return Severity.CRITICAL          # tag-block / supplementary VS
        if cp == 0x00:
            return Severity.CRITICAL          # null byte — always critical
        if 0xFE00 <= cp < 0xFE10 or 0x180B <= cp < 0x180F:
            return Severity.HIGH if not file_is_doc else Severity.MEDIUM
    if len(seq) > 6:
        return Severity.HIGH if in_code_ctx else (Severity.LOW if file_is_doc else Severity.MEDIUM)
    if len(seq) > 1:
        return Severity.MEDIUM if in_code_ctx else Severity.LOW
    return Severity.LOW

# ==============================================================================
# 3.  BIDI CONTROLS
# ==============================================================================

_BIDI_OPENERS: FrozenSet[int] = frozenset({0x202A, 0x202B, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068})
_BIDI_CLOSERS: FrozenSet[int] = frozenset({0x202C, 0x2069})
_HIGH_RISK_BIDI: FrozenSet[int] = frozenset({0x202D, 0x202E, 0x2067})   # LRO, RLO, RLI

_BIDI_META: Dict[int, Tuple[str, str]] = {
    0x202A: ('LRE', 'Left-to-Right Embedding'),
    0x202B: ('RLE', 'Right-to-Left Embedding'),
    0x202C: ('PDF', 'Pop Directional Formatting'),
    0x202D: ('LRO', 'Left-to-Right Override'),
    0x202E: ('RLO', 'Right-to-Left Override'),
    0x2066: ('LRI', 'Left-to-Right Isolate'),
    0x2067: ('RLI', 'Right-to-Left Isolate'),
    0x2068: ('FSI', 'First Strong Isolate'),
    0x2069: ('PDI', 'Pop Directional Isolate'),
    0x200E: ('LRM', 'Left-to-Right Mark'),
    0x200F: ('RLM', 'Right-to-Left Mark'),
    0x061C: ('ALM', 'Arabic Letter Mark'),
}

def get_bidi_info(c: str) -> Optional[Tuple[str, str, str]]:
    """Return (name, description, category) or None."""
    cp = ord(c)
    if cp not in _BIDI_META:
        return None
    name, desc = _BIDI_META[cp]
    cat = ('opener' if cp in _BIDI_OPENERS
           else 'closer' if cp in _BIDI_CLOSERS
           else 'mark')
    return name, desc, cat

def bidi_severity(cp: int, in_code_ctx: bool, file_is_doc: bool) -> Severity:
    if cp in _HIGH_RISK_BIDI:
        return Severity.CRITICAL
    if cp in _BIDI_OPENERS:
        return Severity.HIGH if in_code_ctx else (Severity.LOW if file_is_doc else Severity.MEDIUM)
    return Severity.MEDIUM if not file_is_doc else Severity.LOW

# ==============================================================================
# 4.  CONFUSABLES
#     Static table covers ~300 high-signal mappings.
#     Run --update-confusables to pull the full Unicode TR39 table.
# ==============================================================================

_CONFUSABLES_CACHE: Path = Path.home() / '.cache' / 'unicode_threat_scanner' / 'confusables.json'

_STATIC_CONFUSABLES: Dict[str, str] = {
    # Cyrillic -> Latin
    '\u0430': 'a', '\u0410': 'A', '\u0435': 'e', '\u0415': 'E',
    '\u043E': 'o', '\u041E': 'O', '\u0440': 'p', '\u0420': 'P',
    '\u0441': 'c', '\u0421': 'C', '\u0443': 'y', '\u0423': 'Y',
    '\u0456': 'i', '\u0406': 'I', '\u0458': 'j', '\u0455': 's', '\u0405': 'S',
    '\u0445': 'x', '\u0425': 'X', '\u0412': 'B', '\u041A': 'K',
    '\u041C': 'M', '\u041D': 'H', '\u0422': 'T',
    '\u0504': 'd', '\u0505': 'd', '\u0475': 'v', '\u044C': 'b', '\u042C': 'b',
    # Greek -> Latin
    '\u03BD': 'v', '\u03BC': 'u', '\u03BA': 'k', '\u03BF': 'o', '\u039F': 'O',
    '\u03C1': 'p', '\u03C5': 'u', '\u03C9': 'w', '\u0391': 'A', '\u0392': 'B',
    '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H', '\u0399': 'I', '\u039A': 'K',
    '\u039C': 'M', '\u039D': 'N', '\u03A4': 'T', '\u03A5': 'Y', '\u03A7': 'X',
    '\u03B9': 'i', '\u03C7': 'x', '\u03F2': 'c', '\u03F3': 'j',
    '\u03F1': 'p', '\u03F9': 'C',
    # Armenian -> Latin
    '\u0561': 'u', '\u0585': 'o', '\u0578': 'n', '\u057D': 'u',
    # Hebrew look-alikes
    '\u05D5': 'l', '\u05D7': 'n',
    # Mathematical bold lowercase a-z
    '\U0001D41A': 'a', '\U0001D41B': 'b', '\U0001D41C': 'c', '\U0001D41D': 'd',
    '\U0001D41E': 'e', '\U0001D41F': 'f', '\U0001D420': 'g', '\U0001D421': 'h',
    '\U0001D422': 'i', '\U0001D423': 'j', '\U0001D424': 'k', '\U0001D425': 'l',
    '\U0001D426': 'm', '\U0001D427': 'n', '\U0001D428': 'o', '\U0001D429': 'p',
    '\U0001D42A': 'q', '\U0001D42B': 'r', '\U0001D42C': 's', '\U0001D42D': 't',
    '\U0001D42E': 'u', '\U0001D42F': 'v', '\U0001D430': 'w', '\U0001D431': 'x',
    '\U0001D432': 'y', '\U0001D433': 'z',
    # Mathematical bold uppercase A-Z
    '\U0001D400': 'A', '\U0001D401': 'B', '\U0001D402': 'C', '\U0001D403': 'D',
    '\U0001D404': 'E', '\U0001D405': 'F', '\U0001D406': 'G', '\U0001D407': 'H',
    '\U0001D408': 'I', '\U0001D409': 'J', '\U0001D40A': 'K', '\U0001D40B': 'L',
    '\U0001D40C': 'M', '\U0001D40D': 'N', '\U0001D40E': 'O', '\U0001D40F': 'P',
    '\U0001D410': 'Q', '\U0001D411': 'R', '\U0001D412': 'S', '\U0001D413': 'T',
    '\U0001D414': 'U', '\U0001D415': 'V', '\U0001D416': 'W', '\U0001D417': 'X',
    '\U0001D418': 'Y', '\U0001D419': 'Z',
    # Mathematical italic lowercase
    '\U0001D44E': 'a', '\U0001D44F': 'b', '\U0001D450': 'c', '\U0001D451': 'd',
    '\U0001D452': 'e', '\U0001D453': 'f', '\U0001D454': 'g', '\U0001D456': 'i',
    '\U0001D457': 'j', '\U0001D458': 'k', '\U0001D459': 'l', '\U0001D45A': 'm',
    '\U0001D45B': 'n', '\U0001D45C': 'o', '\U0001D45D': 'p', '\U0001D45E': 'q',
    '\U0001D45F': 'r', '\U0001D460': 's', '\U0001D461': 't', '\U0001D462': 'u',
    '\U0001D463': 'v', '\U0001D464': 'w', '\U0001D465': 'x', '\U0001D466': 'y',
    '\U0001D467': 'z',
    # Double-struck lowercase
    '\U0001D552': 'a', '\U0001D553': 'b', '\U0001D554': 'c', '\U0001D555': 'd',
    '\U0001D556': 'e', '\U0001D557': 'f', '\U0001D558': 'g', '\U0001D559': 'h',
    '\U0001D55A': 'i', '\U0001D55B': 'j', '\U0001D55C': 'k', '\U0001D55D': 'l',
    '\U0001D55E': 'm', '\U0001D55F': 'n', '\U0001D560': 'o', '\U0001D561': 'p',
    '\U0001D562': 'q', '\U0001D563': 'r', '\U0001D564': 's', '\U0001D565': 't',
    '\U0001D566': 'u', '\U0001D567': 'v', '\U0001D568': 'w', '\U0001D569': 'x',
    '\U0001D56A': 'y', '\U0001D56B': 'z',
    # Double-struck uppercase (selected)
    '\U0001D538': 'A', '\U0001D539': 'B', '\U0001D53B': 'D', '\U0001D53C': 'E',
    '\U0001D53D': 'F', '\U0001D53E': 'G', '\U0001D540': 'I', '\U0001D541': 'J',
    '\U0001D542': 'K', '\U0001D543': 'L', '\U0001D544': 'M', '\U0001D546': 'O',
    '\U0001D54A': 'S', '\U0001D54B': 'T', '\U0001D54C': 'U', '\U0001D54D': 'V',
    '\U0001D54E': 'W', '\U0001D54F': 'X', '\U0001D550': 'Y',
    # Mathematical bold digits
    '\U0001D7CE': '0', '\U0001D7CF': '1', '\U0001D7D0': '2', '\U0001D7D1': '3',
    '\U0001D7D2': '4', '\U0001D7D3': '5', '\U0001D7D4': '6', '\U0001D7D5': '7',
    '\U0001D7D6': '8', '\U0001D7D7': '9',
    # Double-struck digits
    '\U0001D7D8': '0', '\U0001D7D9': '1', '\U0001D7DA': '2', '\U0001D7DB': '3',
    '\U0001D7DC': '4', '\U0001D7DD': '5', '\U0001D7DE': '6', '\U0001D7DF': '7',
    '\U0001D7E0': '8', '\U0001D7E1': '9',
    # Fullwidth ASCII (U+FF01..U+FF5E -> U+0021..U+007E)
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
    # Fullwidth digits
    '\uFF10': '0', '\uFF11': '1', '\uFF12': '2', '\uFF13': '3', '\uFF14': '4',
    '\uFF15': '5', '\uFF16': '6', '\uFF17': '7', '\uFF18': '8', '\uFF19': '9',
    # Letterlike symbols
    '\u2113': 'l', '\u2110': 'I', '\u2111': 'I', '\u2112': 'L',
    '\u2115': 'N', '\u2119': 'P', '\u211A': 'Q', '\u211D': 'R', '\u2124': 'Z',
    '\u212F': 'e', '\u210A': 'g', '\u210B': 'H', '\u210C': 'H',
    '\u210D': 'H', '\u210E': 'h', '\u210F': 'h',
    # Smallcaps / phonetic
    '\u0299': 'b', '\u029C': 'h', '\u026A': 'i', '\u1D0B': 'k',
    '\u029F': 'l', '\u1D0D': 'm', '\u0274': 'n', '\u1D18': 'p',
    '\u0280': 'r', '\uA731': 's', '\u1D1B': 't', '\u1D20': 'v',
    '\u1D21': 'w', '\u028F': 'y', '\u1D22': 'z',
    '\u0251': 'a', '\u0261': 'g', '\u0269': 'i',
    # Circled letters
    '\u24D0': 'a', '\u24D1': 'b', '\u24D2': 'c', '\u24D3': 'd', '\u24D4': 'e',
    '\u24D5': 'f', '\u24D6': 'g', '\u24D7': 'h', '\u24D8': 'i', '\u24D9': 'j',
    '\u24DA': 'k', '\u24DB': 'l', '\u24DC': 'm', '\u24DD': 'n', '\u24DE': 'o',
    '\u24DF': 'p', '\u24E0': 'q', '\u24E1': 'r', '\u24E2': 's', '\u24E3': 't',
    '\u24E4': 'u', '\u24E5': 'v', '\u24E6': 'w', '\u24E7': 'x', '\u24E8': 'y',
    '\u24E9': 'z',
    # Misc
    '\u01C0': '|', '\uFF5C': '|', '\u2016': '|', '\u0131': 'i',
    '\u0251': 'a', '\u0261': 'g', '\u0269': 'i',
    # Latin diacritics (typosquatting)
    '\u00E4': 'a', '\u00E0': 'a', '\u00E1': 'a', '\u00E2': 'a', '\u00E3': 'a',
    '\u00E5': 'a', '\u0101': 'a',
    '\u00EB': 'e', '\u00E8': 'e', '\u00E9': 'e', '\u00EA': 'e', '\u0113': 'e',
    '\u00EF': 'i', '\u00EC': 'i', '\u00ED': 'i', '\u00EE': 'i', '\u012B': 'i',
    '\u00F6': 'o', '\u00F2': 'o', '\u00F3': 'o', '\u00F4': 'o', '\u00F5': 'o',
    '\u00F8': 'o', '\u014D': 'o',
    '\u00FC': 'u', '\u00F9': 'u', '\u00FA': 'u', '\u00FB': 'u', '\u016B': 'u',
    '\u00F1': 'n', '\u0144': 'n',
    '\u00FD': 'y', '\u00FF': 'y',
    '\u0107': 'c', '\u010D': 'c', '\u00E7': 'c',
    '\u015B': 's', '\u0161': 's',
    '\u017A': 'z', '\u017C': 'z', '\u017E': 'z',
}


def _load_confusables() -> Dict[str, str]:
    """Merge cached TR39 data with static table. Static entries always win."""
    merged: Dict[str, str] = dict(_STATIC_CONFUSABLES)
    if _CONFUSABLES_CACHE.exists():
        try:
            cached: Dict[str, str] = json.loads(_CONFUSABLES_CACHE.read_text('utf-8'))
            for k, v in cached.items():
                merged.setdefault(k, v)
        except Exception:
            pass
    return merged


def update_confusables(verbose: bool = True) -> int:
    """
    Fetch latest Unicode TR39 confusables.txt and cache as JSON.
    Maps single-char non-ASCII sources to single-char ASCII targets only.
    Returns count of new entries beyond the static table.
    """
    url = 'https://www.unicode.org/Public/security/latest/confusables.txt'
    if verbose:
        print(f'Fetching {url} ...')
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            raw_text = resp.read().decode('utf-8-sig', errors='replace')
    except Exception as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 0

    new_map: Dict[str, str] = {}
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(';')
        if len(parts) < 2:
            continue
        src_hex = parts[0].strip().split()
        tgt_hex = parts[1].strip().split()
        if len(src_hex) != 1 or len(tgt_hex) != 1:
            continue
        try:
            src_c = chr(int(src_hex[0], 16))
            tgt_c = chr(int(tgt_hex[0], 16))
        except ValueError:
            continue
        if src_c.isascii() or not tgt_c.isascii():
            continue
        new_map[src_c] = tgt_c

    _CONFUSABLES_CACHE.parent.mkdir(parents=True, exist_ok=True)
    _CONFUSABLES_CACHE.write_text(json.dumps(new_map, ensure_ascii=False, indent=2), 'utf-8')

    added = len(set(new_map) - set(_STATIC_CONFUSABLES))
    if verbose:
        print(f'Cached {len(new_map)} entries ({added} new beyond static table)')
        print(f'Saved to: {_CONFUSABLES_CACHE}')
    return added


# Build runtime table at import
CONFUSABLES: Dict[str, str] = _load_confusables()
_CONFUSABLE_SET: FrozenSet[str] = frozenset(CONFUSABLES.keys())


def to_skeleton(s: str) -> str:
    return ''.join(CONFUSABLES.get(c, c) for c in s)

def nfkc_skeleton(s: str) -> str:
    return to_skeleton(unicodedata.normalize('NFKC', s))

def confusable_details(s: str) -> List[Tuple[str, str, int]]:
    return [(c, CONFUSABLES[c], i) for i, c in enumerate(s) if c in _CONFUSABLE_SET]


# ==============================================================================
# 5.  PAYLOAD EXTRACTION
# ==============================================================================

def try_extract_payload(seq: str) -> Optional[str]:
    if not seq:
        return None
    cps = [ord(c) for c in seq]

    tag_chars = [c for c in seq if 0xE0000 <= ord(c) < 0xE0080]
    if tag_chars:
        decoded = ''.join(chr(ord(c) - 0xE0000) for c in tag_chars).strip()
        return f"[TAG-BLOCK] decoded: {decoded!r}" if decoded else "[TAG-BLOCK] empty tag sequence"

    vs_ext = [c for c in seq if 0xE0100 <= ord(c) < 0xE01F0]
    if vs_ext:
        bits = [ord(c) - 0xE0100 for c in vs_ext]
        return f"[SUPP.VS] {len(vs_ext)} selectors, values: {bits[:16]}"

    base_vs = [c for c in seq if 0xFE00 <= ord(c) < 0xFE10 or 0x180B <= ord(c) < 0x180F]
    if len(base_vs) >= 4:
        nibbles = [ord(c) & 0xF for c in base_vs]
        return f"[BASE-VS] {len(base_vs)} selectors, nibbles: {nibbles[:16]}"

    if cps.count(0x00):
        return f"[NULL] {cps.count(0x00)} x \\x00 -- C-string or parser attack"

    if len(seq) >= 4:
        try:
            decoded = bytes(cp & 0xFF for cp in cps).decode('utf-8', errors='ignore').strip()
            if len(decoded) > 4 and any(ch.isalnum() for ch in decoded):
                return f"[UTF-8 GUESS] {decoded!r}"
        except Exception:
            pass

    if len(seq) >= 2:
        dump = ' '.join(f'U+{cp:04X}' for cp in cps[:24])
        return f"[INVIS SEQ] {len(seq)} chars: {dump}{'...' if len(seq) > 24 else ''}"
    return None


# ==============================================================================
# 6.  FINDING DATACLASS
# ==============================================================================

@dataclass
class Finding:
    line:            object    # int or 'EOF'
    col:             int
    category:        str
    severity:        Severity
    detail:          str
    visible_context: str = ''
    raw_chars:       str = ''
    payload_hint:    Optional[str] = None
    bidi_depth:      int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d['severity'] = self.severity.value
        return d

    def icon(self) -> str:
        return _SEV_ICON[self.severity.value]


# ==============================================================================
# 7.  FILE SCANNER
# ==============================================================================

MAX_FILE_BYTES = 10 * 1024 * 1024

_CODE_CTX_RE = re.compile(
    r'\b(eval|exec|compile|__import__|importlib|subprocess|os\.system|'
    r'ctypes|socket|requests|urllib|fetch|require|dynamic_import|'
    r'getattr|setattr|globals|locals|__builtins__|open)\s*[(\[]',
    re.IGNORECASE,
)

_IDENT_RE = re.compile(r'\b[^\W\d]\w{2,}\b', re.UNICODE)

_SKIP_DIRS: FrozenSet[str] = frozenset({
    '.git', 'node_modules', '__pycache__', '.venv', 'venv', 'env',
    '.tox', '.eggs', 'dist', 'build', '.mypy_cache', '.pytest_cache',
    'vendor', 'third_party', '.cargo',
})

SCAN_EXTENSIONS: FrozenSet[str] = frozenset({
    '.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
    '.rb', '.php', '.pl', '.pm', '.lua', '.r',
    '.c', '.cpp', '.h', '.hpp', '.cc', '.cxx', '.go', '.rs', '.cs',
    '.java', '.kt', '.swift',
    '.sh', '.bash', '.zsh', '.fish', '.ps1',
    '.json', '.yaml', '.yml', '.toml', '.cfg', '.ini', '.env',
    '.xml', '.html', '.htm', '.md', '.txt', '.rst',
    '.tf', '.hcl', '.sol',
})

def _safe_snippet(line: str, center_col: int, width: int = 60) -> str:
    half  = width // 2
    start = max(0, center_col - half)
    end   = min(len(line), center_col + half)
    return ''.join(
        c if (c.isprintable() and not is_invisible(c)) else '\u25a1'
        for c in line[start:end]
    )


def scan_file(path: Path) -> List[Finding]:
    findings: List[Finding] = []
    file_is_doc = path.suffix.lower() in _DOC_EXTS

    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return findings
        raw = path.read_bytes()
    except Exception:
        return findings

    # -- Null byte check (raw bytes -- not lossy decode) -----------------------
    if b'\x00' in raw:
        count  = raw.count(b'\x00')
        offset = raw.index(b'\x00')
        nline  = raw[:offset].count(b'\n') + 1
        ncol   = offset - raw[:offset].rfind(b'\n') - 1
        findings.append(Finding(
            line=nline, col=max(0, ncol),
            category='null',
            severity=Severity.CRITICAL,
            detail=f"Embedded null bytes ({count} total) -- C-string truncation / parser attack",
            raw_chars='\x00',
            payload_hint=f"[NULL] {count} x \\x00",
        ))

    try:
        text = raw.decode('utf-8', errors='replace')
    except Exception:
        return findings

    lines = text.splitlines(keepends=False)
    bidi_stack: List[Tuple[int, str, int]] = []

    for line_num, line in enumerate(lines, 1):
        in_code_ctx = bool(_CODE_CTX_RE.search(line))
        pos = 0

        while pos < len(line):
            c  = line[pos]
            cp = ord(c)

            # Bidi FIRST (bidi controls are Cf, so must beat is_invisible)
            bidi = get_bidi_info(c)
            if bidi:
                name, desc, cat = bidi
                sev = bidi_severity(cp, in_code_ctx, file_is_doc)
                if cp in _BIDI_OPENERS:
                    bidi_stack.append((cp, name, line_num))
                elif cp in _BIDI_CLOSERS and bidi_stack:
                    bidi_stack.pop()
                findings.append(Finding(
                    line=line_num, col=pos + 1,
                    category='bidi',
                    severity=sev,
                    detail=f"{name} ({desc}) [{cat}]",
                    visible_context=_safe_snippet(line, pos),
                    raw_chars=c,
                    bidi_depth=len(bidi_stack),
                ))
                pos += 1
                continue

            # Invisible run
            if is_invisible(c):
                start = pos
                run: List[str] = []
                while pos < len(line) and is_invisible(line[pos]) and not get_bidi_info(line[pos]):
                    run.append(line[pos])
                    pos += 1
                seq = ''.join(run)
                sev = invisible_severity(seq, in_code_ctx, file_is_doc)
                findings.append(Finding(
                    line=line_num, col=start + 1,
                    category='invisible',
                    severity=sev,
                    detail=f"Invisible/format sequence ({len(seq)} char{'s' if len(seq) != 1 else ''})",
                    visible_context=_safe_snippet(line, start),
                    raw_chars=seq,
                    payload_hint=try_extract_payload(seq),
                    bidi_depth=len(bidi_stack),
                ))
                continue

            # Fullwidth ASCII (emit individually for precision)
            if 0xFF01 <= cp <= 0xFF5E:
                sev = Severity.LOW if file_is_doc else Severity.MEDIUM
                findings.append(Finding(
                    line=line_num, col=pos + 1,
                    category='fullwidth',
                    severity=sev,
                    detail=(f"Fullwidth {unicodedata.name(c, '?')} "
                            f"U+{cp:04X} -> {CONFUSABLES.get(c, '?')!r}"),
                    visible_context=_safe_snippet(line, pos, 40),
                    raw_chars=c,
                ))

            pos += 1

        # End-of-line bidi override leak
        if bidi_stack and in_code_ctx and not file_is_doc:
            findings.append(Finding(
                line=line_num, col=0,
                category='bidi',
                severity=Severity.HIGH,
                detail=f"Active bidi override at end-of-line (depth {len(bidi_stack)})",
                visible_context=(line[:60] + '...' if len(line) > 60 else line),
                bidi_depth=len(bidi_stack),
            ))

    # EOF unbalanced bidi
    if bidi_stack:
        names    = ', '.join(nm for _, nm, _ in bidi_stack)
        at_lines = ', '.join(f'L{ln}' for _, _, ln in bidi_stack)
        findings.append(Finding(
            line='EOF', col=0,
            category='bidi',
            severity=Severity.CRITICAL,
            detail=(f"UNBALANCED BIDI AT EOF -- {len(bidi_stack)} unclosed control(s) "
                    f"({names}) opened at {at_lines} -- CVE-2021-42574"),
            bidi_depth=len(bidi_stack),
        ))

    # -- Identifier analysis ---------------------------------------------------
    seen_idents: Set[str] = set()
    for m in _IDENT_RE.finditer(text):
        ident = m.group(0)
        if ident in seen_idents or ident.isascii():
            continue
        seen_idents.add(ident)

        ln  = text[:m.start()].count('\n') + 1
        col = m.start() - text.rfind('\n', 0, m.start())

        conf = confusable_details(ident)
        if conf:
            chars_desc = '; '.join(
                f"U+{ord(orig):04X} -> {asc!r}" for orig, asc, _ in conf[:4]
            )
            skel = to_skeleton(ident)
            findings.append(Finding(
                line=ln, col=col,
                category='homoglyph',
                severity=Severity.HIGH,
                detail=f"Confusable identifier {ident!r} -> {skel!r} | {chars_desc}",
                visible_context=ident,
                raw_chars=ident,
                payload_hint=f"ASCII skeleton: {skel!r}",
            ))
            continue

        nfkc = unicodedata.normalize('NFKC', ident)
        if nfkc != ident:
            skel = nfkc_skeleton(ident)
            findings.append(Finding(
                line=ln, col=col,
                category='nfkc',
                severity=Severity.HIGH,
                detail=f"NFKC normalises {ident!r} -> {nfkc!r} -- runtimes may resolve differently",
                visible_context=ident,
                raw_chars=ident,
                payload_hint=f"skeleton: {skel!r}",
            ))

    return findings


# ==============================================================================
# 8.  --fix MODE
# ==============================================================================

def fix_file(path: Path, *, dry_run: bool = False, verbose: bool = True) -> int:
    """
    Sanitise a source file in-place (writes a .bak backup first).

    Removal passes, in order:
      1. Null bytes                   (raw-bytes layer, pre-decode)
      2. Bidi controls                (all codepoints in _BIDI_META)
      3. Tag-block payload chars      (U+E0000-E007F  — Glassworm / steganography)
      4. Supplementary VS payload     (U+E0100-E01EF  — bit-stream steganography)
      5. Base variation selectors     (U+FE00-FE0F, U+180B-180E)
      6. Remaining invisible/format   (zero-width, soft-hyphen, word-joiner, etc.)
      7. Fullwidth ASCII substitution (U+FF01-FF5E -> ASCII equivalent)
      8. Confusable identifier chars  (replaced with ASCII skeleton via CONFUSABLES map)

    Returns the total number of characters removed/replaced (0 = nothing to do).
    """
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            if verbose:
                print(f"  {path.name} -- skipped (>{MAX_FILE_BYTES // 1_048_576} MB)")
            return 0
        raw = path.read_bytes()
    except Exception as exc:
        print(f"Cannot read {path}: {exc}", file=sys.stderr)
        return 0

    # -- Pass 1: null bytes (raw) ---------------------------------------------
    cleaned_bytes = raw.replace(b'\x00', b'')
    null_removed  = len(raw) - len(cleaned_bytes)

    try:
        text = cleaned_bytes.decode('utf-8', errors='replace')
    except Exception:
        return 0

    changes: List[str] = []
    if null_removed:
        changes.append(f"  removed {null_removed} null byte(s)")

    # -- Pass 2: bidi controls -------------------------------------------------
    bidi_removed = 0
    for cp, (name, _) in _BIDI_META.items():
        c = chr(cp)
        n = text.count(c)
        if n:
            text = text.replace(c, '')
            bidi_removed += n
            changes.append(f"  removed {n}x bidi {name} (U+{cp:04X})")

    # -- Pass 3: tag-block payload chars (U+E0000-E007F) ----------------------
    tag_chars = [c for c in text if 0xE0000 <= ord(c) < 0xE0080]
    if tag_chars:
        # Attempt to decode so the report shows what was hidden
        decoded = ''.join(chr(ord(c) - 0xE0000) for c in tag_chars).strip()
        text = ''.join(c for c in text if not (0xE0000 <= ord(c) < 0xE0080))
        hint = f" -- decoded: {decoded!r}" if decoded else ''
        changes.append(f"  removed {len(tag_chars)} tag-block payload char(s){hint}")

    # -- Pass 4: supplementary variation selector payload (U+E0100-E01EF) -----
    supp_vs = [c for c in text if 0xE0100 <= ord(c) < 0xE01F0]
    if supp_vs:
        text = ''.join(c for c in text if not (0xE0100 <= ord(c) < 0xE01F0))
        changes.append(f"  removed {len(supp_vs)} supplementary variation selector(s) (VS17-VS256)")

    # -- Pass 5: base variation selectors (U+FE00-FE0F, U+180B-180E) ---------
    base_vs = [c for c in text if 0xFE00 <= ord(c) < 0xFE10 or 0x180B <= ord(c) < 0x180F]
    if base_vs:
        text = ''.join(
            c for c in text
            if not (0xFE00 <= ord(c) < 0xFE10 or 0x180B <= ord(c) < 0x180F)
        )
        changes.append(f"  removed {len(base_vs)} base variation selector(s) (U+FE00-FE0F / U+180B-180E)")

    # -- Pass 6: remaining invisible / format chars (preserve \t \n \r) -------
    clean_chars: List[str] = []
    invis_removed = 0
    for c in text:
        if is_invisible(c) and ord(c) not in (0x09, 0x0A, 0x0D):
            invis_removed += 1
        else:
            clean_chars.append(c)
    if invis_removed:
        changes.append(f"  removed {invis_removed} invisible/format char(s) (ZWSP, soft-hyphen, etc.)")
    text = ''.join(clean_chars)

    # -- Pass 7: fullwidth ASCII (U+FF01-FF5E -> ASCII) -----------------------
    fw_replaced = 0
    fw_chars: List[str] = []
    for c in text:
        cp = ord(c)
        if 0xFF01 <= cp <= 0xFF5E:
            fw_chars.append(chr(cp - 0xFEE0))   # shift to ASCII range
            fw_replaced += 1
        else:
            fw_chars.append(c)
    if fw_replaced:
        changes.append(f"  replaced {fw_replaced} fullwidth ASCII char(s) with narrow equivalents")
    text = ''.join(fw_chars)

    # -- Pass 8: confusable identifier chars -> ASCII skeleton ----------------
    conf_replaced = 0
    def replace_ident(m: re.Match) -> str:
        nonlocal conf_replaced
        ident = m.group(0)
        skel  = to_skeleton(ident)
        if skel != ident:
            conf_replaced += sum(1 for c in ident if c in _CONFUSABLE_SET)
            return skel
        return ident
    text = _IDENT_RE.sub(replace_ident, text)
    if conf_replaced:
        changes.append(f"  replaced {conf_replaced} confusable char(s) with ASCII skeleton")

    total = (null_removed + bidi_removed + len(tag_chars) + len(supp_vs)
             + len(base_vs) + invis_removed + fw_replaced + conf_replaced)

    if not changes:
        if verbose:
            print(f"  {path.name} -- nothing to fix")
        return 0

    if verbose:
        label = '[DRY RUN] ' if dry_run else ''
        print(f"\n  {label}Fixing {path}:")
        for c in changes:
            print(c)
        print(f"  Total: {total} change(s)")

    if not dry_run:
        backup = path.with_suffix(path.suffix + '.bak')
        shutil.copy2(path, backup)
        path.write_text(text, encoding='utf-8')
        if verbose:
            print(f"  Backup saved -> {backup}")

    return total


# ==============================================================================
# 9.  --diff MODE  (git history scanner)
# ==============================================================================

def _git_available(repo: Path) -> bool:
    return shutil.which('git') is not None and (repo / '.git').exists()

def _git_diff_files(repo: Path, ref: str) -> List[Tuple[str, str]]:
    result = subprocess.run(
        ['git', 'diff', '--name-status', ref, 'HEAD'],
        cwd=repo, capture_output=True, text=True,
    )
    files = []
    for line in result.stdout.splitlines():
        parts = line.split('\t', 1)
        if len(parts) == 2 and parts[0][0] in ('A', 'M', 'R'):
            files.append((parts[0][0], parts[1]))
    return files

def _git_blob(repo: Path, ref: str, filepath: str) -> Optional[bytes]:
    r = subprocess.run(
        ['git', 'show', f'{ref}:{filepath}'],
        cwd=repo, capture_output=True,
    )
    return r.stdout if r.returncode == 0 else None


def scan_diff(repo: Path, since_ref: str, min_sev: Severity, json_out: bool) -> int:
    """
    Scan files changed since since_ref.
    For modified files, report only *newly introduced* threats vs the old version.
    """
    if not _git_available(repo):
        print("Error: git not available or not a git repository.", file=sys.stderr)
        return 2

    changed = _git_diff_files(repo, since_ref)
    if not changed:
        print(f"No file changes found since {since_ref!r}")
        return 0

    all_results: Dict[str, dict] = {}
    total = 0

    for status, filepath in changed:
        full_path = repo / filepath
        if not full_path.exists():
            continue
        ext = full_path.suffix.lower()
        if ext not in SCAN_EXTENSIONS:
            continue

        current_findings = [
            f for f in scan_file(full_path)
            if _SEV_RANK[f.severity] >= _SEV_RANK[min_sev]
        ]

        new_findings = current_findings
        if status == 'M':
            old_raw = _git_blob(repo, since_ref, filepath)
            if old_raw is not None:
                with tempfile.NamedTemporaryFile(suffix=full_path.suffix, delete=False) as tmp:
                    tmp.write(old_raw)
                    tmp_path = Path(tmp.name)
                try:
                    old_details = {f.detail for f in scan_file(tmp_path)}
                    new_findings = [f for f in current_findings if f.detail not in old_details]
                finally:
                    tmp_path.unlink(missing_ok=True)

        if new_findings:
            all_results[filepath] = {
                'status': status,
                'new_findings': [f.to_dict() for f in new_findings],
            }
            total += len(new_findings)

    if json_out:
        print(json.dumps({
            'since': since_ref,
            'total_new_findings': total,
            'files': all_results,
        }, indent=2, ensure_ascii=False))
    else:
        print(f"\n-- Git diff scan: {since_ref} -> HEAD --")
        if not all_results:
            print("  No new Unicode threats introduced in this range. OK")
        else:
            for fp, data in all_results.items():
                n = len(data['new_findings'])
                print(f"\n  [{data['status']}] {fp}  ({n} new finding{'s' if n != 1 else ''})")
                for f in data['new_findings']:
                    icon = _SEV_ICON[f['severity']]
                    print(f"    {icon} [{f['severity']:8}] L{f['line']}:{f['col']} [{f['category']}]")
                    print(f"       {f['detail']}")
            print(f"\n  Total newly introduced findings: {total}")

    return 1 if total > 0 else 0


# ==============================================================================
# 10.  PRE-COMMIT HOOK INSTALLER
# ==============================================================================

_HOOK_TEMPLATE = r"""#!/bin/sh
# unicode-threat-scanner pre-commit hook
# Installed by: unicode_threat_scanner.py --install-hook
#
# Blocks commits that introduce HIGH or CRITICAL Unicode threats.
# Emergency bypass: git commit --no-verify

SCANNER="{scanner_path}"
PYTHON="{python_path}"

STAGED=$(git diff --cached --name-only --diff-filter=ACM)
[ -z "$STAGED" ] && exit 0

FOUND=0
for FILE in $STAGED; do
  [ -f "$FILE" ] || continue
  RESULT=$("$PYTHON" "$SCANNER" --file "$FILE" --min-severity HIGH --json 2>/dev/null)
  COUNT=$(printf '%s' "$RESULT" | "$PYTHON" -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('total_findings',0))" 2>/dev/null || echo 0)
  if [ "$COUNT" -gt 0 ]; then
    echo "[unicode-scan] BLOCKED: $COUNT threat(s) in $FILE"
    "$PYTHON" "$SCANNER" --file "$FILE" --min-severity HIGH
    FOUND=1
  fi
done

if [ "$FOUND" -eq 1 ]; then
  printf '\n[unicode-scan] Commit aborted. Fix threats or use --no-verify to bypass.\n'
  exit 1
fi
exit 0
"""

def install_hook(repo: Path, verbose: bool = True) -> int:
    if not (repo / '.git').exists():
        print("Error: not a git repository.", file=sys.stderr)
        return 2

    hook_dir  = repo / '.git' / 'hooks'
    hook_path = hook_dir / 'pre-commit'
    hook_body = _HOOK_TEMPLATE.format(
        scanner_path=Path(__file__).resolve(),
        python_path=sys.executable,
    )

    if hook_path.exists():
        existing = hook_path.read_text()
        if 'unicode-threat-scanner' in existing:
            print("Pre-commit hook already installed.")
            return 0
        # Append to existing hook
        with hook_path.open('a') as f:
            # Strip shebang when appending so it doesn't break the existing one
            body_no_shebang = '\n'.join(hook_body.splitlines()[1:])
            f.write(f'\n# -- unicode-threat-scanner --\n{body_no_shebang}\n')
        if verbose:
            print(f"Appended unicode-scan check to existing hook: {hook_path}")
    else:
        hook_dir.mkdir(exist_ok=True)
        hook_path.write_text(hook_body)
        if verbose:
            print(f"Pre-commit hook installed: {hook_path}")

    hook_path.chmod(hook_path.stat().st_mode | 0o111)
    if verbose:
        print("  Blocks HIGH/CRITICAL threats on every commit.")
        print("  Override: git commit --no-verify")
    return 0


# ==============================================================================
# 11.  REPO SCANNER & TERMINAL OUTPUT
# ==============================================================================

def _ansi(code: str) -> str:
    return code if sys.stdout.isatty() else ''

_R   = _ansi('\033[0m');  _B   = _ansi('\033[1m');   _DIM = _ansi('\033[2m')
_RED = _ansi('\033[31m'); _YEL = _ansi('\033[33m');  _CYN = _ansi('\033[36m')
_GRN = _ansi('\033[32m')

_SEV_COLOR: Dict[str, str] = {
    "CRITICAL": _RED, "HIGH": _YEL, "MEDIUM": _CYN, "LOW": _DIM,
}


def scan_repo(
    root_dir:     str | Path,
    *,
    json_output:  bool            = False,
    min_severity: Severity        = Severity.LOW,
    extensions:   Optional[Set[str]] = None,
) -> int:
    root = Path(root_dir).resolve()
    exts = extensions or SCAN_EXTENSIONS
    all_findings:  Dict[Path, List[Finding]] = {}
    sev_counts:    Dict[Severity, int]       = {s: 0 for s in Severity}
    files_scanned  = 0

    for path in sorted(root.rglob('*')):
        if not path.is_file():
            continue
        if _SKIP_DIRS & set(path.parts):
            continue
        if path.suffix.lower() not in exts:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue

        raw_findings = scan_file(path)
        files_scanned += 1
        filtered = [f for f in raw_findings if _SEV_RANK[f.severity] >= _SEV_RANK[min_severity]]
        if not filtered:
            continue
        all_findings[path] = filtered
        for f in filtered:
            sev_counts[f.severity] += 1

    total = sum(len(v) for v in all_findings.values())

    if json_output:
        print(json.dumps({
            "root":            str(root),
            "files_scanned":   files_scanned,
            "total_findings":  total,
            "severity_counts": {k.value: v for k, v in sev_counts.items()},
            "files": {
                str(p.relative_to(root)): [f.to_dict() for f in fs]
                for p, fs in all_findings.items()
            },
        }, indent=2, ensure_ascii=False))
    else:
        _print_report(root, all_findings, files_scanned, total, sev_counts)

    return 1 if total > 0 else 0


def _print_report(
    root:          Path,
    all_findings:  Dict[Path, List[Finding]],
    files_scanned: int,
    total:         int,
    sev_counts:    Dict[Severity, int],
) -> None:
    bar = '=' * 72
    print(f"\n{_B}{bar}{_R}")
    print(f"{_B}  Unicode Threat Scanner{_R}")
    print(f"  Root   : {root}")
    print(f"  Scanned: {files_scanned} file(s)")
    print(f"{_B}{bar}{_R}\n")

    if not all_findings:
        print(f"  {_GRN}OK  No threats detected.{_R}\n")
        return

    for path, findings in sorted(
        all_findings.items(),
        key=lambda kv: -max(_SEV_RANK[f.severity] for f in kv[1]),
    ):
        worst = max(findings, key=lambda f: _SEV_RANK[f.severity]).severity
        col   = _SEV_COLOR[worst.value]
        rel   = path.relative_to(root) if root != path.parent else path.name
        n     = len(findings)
        print(f"\n{_B}{col}>> {rel}{_R}  ({n} finding{'s' if n != 1 else ''})")

        sorted_f = sorted(
            findings,
            key=lambda f: (999999 if f.line == 'EOF' else int(f.line), -_SEV_RANK[f.severity]),
        )
        for i, f in enumerate(sorted_f):
            if i >= 30:
                print(f"  {_DIM}... +{len(sorted_f) - 30} more -- use --json for full list{_R}")
                break
            sc   = _SEV_COLOR[f.severity.value]
            lstr = 'EOF' if f.line == 'EOF' else f"{f.line}:{f.col}"
            cat  = f.category.upper().replace('_', '-')
            icon = f.icon()
            print(f"  {icon} {sc}[{f.severity.value:8}]{_R} L{lstr:<12} [{cat}]")
            print(f"     {_DIM}-> {f.detail[:115]}{_R}")
            if f.visible_context and f.category not in ('invisible', 'null'):
                print(f"     {_DIM}   ctx : {f.visible_context[:80]!r}{_R}")
            if f.payload_hint:
                print(f"     {_CYN}   hint: {f.payload_hint[:120]}{_R}")
            if f.bidi_depth > 0:
                print(f"     {_DIM}   bidi depth: {f.bidi_depth}{_R}")

    print(f"\n{bar}")
    print(f"{_B}  SUMMARY -- {total} finding(s) across {len(all_findings)} file(s) "
          f"[{files_scanned} scanned]{_R}")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = sev_counts[sev]
        if count:
            col = _SEV_COLOR[sev.value]
            print(f"  {_SEV_ICON[sev.value]} {col}{sev.value:8}{_R} : {count}")
    print(f"{bar}\n")


# ==============================================================================
# 12.  CLI
# ==============================================================================

def main() -> None:
    ap = argparse.ArgumentParser(
        prog='unicode-scan',
        description='Detect Unicode-based supply-chain threats in source code.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  unicode-scan .                                # scan current directory
  unicode-scan --file src/auth.py               # single file
  unicode-scan --json --min-severity HIGH .     # CI hard-fail gate
  unicode-scan --fix src/suspicious.py          # sanitise in-place (writes .bak)
  unicode-scan --fix --dry-run .                # preview what --fix would change
  unicode-scan --diff HEAD~10                   # new threats introduced since HEAD~10
  unicode-scan --install-hook                   # add pre-commit hook to this repo
  unicode-scan --update-confusables             # refresh TR39 confusables table
        """,
    )
    ap.add_argument('path',     nargs='?', default='.', help='Directory to scan (default: .)')
    ap.add_argument('--file',   metavar='FILE',         help='Scan a single file')
    ap.add_argument('--json',   action='store_true',    help='Emit JSON output (CI-friendly)')
    ap.add_argument('--min-severity', default='LOW',
                    choices=[s.value for s in Severity],
                    help='Minimum severity to report (default: LOW)')
    ap.add_argument('--fix',    action='store_true',    help='Sanitise file(s) in-place')
    ap.add_argument('--dry-run',action='store_true',    help='Preview --fix changes without writing')
    ap.add_argument('--diff',   metavar='GIT_REF',      help='Scan only changes since GIT_REF')
    ap.add_argument('--install-hook', action='store_true', help='Install git pre-commit hook')
    ap.add_argument('--update-confusables', action='store_true',
                    help='Fetch latest Unicode TR39 confusables.txt and cache locally')

    args   = ap.parse_args()
    min_sev = Severity(args.min_severity.upper())

    # -- Special modes ---------------------------------------------------------
    if args.update_confusables:
        sys.exit(0 if update_confusables() >= 0 else 2)

    if args.install_hook:
        sys.exit(install_hook(Path(args.path).resolve()))

    if args.diff:
        sys.exit(scan_diff(Path(args.path).resolve(), args.diff, min_sev, args.json))

    # -- Fix mode --------------------------------------------------------------
    if args.fix or args.dry_run:
        target = Path(args.file or args.path).resolve()
        if not target.exists():
            print(f"Error: {target} does not exist", file=sys.stderr)
            sys.exit(2)
        paths = ([target] if target.is_file() else [
            q for q in target.rglob('*')
            if q.is_file()
            and q.suffix.lower() in SCAN_EXTENSIONS
            and not (_SKIP_DIRS & set(q.parts))
        ])
        total = sum(fix_file(q, dry_run=args.dry_run) for q in paths)
        if args.dry_run and total == 0:
            print("Nothing to fix.")
        sys.exit(0)

    # -- Scan mode -------------------------------------------------------------
    target = Path(args.file or args.path).resolve()
    if not target.exists():
        print(f"Error: {target} does not exist", file=sys.stderr)
        sys.exit(2)

    if args.file or target.is_file():
        raw      = scan_file(target)
        filtered = [f for f in raw if _SEV_RANK[f.severity] >= _SEV_RANK[min_sev]]
        if args.json:
            print(json.dumps({
                'file': str(target),
                'total_findings': len(filtered),
                'findings': [f.to_dict() for f in filtered],
            }, indent=2, ensure_ascii=False))
        else:
            if filtered:
                sev_c = {s: sum(1 for f in filtered if f.severity == s) for s in Severity}
                _print_report(target.parent, {target: filtered}, 1, len(filtered), sev_c)
            else:
                print(f"{_GRN}OK  No threats detected in {target.name}{_R}")
        sys.exit(1 if filtered else 0)

    sys.exit(scan_repo(target, json_output=args.json, min_severity=min_sev))


if __name__ == '__main__':
    main()
