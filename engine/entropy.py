"""
Snitch — Entropy Analysis v2.0

Key improvements over v1:
- Per-pattern entropy thresholds (high-confidence patterns skip entropy check)
- Charset-aware scoring (hex strings are penalised — lower max entropy)
- Smarter placeholder detection
- Confidence scoring returned with each result
"""

import math
import string
import re

# ── Thresholds ─────────────────────────────────────────────────────────────────

ENTROPY_HIGH   = 3.8   # Very likely real
ENTROPY_MEDIUM = 3.0   # Possibly real — medium confidence
ENTROPY_LOW    = 2.2   # Probably placeholder / dictionary word

# Hex strings have a smaller alphabet so their max entropy is lower (~4.0 bits)
# Adjust the threshold down for them
ENTROPY_HEX_MEDIUM = 2.4

# ── Character set detection ────────────────────────────────────────────────────

_RE_HEX    = re.compile(r'^[0-9a-fA-F]+$')
_RE_BASE64 = re.compile(r'^[A-Za-z0-9+/=]+$')
_RE_ALNUM  = re.compile(r'^[A-Za-z0-9]+$')


def _charset(value: str) -> str:
    if _RE_HEX.match(value):
        return "hex"
    if _RE_BASE64.match(value):
        return "base64"
    if _RE_ALNUM.match(value):
        return "alnum"
    return "mixed"


# ── Core entropy calculation ───────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Shannon entropy in bits. H = -Σ p(x) log₂ p(x)."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def classify_entropy(value: str, pattern_confidence: str = "medium") -> dict:
    """
    Returns a dict with:
      score       : float — Shannon entropy
      label       : str   — high / medium / low / very_low
      is_likely_real : bool
      charset     : str   — hex / base64 / alnum / mixed
      confidence  : str   — inherited from pattern
    """
    if not value:
        return {"score": 0.0, "label": "very_low", "is_likely_real": False,
                "charset": "mixed", "confidence": pattern_confidence}

    score   = shannon_entropy(value)
    charset = _charset(value)

    # High-confidence patterns (specific prefixes like ghp_, sk_live_, AKIA...)
    # still get entropy scored but we DON'T use it to filter them out.
    # That logic lives in scanner.py.

    # Calibrate thresholds by charset
    hi  = ENTROPY_HIGH
    med = ENTROPY_HEX_MEDIUM if charset == "hex" else ENTROPY_MEDIUM

    if score >= hi:
        label, real = "high", True
    elif score >= med:
        label, real = "medium", True
    elif score >= ENTROPY_LOW:
        label, real = "low", False
    else:
        label, real = "very_low", False

    return {
        "score":        round(score, 4),
        "label":        label,
        "is_likely_real": real,
        "charset":      charset,
        "confidence":   pattern_confidence,
    }


# ── Placeholder detection ──────────────────────────────────────────────────────

_PLACEHOLDER_KW = [
    # Generic placeholders
    'placeholder', 'changeme', 'replace_me', 'your_key', 'your_secret',
    'your_token', 'your_password', 'insert_key', 'insert_here',
    'api_key_here', 'secret_here', 'token_here',
    'testkey', 'demokey', 'fakekey',
    # Common test strings
    'xxxxxxxx', 'aaaaaaaa', '11111111', '00000000',
    'qwerty', 
    # Template patterns already stripped by regex but belt-and-suspenders
    'todo', 'fixme', 'tbd', 'n/a',
]

_SEQUENTIAL_RE = re.compile(r'(.)\1{5,}')  # 6+ repeated chars


def is_placeholder(value: str) -> bool:
    """
    Return True if the value is obviously a test/placeholder string.
    Called BEFORE entropy check — catches low-effort fakes fast.
    """
    if not value or len(value) < 6:
        return True

    lower = value.lower()
    for kw in _PLACEHOLDER_KW:
        if kw in lower:
            return True

    # All same character or almost
    if len(set(value)) <= 2:
        return True

    # 6+ repeated chars (aaaaaaa, xxxxxxx)
    if _SEQUENTIAL_RE.search(value):
        return True

    # Template variable patterns
    if (value.startswith(('${', '{{', '<%', '<', '%{'))
            or value.endswith(('}', '>', '%}'))):
        return True

    # Pure ascending/descending ASCII run (abcde, 12345)
    if len(value) <= 12 and _is_sequential_run(value):
        return True

    return False


def _is_sequential_run(s: str) -> bool:
    """True if >80% of chars are consecutive ASCII."""
    if len(s) < 4:
        return False
    consecutive = sum(
        1 for i in range(1, len(s))
        if abs(ord(s[i]) - ord(s[i - 1])) == 1
    )
    return consecutive / (len(s) - 1) > 0.80


# ── Severity adjustment ────────────────────────────────────────────────────────

_SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def boost_severity(base_severity: str, entropy_label: str,
                   pattern_confidence: str = "medium") -> str:
    """
    High-confidence patterns: never downgrade (the pattern IS the evidence).
    Medium-confidence patterns: downgrade one step on low/very_low entropy.
    """
    if pattern_confidence == "high":
        return base_severity  # trust the pattern

    if entropy_label in ("low", "very_low"):
        idx = _SEV_ORDER.index(base_severity)
        return _SEV_ORDER[max(0, idx - 1)]

    return base_severity
