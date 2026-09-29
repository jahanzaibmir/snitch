"""
Snitch thi is an Entropy Analysis

"""

import math
import string


# Character sets used in entropy calculations
CHARSET_BASE64 = set(string.ascii_letters + string.digits + '+/=')
CHARSET_HEX    = set(string.hexdigits)
CHARSET_ALNUM  = set(string.ascii_letters + string.digits)

# Thresholds  tuned empirically
# Real secrets tend to be high entropy, placeholders tend to be low
ENTROPY_THRESHOLD_HIGH   = 4.0   # Very likely a real secret
ENTROPY_THRESHOLD_MEDIUM = 3.2   # Possibly a real secret  flag with lower confidence
ENTROPY_THRESHOLD_LOW    = 2.5   # Likely a placeholder or dictionary word


def shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher = more random = more likely to be a real secret.
    
    Formula: H = -Σ p(x) * log2(p(x))
    Max entropy for a 64-char alphabet ≈ 6.0 bits
    """
    if not data:
        return 0.0

    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def classify_entropy(value: str) -> dict:
    """
    Returns entropy score and a classification for a matched secret value.
    """
    entropy = shannon_entropy(value)

    if entropy >= ENTROPY_THRESHOLD_HIGH:
        label = "high"
        is_likely_real = True
    elif entropy >= ENTROPY_THRESHOLD_MEDIUM:
        label = "medium"
        is_likely_real = True
    elif entropy >= ENTROPY_THRESHOLD_LOW:
        label = "low"
        is_likely_real = False
    else:
        label = "very_low"
        is_likely_real = False

    return {
        "score": round(entropy, 4),
        "label": label,
        "is_likely_real": is_likely_real,
    }


def is_placeholder(value: str) -> bool:
    """
    Heuristic checks to catch obvious placeholder/test values.
    These bypass the entropy check entirely.
    """
    if not value or len(value) < 6:
        return True

    lower = value.lower()

    # Common placeholder patterns
    placeholder_keywords = [
        'sample_key', 'fake_key', 'dummy_key', 'placeholder',
        'your_api', 'your_key', 'your-key', 'insert_key',
        'replace_me', 'changeme', 'todo', 'fixme',
        'xxxxxxxx', '12345678', 'testkey', 'demokey',
    ]
    for kw in placeholder_keywords:
        if kw in lower:
            return True

    # All same character ( "aaaaaaaaa")
    if len(set(value)) <= 2:
        return True

    # Sequential characters   only very short pure-sequential strings
    if len(value) < 16 and _is_sequential(value):
        return True

    # Template variable patterns like ${VAR}, {{var}}, <VAR>
    if value.startswith(('${', '{{', '<', '%')) or value.endswith(('}', '>', '%')):
        return True

    return False


def _is_sequential(s: str) -> bool:
    """Check if string is mostly sequential ASCII characters."""
    if len(s) < 6:
        return False

    consecutive = 0
    for i in range(1, len(s)):
        if abs(ord(s[i]) - ord(s[i-1])) == 1:
            consecutive += 1

    # If >70% of chars are sequential, likely a placeholder
    return (consecutive / (len(s) - 1)) > 0.7


def boost_severity(base_severity: str, entropy_label: str) -> str:
    """
    Optionally boost or downgrade severity based on entropy.
    High entropy on a MEDIUM finding → stays MEDIUM (entropy confirms it's real)
    Low entropy on a MEDIUM finding → downgrade to LOW
    """
    severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    if entropy_label in ("high",):
        # Confirmed real — no downgrade
        return base_severity
    elif entropy_label in ("medium",):
        return base_severity
    elif entropy_label in ("low", "very_low"):
        # Downgrade one level
        idx = severity_order.index(base_severity)
        return severity_order[max(0, idx - 1)]

    return base_severity
