"""
Heuristic Phishing Analysis Engine
====================================
Extracts structural, lexical and statistical features from a URL
and produces a weighted risk score (0-100) with detailed reasoning.

This module operates entirely offline — no network calls required.
"""

import math
import re
import string
from collections import Counter
from typing import Dict, List, Tuple
from urllib.parse import urlparse, unquote

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS: List[str] = [
    "login", "signin", "sign-in", "verify", "secure", "account",
    "update", "confirm", "bank", "paypal", "password", "credential",
    "suspend", "alert", "urgent", "click", "free", "winner", "prize",
    "bonus", "offer", "gift", "reward", "billing", "invoice",
    "authenticate", "wallet", "recover", "unlock", "validate",
    "webscr", "cmd", "token", "auth", "sso", "oauth",
]

# High-risk TLDs frequently seen in phishing campaigns
HIGH_RISK_TLDS: Dict[str, float] = {
    ".tk": 8.0, ".ml": 8.0, ".ga": 8.0, ".cf": 8.0, ".gq": 8.0,
    ".xyz": 6.0, ".top": 6.0, ".pw": 7.0, ".cc": 5.0, ".club": 5.0,
    ".work": 5.0, ".buzz": 6.0, ".icu": 6.0, ".cam": 5.0, ".surf": 5.0,
    ".link": 4.0, ".click": 5.0, ".info": 3.0, ".biz": 3.0, ".online": 4.0,
    ".site": 4.0, ".store": 3.0, ".fun": 4.0,
}

# Well-known brands targeted by phishing
TARGET_BRANDS: Dict[str, List[str]] = {
    "facebook":  ["faceb00k", "facbook", "facebk", "fb-login", "faceb0ok"],
    "google":    ["g00gle", "gogle", "googl", "go0gle", "goog1e"],
    "paypal":    ["paypa1", "paypall", "pay-pal", "payp4l"],
    "microsoft": ["micros0ft", "microsft", "m1crosoft", "micr0soft"],
    "apple":     ["app1e", "appie", "apple-id", "appl3"],
    "amazon":    ["amaz0n", "amazn", "arnazon", "amzon"],
    "netflix":   ["netf1ix", "netflex", "netfl1x"],
    "instagram": ["1nstagram", "instagran", "lnstagram"],
    "twitter":   ["tw1tter", "tvvitter", "twiiter"],
    "linkedin":  ["linkedln", "l1nkedin", "linkdin"],
}

# Unicode confusable characters (homograph attacks)
HOMOGRAPH_MAP: Dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u04bb": "h",
    "\u0456": "i", "\u0458": "j", "\u04cf": "l", "\u043d": "n",
    "\u0455": "s", "\u0442": "t", "\u044a": "b", "\u0432": "v",
    "\u0448": "w", "\u0443": "u", "\u0437": "3",
}


# ---------------------------------------------------------------------------
# Feature extraction helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_ip_address(host: str) -> bool:
    """Check if the host part is a raw IP address."""
    pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"          # IPv4
        r"|^\[?[0-9a-fA-F:]+\]?$"            # IPv6
    )
    return bool(pattern.match(host))


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _detect_homographs(domain: str) -> List[str]:
    """Detect Unicode homograph characters in domain."""
    found: List[str] = []
    for char in domain:
        if char in HOMOGRAPH_MAP:
            found.append(
                f"U+{ord(char):04X} looks like '{HOMOGRAPH_MAP[char]}'"
            )
    return found


def _detect_brand_spoofing(domain: str) -> List[Tuple[str, int]]:
    """Check if domain contains misspellings of popular brands."""
    hits: List[Tuple[str, int]] = []
    domain_lower = domain.lower()
    for brand, variants in TARGET_BRANDS.items():
        # Direct brand name in domain but domain is NOT official
        if brand in domain_lower:
            # Simple heuristic: if the domain isn't just "brand.com"
            # it might be spoofing
            core = domain_lower.split(".")[0]
            if core != brand:
                hits.append((brand, 0))
        for variant in variants:
            if variant in domain_lower:
                dist = _levenshtein(variant, brand)
                hits.append((f"{brand} (variant: {variant})", dist))
    return hits


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> Dict:
    """
    Perform full heuristic analysis on a URL.

    Returns a dict with:
        risk_score      : float (0–100)
        classification  : str   (Safe / Suspicious / Phishing)
        confidence      : float (0–1)
        features        : dict  (individual feature values)
        reasoning       : list  (human-readable explanations)
    """
    # Normalise
    url = unquote(url).strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    full = host + path

    score = 0.0
    reasons: List[str] = []
    features: Dict = {}

    # ---- 1. Domain length -------------------------------------------------
    domain_len = len(host)
    features["domain_length"] = domain_len
    if domain_len > 30:
        penalty = min((domain_len - 30) * 0.5, 12)
        score += penalty
        reasons.append(f"Long domain ({domain_len} chars, +{penalty:.1f})")

    # ---- 2. Entropy -------------------------------------------------------
    entropy = _shannon_entropy(host)
    features["entropy"] = round(entropy, 3)
    if entropy > 3.8:
        penalty = min((entropy - 3.8) * 8, 15)
        score += penalty
        reasons.append(f"High entropy ({entropy:.2f}, +{penalty:.1f})")

    # ---- 3. Hyphens -------------------------------------------------------
    hyphen_count = host.count("-")
    features["hyphen_count"] = hyphen_count
    if hyphen_count >= 2:
        penalty = min(hyphen_count * 3, 12)
        score += penalty
        reasons.append(f"Multiple hyphens ({hyphen_count}, +{penalty:.1f})")

    # ---- 4. Suspicious keywords -------------------------------------------
    found_keywords: List[str] = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full.lower():
            found_keywords.append(kw)
    features["suspicious_keywords"] = found_keywords
    if found_keywords:
        penalty = min(len(found_keywords) * 4, 20)
        score += penalty
        reasons.append(
            f"Suspicious keywords: {', '.join(found_keywords)} (+{penalty:.1f})"
        )

    # ---- 5. TLD risk ------------------------------------------------------
    tld_score = 0.0
    for tld, risk in HIGH_RISK_TLDS.items():
        if host.endswith(tld):
            tld_score = risk
            break
    features["tld_risk"] = tld_score
    if tld_score:
        score += tld_score
        reasons.append(f"High-risk TLD (+{tld_score:.1f})")

    # ---- 6. IP address usage -----------------------------------------------
    is_ip = _is_ip_address(host)
    features["is_ip_address"] = is_ip
    if is_ip:
        score += 15
        reasons.append("Raw IP address used as host (+15)")

    # ---- 7. Subdomain depth -----------------------------------------------
    subdomain_depth = host.count(".") - 1 if host else 0
    features["subdomain_depth"] = max(subdomain_depth, 0)
    if subdomain_depth >= 3:
        penalty = min((subdomain_depth - 2) * 4, 12)
        score += penalty
        reasons.append(f"Deep subdomains (depth {subdomain_depth}, +{penalty:.1f})")

    # ---- 8. Homograph detection -------------------------------------------
    homographs = _detect_homographs(host)
    features["homograph_chars"] = homographs
    if homographs:
        penalty = min(len(homographs) * 8, 20)
        score += penalty
        reasons.append(
            f"Unicode homograph chars detected: {'; '.join(homographs)} (+{penalty:.1f})"
        )

    # ---- 9. Brand spoofing ------------------------------------------------
    brand_hits = _detect_brand_spoofing(host)
    features["brand_spoofing"] = brand_hits
    if brand_hits:
        penalty = min(len(brand_hits) * 8, 20)
        score += penalty
        reasons.append(
            f"Possible brand spoofing: "
            + ", ".join(b for b, _ in brand_hits)
            + f" (+{penalty:.1f})"
        )

    # ---- 10. HTTPS check --------------------------------------------------
    uses_https = parsed.scheme == "https"
    features["uses_https"] = uses_https
    if not uses_https:
        score += 5
        reasons.append("No HTTPS (+5)")

    # ---- 11. Path depth & special chars -----------------------------------
    path_depth = len([p for p in path.split("/") if p])
    features["path_depth"] = path_depth
    if path_depth > 5:
        penalty = min((path_depth - 5) * 2, 8)
        score += penalty
        reasons.append(f"Deep URL path (depth {path_depth}, +{penalty:.1f})")

    at_sign = "@" in url
    features["has_at_sign"] = at_sign
    if at_sign:
        score += 10
        reasons.append("URL contains '@' sign (+10)")

    # ---- 12. Digit ratio in domain ----------------------------------------
    if host:
        digit_ratio = sum(c.isdigit() for c in host) / len(host)
    else:
        digit_ratio = 0
    features["digit_ratio"] = round(digit_ratio, 3)
    if digit_ratio > 0.3:
        penalty = min(digit_ratio * 20, 10)
        score += penalty
        reasons.append(f"High digit ratio in domain ({digit_ratio:.2f}, +{penalty:.1f})")

    # ---- Clamp and classify -----------------------------------------------
    score = max(0.0, min(100.0, score))

    if score < 30:
        classification = "Safe"
    elif score < 65:
        classification = "Suspicious"
    else:
        classification = "Phishing"

    # Confidence based on how many features fired
    active_features = sum(1 for r in reasons)
    total_checks = 12
    confidence = min(0.5 + (active_features / total_checks) * 0.5, 1.0)

    if not reasons:
        reasons.append("No suspicious indicators detected")

    return {
        "risk_score": round(score, 2),
        "classification": classification,
        "confidence": round(confidence, 3),
        "features": features,
        "reasoning": reasons,
        "engine": "Heuristic Engine v2.0",
    }
