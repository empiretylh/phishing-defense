"""
Machine Learning Phishing Detection Engine
============================================
Loads a pre-trained RandomForest model (models/phishing_model.pkl).
If no model file is found, falls back to the heuristic engine.

Also provides a training utility to build the model from a CSV dataset.
"""

import math
import os
import pickle
import re
from collections import Counter
from typing import Dict, List, Optional
from urllib.parse import urlparse, unquote

import numpy as np

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models",
    "phishing_model.pkl",
)

# Feature names must match training order
FEATURE_NAMES: List[str] = [
    "domain_length",
    "path_length",
    "entropy",
    "digit_ratio",
    "hyphen_count",
    "dot_count",
    "at_sign",
    "has_ip",
    "subdomain_depth",
    "is_https",
    "suspicious_keyword_count",
    "special_char_count",
]

# Keywords used during feature extraction
_SUSPICIOUS_KW = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "bank", "paypal", "password", "free", "winner",
    "prize", "billing", "invoice", "wallet", "recover", "unlock",
    "validate", "auth", "sso", "token", "webscr",
]


# ---------------------------------------------------------------------------
# Feature extraction (mirrors training pipeline)
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_features(url: str) -> np.ndarray:
    """Extract a numeric feature vector from a URL string."""
    url = unquote(url).strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""

    domain_length = len(host)
    path_length = len(path)
    entropy = _shannon_entropy(host)
    digit_ratio = sum(c.isdigit() for c in host) / max(len(host), 1)
    hyphen_count = host.count("-")
    dot_count = host.count(".")
    at_sign = 1 if "@" in url else 0
    has_ip = 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) else 0
    subdomain_depth = max(host.count(".") - 1, 0)
    is_https = 1 if parsed.scheme == "https" else 0

    full_lower = (host + path).lower()
    suspicious_keyword_count = sum(1 for kw in _SUSPICIOUS_KW if kw in full_lower)
    special_char_count = sum(1 for c in url if c in "!@#$%^&*()+=[]{}|;:'\",<>?")

    return np.array([
        domain_length,
        path_length,
        entropy,
        digit_ratio,
        hyphen_count,
        dot_count,
        at_sign,
        has_ip,
        subdomain_depth,
        is_https,
        suspicious_keyword_count,
        special_char_count,
    ], dtype=np.float64).reshape(1, -1)


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

_model = None  # cached in memory


def _load_model():
    """Load pickled sklearn model. Returns None if unavailable."""
    global _model
    if _model is not None:
        return _model
    if not os.path.isfile(MODEL_PATH):
        return None
    try:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        return _model
    except Exception:
        return None


def model_available() -> bool:
    """Check if a trained model file exists and loads correctly."""
    return _load_model() is not None


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def predict(url: str) -> Optional[Dict]:
    """
    Run the ML model on a URL.

    Returns dict with risk_score, classification, confidence, reasoning
    or None if the model is not available.
    """
    model = _load_model()
    if model is None:
        return None

    features = extract_features(url)
    try:
        proba = model.predict_proba(features)[0]
        # proba[0] = safe, proba[1] = phishing
        phishing_prob = proba[1] if len(proba) > 1 else proba[0]
    except Exception:
        # Model may not support predict_proba
        pred = model.predict(features)[0]
        phishing_prob = float(pred)

    risk_score = round(phishing_prob * 100, 2)
    if risk_score < 30:
        classification = "Safe"
    elif risk_score < 65:
        classification = "Suspicious"
    else:
        classification = "Phishing"

    confidence = round(max(phishing_prob, 1 - phishing_prob), 3)

    # Feature importance reasoning
    reasoning = []
    feat_values = features.flatten()
    try:
        importances = model.feature_importances_
        top_indices = np.argsort(importances)[::-1][:5]
        for idx in top_indices:
            reasoning.append(
                f"{FEATURE_NAMES[idx]}: {feat_values[idx]:.3f} "
                f"(importance: {importances[idx]:.3f})"
            )
    except AttributeError:
        reasoning.append("Feature importances not available for this model")

    return {
        "risk_score": risk_score,
        "classification": classification,
        "confidence": confidence,
        "reasoning": reasoning,
        "engine": "ML RandomForest v1.0",
    }


# ---------------------------------------------------------------------------
# Training utility
# ---------------------------------------------------------------------------

def train_model(csv_path: str, save_path: Optional[str] = None) -> Dict:
    """
    Train a RandomForestClassifier from a CSV dataset.

    CSV must have columns: url, label  (label: 0 = safe, 1 = phishing)

    Returns training metrics dict.
    """
    import csv as csv_mod
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, f1_score

    urls: List[str] = []
    labels: List[int] = []

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv_mod.DictReader(f)
        for row in reader:
            urls.append(row["url"])
            labels.append(int(row["label"]))

    X = np.vstack([extract_features(u) for u in urls])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    out_path = save_path or MODEL_PATH
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f:
        pickle.dump(clf, f)

    global _model
    _model = clf

    return {
        "accuracy": round(acc, 4),
        "f1_score": round(f1, 4),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "model_path": out_path,
    }
