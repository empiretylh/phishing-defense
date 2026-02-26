"""
VirusTotal API Client
=====================
Submits URLs to the VirusTotal v3 API for reputation scanning.
Falls back gracefully when no API key is configured.

Rate-limited to 4 requests/minute (free-tier default).
"""

import os
import time
import threading
from typing import Dict, Optional
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_URL = "https://www.virustotal.com/api/v3/urls"
_RATE_LIMIT = 4          # max requests per minute (free tier)
_RATE_WINDOW = 60.0      # seconds

_request_times: list = []
_rate_lock = threading.Lock()


def _get_api_key() -> Optional[str]:
    """Retrieve VirusTotal API key from environment."""
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    return key if key else None


def api_key_available() -> bool:
    """Check if a valid-looking API key is configured."""
    key = _get_api_key()
    return key is not None and len(key) >= 32


def _rate_limit_wait() -> None:
    """Block until a request slot is available (sliding window)."""
    with _rate_lock:
        now = time.time()
        # Prune old entries
        _request_times[:] = [t for t in _request_times if now - t < _RATE_WINDOW]
        if len(_request_times) >= _RATE_LIMIT:
            sleep_time = _RATE_WINDOW - (now - _request_times[0]) + 0.5
            if sleep_time > 0:
                time.sleep(sleep_time)
        _request_times.append(time.time())


def _normalize_url(url: str) -> str:
    """Basic URL normalization."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    # Lowercase scheme and host
    normalized = f"{parsed.scheme.lower()}://{(parsed.hostname or '').lower()}"
    if parsed.port and parsed.port not in (80, 443):
        normalized += f":{parsed.port}"
    normalized += parsed.path.rstrip("/") or "/"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return normalized


def scan_url(url: str) -> Dict:
    """
    Submit a URL to VirusTotal and return structured results.

    Returns dict with:
        risk_score      : float (0-100)
        classification  : str
        confidence      : float (0-1)
        reasoning       : list[str]
        engine          : str
        api_used        : True
        raw_stats       : dict (malicious, suspicious, harmless, undetected)

    Raises RuntimeError on API errors.
    """
    api_key = _get_api_key()
    if not api_key:
        raise RuntimeError("VirusTotal API key is not configured")

    url = _normalize_url(url)
    _rate_limit_wait()

    headers = {"x-apikey": api_key}

    # Step 1 — Submit URL for scanning
    try:
        submit_resp = requests.post(
            VT_API_URL,
            headers=headers,
            data={"url": url},
            timeout=30,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Network error submitting URL: {exc}")

    if submit_resp.status_code == 401:
        raise RuntimeError("Invalid VirusTotal API key")
    if submit_resp.status_code == 429:
        raise RuntimeError("VirusTotal rate limit exceeded — try again later")
    if submit_resp.status_code not in (200, 201):
        raise RuntimeError(
            f"VirusTotal submission failed (HTTP {submit_resp.status_code})"
        )

    # Extract analysis ID
    try:
        analysis_id = submit_resp.json()["data"]["id"]
    except (KeyError, ValueError):
        raise RuntimeError("Unexpected response from VirusTotal submission")

    # Step 2 — Poll for analysis results (up to 60 s)
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(12):
        time.sleep(5)
        _rate_limit_wait()
        try:
            result_resp = requests.get(
                analysis_url, headers=headers, timeout=30
            )
        except requests.RequestException:
            continue

        if result_resp.status_code != 200:
            continue

        data = result_resp.json().get("data", {})
        attrs = data.get("attributes", {})
        status = attrs.get("status")

        if status == "completed":
            stats = attrs.get("stats", {})
            return _build_result(url, stats)

    raise RuntimeError("VirusTotal analysis timed out")


def _build_result(url: str, stats: Dict) -> Dict:
    """Convert VT stats into our standard result format."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total_engines = malicious + suspicious + harmless + undetected
    if total_engines == 0:
        total_engines = 1  # avoid division by zero

    detection_ratio = (malicious + suspicious) / total_engines
    risk_score = round(detection_ratio * 100, 2)

    if risk_score < 15:
        classification = "Safe"
    elif risk_score < 50:
        classification = "Suspicious"
    else:
        classification = "Phishing"

    confidence = round(min(total_engines / 70, 1.0), 3)  # more engines = higher confidence

    reasoning = [
        f"VirusTotal detection: {malicious} malicious, {suspicious} suspicious "
        f"out of {total_engines} engines",
        f"Detection ratio: {detection_ratio:.1%}",
        f"Harmless: {harmless}, Undetected: {undetected}",
    ]

    return {
        "risk_score": risk_score,
        "classification": classification,
        "confidence": confidence,
        "reasoning": reasoning,
        "engine": f"VirusTotal API ({total_engines} engines)",
        "api_used": True,
        "raw_stats": stats,
    }
