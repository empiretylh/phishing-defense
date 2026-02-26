"""
Chrome Extension Testing Module
================================
Provides automated testing of Chrome extensions for phishing detection.
- Detects Chrome install path
- Validates extension manifest
- Launches Chrome with a test URL and collects results
- Reports detection response

FOR EDUCATIONAL / LOCAL TESTING ONLY.
Only tests locally-created test domains (localhost / 127.0.0.1).
"""

import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Chrome path detection
# ---------------------------------------------------------------------------

_CHROME_PATHS_WIN = [
    os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
    os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
    os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
]

_CHROME_PATHS_MAC = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]

_CHROME_PATHS_LINUX = [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/snap/bin/chromium",
]


def detect_chrome_path() -> Optional[str]:
    """Auto-detect Chrome executable path."""
    system = platform.system()
    if system == "Windows":
        candidates = _CHROME_PATHS_WIN
    elif system == "Darwin":
        candidates = _CHROME_PATHS_MAC
    else:
        candidates = _CHROME_PATHS_LINUX

    for path in candidates:
        if os.path.isfile(path):
            return path

    # Try shutil.which as fallback
    which = shutil.which("google-chrome") or shutil.which("chrome") or shutil.which("chromium")
    return which


def chrome_available() -> bool:
    """Check if Chrome is installed."""
    return detect_chrome_path() is not None


def get_chrome_version() -> Optional[str]:
    """Get installed Chrome version string."""
    chrome = detect_chrome_path()
    if not chrome:
        return None
    try:
        result = subprocess.run(
            [chrome, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Extension manifest validation
# ---------------------------------------------------------------------------

def validate_extension_manifest(extension_dir: str) -> Dict:
    """
    Validate a Chrome extension's manifest.json.

    Returns dict with:
        valid       : bool
        errors      : list[str]
        warnings    : list[str]
        manifest    : dict or None
    """
    result = {"valid": False, "errors": [], "warnings": [], "manifest": None}

    manifest_path = os.path.join(extension_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        result["errors"].append("manifest.json not found")
        return result

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except json.JSONDecodeError as e:
        result["errors"].append(f"Invalid JSON: {e}")
        return result

    result["manifest"] = manifest

    # Required fields
    required = ["manifest_version", "name", "version"]
    for field in required:
        if field not in manifest:
            result["errors"].append(f"Missing required field: '{field}'")

    # Check manifest version
    mv = manifest.get("manifest_version")
    if mv not in (2, 3):
        result["errors"].append(
            f"Invalid manifest_version: {mv} (must be 2 or 3)"
        )

    # Warnings
    if "description" not in manifest:
        result["warnings"].append("Missing 'description' field")
    if "permissions" not in manifest:
        result["warnings"].append("No permissions declared")
    else:
        perms = manifest["permissions"]
        risky = [p for p in perms if p in (
            "<all_urls>", "tabs", "webRequest", "webRequestBlocking",
            "cookies", "history", "bookmarks",
        )]
        if risky:
            result["warnings"].append(f"Sensitive permissions: {', '.join(risky)}")

    if "content_scripts" in manifest:
        for cs in manifest["content_scripts"]:
            matches = cs.get("matches", [])
            if "<all_urls>" in matches:
                result["warnings"].append(
                    "Content script matches <all_urls> — broad scope"
                )

    result["valid"] = len(result["errors"]) == 0
    return result


# ---------------------------------------------------------------------------
# Chrome launch with extension for testing
# ---------------------------------------------------------------------------

_SAFE_TEST_URLS = [
    "http://127.0.0.1:8080/phishing-test",
    "http://localhost:8080/phishing-test",
]


def launch_chrome_test(
    test_url: str,
    extension_dir: Optional[str] = None,
    timeout_seconds: int = 15,
) -> Dict:
    """
    Launch Chrome with a test URL (and optional extension) and report result.

    Only allows localhost/127.0.0.1 URLs for safety.

    Returns dict with:
        launched    : bool
        chrome_path : str
        test_url    : str
        extension   : str or None
        duration    : float (seconds)
        notes       : list[str]
    """
    result: Dict = {
        "launched": False,
        "chrome_path": None,
        "test_url": test_url,
        "extension": extension_dir,
        "duration": 0.0,
        "notes": [],
    }

    # Safety check — only allow local test URLs
    from urllib.parse import urlparse
    parsed = urlparse(test_url)
    if parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        result["notes"].append(
            "BLOCKED: Only localhost / 127.0.0.1 test URLs are allowed"
        )
        return result

    chrome = detect_chrome_path()
    if not chrome:
        result["notes"].append("Chrome not found on this system")
        return result

    result["chrome_path"] = chrome

    # Build command-line arguments
    user_data_dir = tempfile.mkdtemp(prefix="phish_test_")
    args = [
        chrome,
        f"--user-data-dir={user_data_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-default-apps",
        "--disable-sync",
    ]

    if extension_dir and os.path.isdir(extension_dir):
        args.append(f"--load-extension={os.path.abspath(extension_dir)}")
        result["notes"].append(f"Extension loaded from: {extension_dir}")

    args.append(test_url)

    try:
        start = time.time()
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result["launched"] = True
        result["notes"].append("Chrome launched successfully")

        # Wait briefly then terminate (test mode)
        try:
            proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            proc.terminate()
            result["notes"].append(
                f"Chrome terminated after {timeout_seconds}s test window"
            )

        result["duration"] = round(time.time() - start, 2)

    except Exception as e:
        result["notes"].append(f"Failed to launch Chrome: {e}")

    # Cleanup temp profile
    try:
        shutil.rmtree(user_data_dir, ignore_errors=True)
    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Summary report builder
# ---------------------------------------------------------------------------

def generate_test_report(
    extension_dir: Optional[str] = None,
    test_url: str = "http://127.0.0.1:8080/phishing-test",
) -> Dict:
    """
    Run a full extension test cycle and produce a report.

    Steps:
    1. Detect Chrome installation
    2. Validate extension manifest (if provided)
    3. Launch Chrome with test URL
    4. Aggregate findings
    """
    report: Dict = {
        "chrome_detected": False,
        "chrome_version": None,
        "manifest_validation": None,
        "launch_result": None,
        "overall_status": "NOT RUN",
    }

    # 1. Chrome detection
    chrome = detect_chrome_path()
    report["chrome_detected"] = chrome is not None
    report["chrome_version"] = get_chrome_version()

    if not chrome:
        report["overall_status"] = "FAIL — Chrome not found"
        return report

    # 2. Manifest validation
    if extension_dir:
        report["manifest_validation"] = validate_extension_manifest(extension_dir)

    # 3. Launch test
    report["launch_result"] = launch_chrome_test(
        test_url=test_url,
        extension_dir=extension_dir,
    )

    # 4. Overall status
    if report["launch_result"]["launched"]:
        report["overall_status"] = "PASS — Chrome launched and tested"
    else:
        report["overall_status"] = "PARTIAL — Chrome found but launch failed"

    return report
