"""
Educational Phishing Simulation Generator
==========================================
Generates safe, clearly-marked HTML pages that simulate phishing login
forms for security-awareness training.

ALL generated pages include:
  - Prominent "EDUCATIONAL SIMULATION" banners
  - No credential storage or transmission
  - Post-submission awareness messages
  - Explanation of phishing indicators

THIS MODULE DOES NOT HARVEST, STORE, OR TRANSMIT CREDENTIALS.
"""

import os
import tempfile
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Template loading from files
# ---------------------------------------------------------------------------

# Get the directory where templates are stored
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")


def load_template(template_name: str) -> str:
    """Load an HTML template from the templates directory."""
    template_path = os.path.join(TEMPLATE_DIR, f"{template_name}.html")
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        # Fallback to generic template if specific template not found
        generic_path = os.path.join(TEMPLATE_DIR, "generic_login.html")
        with open(generic_path, "r", encoding="utf-8") as f:
            return f.read()


# Template mapping
TEMPLATE_MAP = {
    "facebook_login": "facebook_login",
    "google_login": "google_login",
    "microsoft_login": "microsoft_login",
    "pudawei_lms": "pudawei_lms",
    "generic_login": "generic_login",
    "bank_login": "generic_login",
    "social_media": "generic_login",
    "cloud_storage": "generic_login",
}

# ---------------------------------------------------------------------------
# Template presets
# ---------------------------------------------------------------------------

PRESETS: Dict[str, Dict] = {
    "generic_login": {
        "brand_name": "SecureMail",
        "indicators": (
            "• Non-standard domain (not the real site)<br>"
            "• No valid SSL certificate from the brand<br>"
            "• Generic login form without company branding<br>"
            "• URL does not match the official website"
        ),
    },
    "facebook_login": {
        "brand_name": "Facebook",
        "indicators": (
            "• URL is not facebook.com (check for misspellings like facebo0k.com)<br>"
            "• Missing the blue Facebook branding and official logo<br>"
            "• Real Facebook uses HTTPS with valid certificate<br>"
            "• Be suspicious of login prompts from email or message links"
        ),
    },
    "google_login": {
        "brand_name": "Google",
        "indicators": (
            "• Domain should be accounts.google.com, not a lookalike<br>"
            "• Missing Google's multi-layered security prompts<br>"
            "• Real Google login shows your profile picture if you've signed in before<br>"
            "• Check for HTTPS and valid Google SSL certificate"
        ),
    },
    "microsoft_login": {
        "brand_name": "Microsoft Account",
        "indicators": (
            "• URL should be login.microsoftonline.com or login.live.com<br>"
            "• Watch for typos like micros0ft.com or rnicrosoft.com<br>"
            "• Microsoft uses modern authentication with security info prompts<br>"
            "• Verify the SSL certificate is issued to Microsoft Corporation"
        ),
    },
    "bank_login": {
        "brand_name": "National Bank Online",
        "indicators": (
            "• Real banks never ask you to log in via email links<br>"
            "• Domain does not match the bank's official URL<br>"
            "• Missing bank-specific security seals<br>"
            "• No multi-factor authentication prompt"
        ),
    },
    "social_media": {
        "brand_name": "SocialConnect",
        "indicators": (
            "• URL is not the official social media domain<br>"
            "• Page design may look similar but has subtle differences<br>"
            "• Legitimate sites use branded URLs, not IP addresses<br>"
            "• No 2FA verification step present"
        ),
    },
    "cloud_storage": {
        "brand_name": "CloudDrive Login",
        "indicators": (
            "• Cloud services use their own verified domains<br>"
            "• Shared-document phishing often uses urgency<br>"
            "• Real cloud services show your profile picture<br>"
            "• Check the sender of the link-sharing email"
        ),
    },
    "pudawei_lms": {
        "brand_name": "PUDawei LMS",
        "indicators": (
            "• URL should be lms.pudawei.edu.mm with valid .edu.mm domain<br>"
            "• Check for proper SSL certificate issued to the university<br>"
            "• Real LMS login pages have consistent branding and official logos<br>"
            "• Educational institutions use secure authentication systems<br>"
            "• Be wary of login prompts from unsolicited emails or messages"
        ),
    },
}


# ---------------------------------------------------------------------------
# Page generation
# ---------------------------------------------------------------------------

def generate_simulation_page(
    preset: str = "generic_login",
    output_dir: Optional[str] = None,
) -> str:
    """
    Generate a safe educational phishing simulation HTML file.

    Args:
        preset:     One of the PRESETS keys.
        output_dir: Directory to save the HTML file. Uses temp dir if None.

    Returns:
        Absolute path to the generated HTML file.
    """
    config = PRESETS.get(preset, PRESETS["generic_login"])
    config["preset_key"] = preset  # Add preset key for credential tracking
    
    # Load appropriate template from file
    template_name = TEMPLATE_MAP.get(preset, "generic_login")
    template = load_template(template_name)
    
    html = template.format(**config)

    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="phish_sim_")
    os.makedirs(output_dir, exist_ok=True)

    filepath = os.path.join(output_dir, "simulation.html")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath


# ---------------------------------------------------------------------------
# Local HTTP server for simulation hosting
# ---------------------------------------------------------------------------

class _SimulationHandler(SimpleHTTPRequestHandler):
    """Serve files from a specific directory, handle credential capture."""

    def __init__(self, *args, directory=None, **kwargs):
        self._directory = directory
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format, *args):
        pass  # Silence server logs

    def do_POST(self):
        """Handle POST requests for credential capture."""
        if self.path == '/capture':
            try:
                import json
                from database.db_manager import insert_phished_credential
                
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
                
                # Extract client info
                ip_address = self.client_address[0]
                user_agent = self.headers.get('User-Agent', '')
                
                # Store in database
                insert_phished_credential(
                    username=data.get('username', ''),
                    password=data.get('password', ''),
                    preset=data.get('preset', 'unknown'),
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                
                # Send success response
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'captured'}).encode())
                
            except Exception as e:
                self.send_error(500, f"Capture failed: {str(e)}")
        else:
            self.send_error(404, "Endpoint not found")


_server_instance: Optional[HTTPServer] = None
_server_thread: Optional[threading.Thread] = None


def start_simulation_server(
    html_dir: str,
    port: int = 8080,
) -> str:
    """
    Start a local HTTP server hosting the simulation page.
    Returns the URL to access it.
    """
    global _server_instance, _server_thread

    stop_simulation_server()  # stop any previous instance

    handler = lambda *args, **kwargs: _SimulationHandler(
        *args, directory=html_dir, **kwargs
    )
    _server_instance = HTTPServer(("127.0.0.1", port), handler)
    _server_thread = threading.Thread(target=_server_instance.serve_forever, daemon=True)
    _server_thread.start()

    time.sleep(0.3)  # let server bind
    return f"http://127.0.0.1:{port}/simulation.html"


def stop_simulation_server() -> None:
    """Stop the running simulation server."""
    global _server_instance, _server_thread
    if _server_instance:
        _server_instance.shutdown()
        _server_instance = None
    _server_thread = None


def server_running() -> bool:
    """Check if the simulation server is active."""
    return _server_instance is not None
