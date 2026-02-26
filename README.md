# 🛡️ Enterprise Phishing Analysis & Simulation Platform

**Educational Edition v2.0.0**

A production-grade desktop security operations toolkit for phishing URL analysis, threat intelligence monitoring, awareness training simulation, and Chrome extension testing — built in Python with PyQt6.

> **⚠️ DISCLAIMER:** This tool is designed exclusively for **educational cybersecurity research**. It does not support real-world exploitation. All simulation features are clearly marked and contain no credential harvesting capabilities.

---

## 📸 What You Get

| Feature | Description |
|---------|-------------|
| **URL Intelligence Scanner** | Analyse any URL with risk scoring, classification, and reasoning |
| **Threat Intelligence Dashboard** | Charts, trends, keyword analysis, and scan history |
| **Phishing Simulation Lab** | Generate safe, marked training pages with awareness messages |
| **Chrome Extension Tester** | Validate manifests and launch automated Chrome tests |
| **SQLite Logging** | Every scan is persisted with full metadata |
| **CSV Export** | Export all scan history for external analysis |

---

## 🏗️ Architecture

```
phishing-defense/
│
├── main.py                         # Application entry point
├── train_model.py                  # ML model training script
├── requirements.txt                # Python dependencies
├── .env.example                    # API key template
├── .gitignore
│
├── ui/                             # PyQt6 interface layer
│   ├── dashboard.py                # Main window with sidebar navigation
│   ├── scanner_tab.py              # URL scanner with risk gauge
│   ├── simulation_tab.py           # Phishing simulation lab
│   ├── extension_tab.py            # Chrome extension testing
│   └── threat_intel_tab.py         # Analytics dashboard with charts
│
├── core/                           # Business logic
│   ├── api_client.py               # VirusTotal API integration
│   ├── heuristic_engine.py         # Rule-based URL analysis (12 features)
│   ├── ml_engine.py                # RandomForest ML model
│   ├── chrome_tester.py            # Chrome detection and extension testing
│   └── simulation_generator.py     # Safe HTML page generator
│
├── database/
│   └── db_manager.py               # SQLite operations and analytics
│
└── models/
    ├── sample_dataset.csv          # 100-row training dataset
    └── phishing_model.pkl          # Trained model (generated)
```

---

## 🚀 Quick Start

### 1. Clone & Set Up Environment

```bash
cd phishing-defense
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. (Optional) Configure VirusTotal API

```bash
copy .env.example .env
# Edit .env and paste your VirusTotal API key
```

If no API key is configured, the platform uses the local heuristic engine and ML model — **fully offline**.

### 4. Train the ML Model

```bash
python train_model.py
```

Expected output:
```
============================================================
  Phishing Detection Model Training
============================================================

  Dataset : ...\models\sample_dataset.csv
  Training...

  ✅  Model trained successfully!
  Accuracy   : 0.9500
  F1 Score   : 0.9524
  Train size : 80
  Test size  : 20
  Model saved: ...\models\phishing_model.pkl

============================================================
```

### 5. Launch the Application

```bash
python main.py
```

---

## 🔍 Module Deep-Dive

### URL Intelligence Scanner

**How it works:**

1. Enter any URL in the input field and press **⚡ Analyse**
2. The engine selection cascades automatically:
   - If a **VirusTotal API key** is configured → uses the VT API (polls up to 60s for results)
   - If no API key but a **trained ML model** exists → uses RandomForest prediction
   - Otherwise → uses the **heuristic rule engine** (always available)
3. Results display in real-time with an animated circular gauge

**Example scan — heuristic mode:**

```
URL:    http://faceb00k-login.secure-verify.tk/auth
Score:  82 / 100
Class:  Phishing
Engine: Heuristic Engine v2.0

Reasoning:
  1. High entropy (3.91, +0.9)
  2. Multiple hyphens (3, +9.0)
  3. Suspicious keywords: login, secure, verify, auth (+16.0)
  4. High-risk TLD (+8.0)
  5. No HTTPS (+5)
  6. Possible brand spoofing: facebook (variant: faceb00k) (+8.0)
```

**Example scan — API mode:**

```
URL:    https://suspicious-site.xyz/login
Score:  45.7 / 100
Class:  Suspicious
Engine: VirusTotal API (72 engines)

Reasoning:
  1. VirusTotal detection: 33 malicious, 0 suspicious out of 72 engines
  2. Detection ratio: 45.8%
  3. Harmless: 31, Undetected: 8
```

### Heuristic Engine — Risk Scoring

The engine extracts 12 features and applies weighted penalties:

| Feature | Condition | Max Penalty |
|---------|-----------|-------------|
| Domain length | > 30 chars | +12 |
| Shannon entropy | > 3.8 | +15 |
| Hyphen count | ≥ 2 | +12 |
| Suspicious keywords | Each match | +20 total |
| TLD risk | High-risk TLD | +8 |
| IP address as host | Raw IP used | +15 |
| Subdomain depth | ≥ 3 levels | +12 |
| Unicode homographs | Confusable chars | +20 |
| Brand spoofing | Typosquatting detected | +20 |
| HTTPS check | Missing HTTPS | +5 |
| Path depth | > 5 segments | +8 |
| @ sign in URL | Present | +10 |
| Digit ratio | > 30% digits | +10 |

**Classification thresholds:**
- **0–29**: Safe (green)
- **30–64**: Suspicious (amber)
- **65–100**: Phishing (red)

### Machine Learning Engine

- **Algorithm:** RandomForestClassifier (200 trees, max depth 12)
- **Features:** 12 numeric features extracted from URL structure
- **Training data:** 100 labelled URLs (50 safe, 50 phishing)
- **Output:** Probability-based risk score with feature importance breakdown

To retrain with your own data, create a CSV with `url,label` columns (0 = safe, 1 = phishing) and run:

```bash
python train_model.py
```

### Phishing Simulation Lab

Generate safe, educational phishing awareness pages:

1. Select a **template preset** (Generic Login, Bank, Social Media, Cloud Storage)
2. Click **📄 Generate Page** — creates an HTML file in a temp directory
3. Click **🚀 Start Server** — starts a local HTTP server on `127.0.0.1:8080`
4. Click **🌐 Open in Browser** — view the simulation page

**Safety guarantees:**
- Every page has a red "EDUCATIONAL SIMULATION" banner
- No JavaScript sends data anywhere
- Form submission clears inputs and shows awareness tips
- The local server only binds to `127.0.0.1`

### Chrome Extension Testing

Test Chrome extensions for phishing detection:

1. The module auto-detects Chrome installation
2. Point it to an **unpacked extension directory** (optional)
3. Click **✅ Validate Manifest** to check `manifest.json`
4. Click **🚀 Launch Test** to open Chrome with a test URL
5. Click **📋 Full Report** for a complete test cycle report

**Safety:** Only `localhost` / `127.0.0.1` test URLs are allowed.

### Threat Intelligence Dashboard

Real-time analytics from your scan history:

- **Risk Score Trend** — average risk over the last 30 days (line chart)
- **Classification Distribution** — Safe/Suspicious/Phishing breakdown (pie chart)
- **Top Suspicious Keywords** — most frequently detected keywords (bar chart)
- **API vs Local Usage** — engine usage ratio (bar chart)
- **Recent Scans Table** — last 50 scans with colour-coded classifications

Click **🔄 Refresh Dashboard** to update all panels.

---

## 📊 Database Schema

All scans are stored in `database/phishing_scans.db`:

```sql
CREATE TABLE scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    url            TEXT    NOT NULL,
    risk_score     REAL    NOT NULL,
    classification TEXT    NOT NULL,
    confidence     REAL    DEFAULT 0.0,
    api_used       INTEGER DEFAULT 0,
    engine         TEXT    DEFAULT '',
    reasoning      TEXT    DEFAULT '',
    timestamp      TEXT    NOT NULL
);
```

**Export all scans:**  
Use the **📥 Export CSV** button in the sidebar, or programmatically:

```python
from database.db_manager import export_to_csv
export_to_csv("my_scans.csv")
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VIRUSTOTAL_API_KEY` | No | VirusTotal v3 API key (64 hex chars). Get one free at [virustotal.com](https://www.virustotal.com/gui/join-us) |

### Rate Limiting

- VirusTotal free tier: **4 requests/minute**, 500/day
- The API client enforces a sliding-window rate limiter automatically
- No rate limiting applies to local engine scans

---

## 🛠️ Development

### Running Tests

```bash
# Quick heuristic engine test
python -c "
from core.heuristic_engine import analyze_url
result = analyze_url('http://faceb00k-login.verify.tk/auth')
print(f'Score: {result[\"risk_score\"]}')
print(f'Class: {result[\"classification\"]}')
for r in result['reasoning']:
    print(f'  - {r}')
"
```

### Adding New Features to the Heuristic Engine

1. Add the feature extraction logic in `core/heuristic_engine.py` → `analyze_url()`
2. Assign a weight (penalty points)
3. Add a human-readable reason string
4. The feature count updates automatically in the confidence calculation

### Adding New Simulation Presets

1. Add a new entry to the `PRESETS` dict in `core/simulation_generator.py`
2. Provide `brand_name` and `indicators` HTML string
3. The UI preset dropdown populates automatically

---

## 🔒 Security Design Principles

- **No hardcoded secrets** — API keys loaded from `.env` only
- **Input validation** — all URLs are normalised and parsed before processing
- **Thread safety** — database writes use locks; UI updates via Qt signals
- **No credential storage** — simulation pages explicitly clear form data
- **Localhost only** — simulation server and Chrome tests restricted to `127.0.0.1`
- **Rate limiting** — API requests throttled to prevent account suspension
- **Graceful degradation** — API → ML → Heuristic fallback chain

---

## 📝 License

This project is for **educational and research purposes only**. It must not be used for malicious activities, credential harvesting, or unauthorised security testing.

---

## 🙏 Acknowledgements

- [VirusTotal](https://www.virustotal.com/) for their URL scanning API
- [scikit-learn](https://scikit-learn.org/) for the ML framework
- [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) for the desktop UI framework
- [matplotlib](https://matplotlib.org/) for charting
