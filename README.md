# 🛡️ Advanced Stealth URL Shortener (V8)

A production-ready, security-focused URL Shortener built with **Flask**, **SQLAlchemy**, and **Python**.
Designed for high-traffic environments requiring advanced traffic filtering, cloaking, and detailed analytics.

## ✨ Key Features

### 👻 Stealth & Cloaking
- **HTTP 200 OK Redirects**: Uses a lightweight "Loading" page with JavaScript redirection to fool URL expanders/scanners that look for 30x headers.
- **Smart Cloaking**: Automatically redirects suspicious traffic (Bots, VPNs, Crawlers) to a safe "fallback" URL (e.g., Google) while real users go to the target.
- **Bot Detection**: Double-layer detection using Server-side User-Agent heuristics and Client-side `navigator.webdriver` beaconing.

### 🌍 Traffic Filtering
- **ISP & Geo Blocking**: Native integration with `ip-api.com` to detect and block Hosting Providers/Data Centers (AWS, DigitalOcean, Hetzner, etc.).
- **VPN Protection**: Effectively filters out proxy/VPN traffic using ISP classification.
- **Device Targeting**: Route iOS and Android users to specific app store URLs automatically.

### 📊 Deep Analytics
- **Client-Side Beacons**: Captures Screen Resolution, Timezone, and Browser Capabilities without slowing down the redirect.
- **Rich Stats**: Tracks City, Country, ISP, Device Type, and Referrer.
- **CSV Export**: Full raw data export for forensic analysis.

### 🔒 Security Interstitials
- **Password Protection**: Secure SHA-256 hashed password gates.
- **Cloudflare Turnstile**: Integrated CAPTCHA to prevent automated bot traffic.

## 🚀 Tech Stack

- **Backend**: Python (Flask, SQLAlchemy)
- **Database**: SQLite (Production-ready with per-request locking)
- **Deployment**: Optimized for PythonAnywhere (WSGI)
- **Frontend**: Jinja2 Templates (No heavy frameworks, maximum speed)

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/stealth-shortener.git
cd stealth-shortener

# Install dependencies
pip install -r requirements.txt

# Configure Environment
cp .env.example .env
# Edit .env with your SECRET_KEY and API Keys
```

## 📦 Usage (CLI)

Includes a powerful Command Line Interface for managing links:

```bash
python client/cli.py creates
# Follow the interactive menu to set Target, Cloaking, and Security options.
```

## ⚠️ Disclaimer
This tool is intended for educational and legitimate traffic management purposes. The authors are not responsible for misuse.
