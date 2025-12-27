# 🦅 ulrTrack: Advanced Intelligence Router

**The Open-Source "Link Router" for Advanced Analytics & Traffic Control.**

ulrTrack is a sophisticated URL routing platform designed for deep traffic analysis, behavioral fingerprinting, and granular access control. Unlike standard URL shorteners, ulrTrack acts as an intelligent gateway that analyzes every visitor in real-time before routing them to their destination.

![Dashboard Preview](dashboard_preview.png)

## 🚀 Core Capabilities

### 1. 🧠 Ultra-Customizable Routing
Define exactly who sees your content and where they go based on granular rules:
*   **Device Targeting:** Route iOS users to App Store, Android to Play Store, and Desktop to Web.
*   **Geo-Fencing:** Allow or Block traffic from specific countries.
*   **VPN/Proxy Shield:** Automatically detect and filter traffic from commercial VPNs, Proxy services, and Data Centers (AWS, DigitalOcean, etc.).
*   **Time-Based Access:** Schedule links to open/close at specific hours (e.g., "Office Hours Only").
*   **Bot Cloaking:** Show a harmless "404" or "Safe Page" to bots/crawlers while real users get through.

### 2. 🔬 Deep Behavioral Analytics
Going far beyond simple click counts, providing a forensic level of detail:
*   **Hardware Fingerprinting:** Detect Screen Resolution, GPU Renderer, CPU Cores, and RAM.
*   **Network Intelligence:** Identify ISP, Organization, and Connection Type (Residential/Cellular/Corporate).
*   **Session Graph:** Visualize connections between different visitors (e.g., "Same device, different IP").
*   **AI Analyst (Gemini 2.0):** Ask questions like *"What is the top device used in Italy today?"* directly in the dashboard.

### 3. 🛡️ Security Gates
Protect your destination with interactive challenges:
*   **Email Gate:** Require a validated email address to proceed (checks for disposable/temporary domains).
*   **Password Protection:** Secure SHA-256 hashed access.
*   **reCAPTCHA / Turnstile:** Invisible bot protection.

---

## 🛠️ Installation (Self-Hosted)

### Prerequisites
*   Python 3.10+
*   pip / virtualenv

### 1. Clone & Setup
```bash
git clone https://github.com/MN-company/ulrTrack.git
cd ulrTrack

# Create Virtual Env
python3 -m venv venv
source venv/bin/activate

# Install Dependencies
pip install -r server/requirements.txt
```

### 2. Configure Environment
Copy `.env.example` to `.env` and configure:
```bash
SERVER_URL=https://your-domain.com
SECRET_KEY=your-secret-key
GEMINI_API_KEY=your-gemini-key  # For AI Features
```

### 3. Initialize & Run
```bash
# Initialize Database
python3 -m server.init_db

# Run Development Server
./run.sh
```

---

## 📊 Dashboard Features

*   **Live Feed:** Real-time stream of every click.
*   **Visual Graph:** Interactive node graph showing relationships between Visitors, IPs, and Devices.
*   **Export:** Full CSV/JSON export for external analysis.
*   **System Status:** Monitor background workers and AI latency.

---

## ⚠️ Disclaimer
This tool is designed for legitimate marketing analytics, traffic management, and cybersecurity research. The developers are not responsible for misuse.
