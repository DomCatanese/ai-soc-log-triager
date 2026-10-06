# AI-Powered SOC Log Triager & SOAR Engine

A lightweight, privacy-focused Security Operations Center (SOC) triage engine that uses a local Large Language Model (Llama 3.2 3B via Ollama) to ingest raw server logs, classify security incidents into structured JSON, and automatically generate defensive firewall rules.

All processing runs entirely on the local machine—ensuring sensitive authentication and internal network logs never leave the host environment.

---

## Architecture Overview

```
[ Raw Server Logs ]
        │
        ▼
[ Python Ingestion Pipeline ]
        │
        ├─► [ Ollama / Llama 3.2 (Local LLM) ]
        │     • Zero-temperature (deterministic)
        │     • Enforced JSON schema
        │     • Attack classification & severity scoring
        │
        ▼
[ Structured Security Report (JSON) ]
        │
        ▼
[ SOAR Remediation Engine ]
        │
        └─► Generates host firewall rules (Windows netsh / Linux iptables)
```

---

## Key Features

- **Local LLM Inference:** Powered by `llama3.2:3b` via Ollama; no cloud API keys required and zero data egress.
- **Deterministic Threat Classification:** Uses zero-temperature (`temperature: 0.0`) and strict system prompt constraints to eliminate model hallucinations.
- **Structured JSON Schema:** Direct JSON output format enforcement enables programmatic parsing without regex scraping.
- **Noise Reduction:** Automatically filters out benign administrative activity (private IP logins, routine logouts) to combat alert fatigue.
- **Automated SOAR Capabilities:** Dynamically generates deduplicated host-based firewall rules (`netsh advfirewall`) for identified High and Critical threats.

---

## Detection Capabilities

The triager analyzes raw access and authentication logs to flag attack patterns including:
- **Credential Access:** SSH Brute-Force and Credential Spraying attacks.
- **Initial Access & Injection:** Web-based SQL Injection (`' OR '1'='1`) and parameter tampering.
- **Noise Filtering:** Disregards valid internal logins (`10.0.0.0/8`, `192.168.0.0/16`) and standard user sessions.

---

## Getting Started

### Prerequisites

1. **Python 3.10+**
2. **Ollama**: Download and install from [ollama.com](https://ollama.com)

### Installation

1. Clone or download this repository:
   ```bash
   git clone [https://github.com/your-username/ai-soc-triager.git](https://github.com/your-username/ai-soc-triager.git)
   cd ai-soc-triager
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Pull the local AI model:
   ```bash
   ollama pull llama3.2:3b
   ```

---

## Usage

1. Place your target log file in the project directory as `auth_sample.log` (or update `LOG_FILE` in `triager.py`).
2. Run the triager:
   ```bash
   python triager.py
   ```

---

## Sample Output

```json
=================================================================
             STRUCTURED INCIDENT REPORT (JSON)
=================================================================
[
  {
    "attack_type": "Brute Force Attack",
    "source_ip": "203.0.113.45",
    "severity": "High",
    "evidence": "Failed password for invalid user root from 203.0.113.45 port 39120",
    "recommended_action": "Implement rate limiting and block source IP"
  },
  {
    "attack_type": "SQL Injection",
    "source_ip": "198.51.100.12",
    "severity": "Critical",
    "evidence": "Connection from 198.51.100.12: GET /login.php?user=admin' OR '1'='1 HTTP/1.1 200",
    "recommended_action": "Validate/sanitize input queries and deploy WAF rule"
  }
]

=================================================================
           AUTO-GENERATED MITIGATION COMMANDS
=================================================================
[+] Suggested Rule: netsh advfirewall firewall add rule name="Block_203.0.113.45" dir=in action=block remoteip=203.0.113.45
[+] Suggested Rule: netsh advfirewall firewall add rule name="Block_198.51.100.12" dir=in action=block remoteip=198.51.100.12
```

---

## License

MIT License. Free for educational and portfolio use.