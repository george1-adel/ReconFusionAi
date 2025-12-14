# ReconFusionAI 

**Intelligent Web Asset Scanner with AI-Powered Contextual Analysis**

> **v1 Major Release**: Now featuring **1,183+ Detection Patterns** including Gitleaks, PII, and extensive Cloud Secrets!

ReconFusionAI is an advanced security reconnaissance tool that combines massive regex pattern libraries with AI contextual reasoning (Ollama) to detect exposed secrets, credentials, PII, and vulnerabilities across web applications with unparalleled accuracy.

---

##  Features

###  Massive Multi-Layer Detection System
- **1,183+ Total Detection Patterns** (The "Brain" of the operation)
  - **Gitleaks Integration**: 199+ high-fidelity patterns for Stripe, Slack, modern CI/CD tokens.
  - **Secrets Database**: 803+ patterns for API Keys, AWS/GCP/Azure, SaaS tokens, and more.
  - **PII Detection**: 97+ patterns for Credit Cards (Visa/Master), SSNs, Passports (US/UK/EU), and IDs.
  - **Critical & Discovery**: 84 core patterns for reconnaissance and immediate threats.

###  AI Contextual Intelligence
- **Ollama Integration**: Uses `qwen2.5:1.5b` (or custom models) for reasoning.
- **Contextual Fusion Scoring**: Doesn't just match regex; it understands *context* (e.g., "Is this API key in a config file or a comment?").
- **False Positive Reduction**: AI filters out dummy data and example code.

### ⚡ Advanced Capabilities
- **Production Hardened**: Hardware monitoring (CPU/GPU auto-cooldown), Request Throttling, and Robust Error Handling.
- **Efficient Caching**:
  - **AI Cache (SQLite)**: Reduces redundant LLM calls (1h TTL).
  - **Memory Cache (LRU)**: Efficiently handles duplicates during large scans.
- **Modular Architecture**: Patterns separated into `external_patterns.py` for easy updates.
- **Dual Output**:
  - `findings.json` - Critical secrets with AI analysis.
  - `discoveries.json` - Recon & passive intel.

---

##  Requirements

### System Requirements
- **Python**: 3.8+
- **Ollama**: Installed and running efficiently.
- **OS**: Linux (Recommended), macOS, Windows (WSL).

### Dependencies
```bash
pip install -r requirements.txt
```

### AI Model (Ollama)
```bash
# Install Ollama
curl https://ollama.ai/install.sh | sh

# Pull the optimized model
ollama pull qwen2.5:1.5b
```

---

##  Installation

```bash
# Clone the repository
git clone https://github.com/george1-adel/ReconFusionAi.git
cd ReconFusionAI

# Install Python requirements
pip install -r requirements.txt

# Configure settings
cp config.json.example config.json
nano config.json
```

---

## ⚙️ Configuration

Edit `config.json` to tailor the scanner to your hardware and needs:

```json
{
  "telegram": {
    "bot_token": "YOUR_BOT_TOKEN",
    "chat_id": "YOUR_CHAT_ID",
    "enabled": true
  },
  "ollama": {
    "url": "http://localhost:11434/api/generate",
    "model": "qwen2.5:1.5b"
  },
  "scanning": {
    "concurrent_requests": 10,
    "timeout": 15.0
  }
}
```

---

##  Usage

### Basic Scan
```bash
python3 reconfusionai.py urls.txt
```

### Fast Scan (Skip Phase 1 HTTP Check)
Useful for lists of URLs you know are valid or internal.
```bash
python3 reconfusionai.py s-mylist.txt
```
*(Prefix the filename with `s-` to bypass the initial connectivity check)*

### Input Format
Simple text file, one URL per line:
```
https://example.com
https://api.example.com/v1/config.js
http://dev.internal-dashboard.com
```

---

##  Detection Capabilities (v1)

Our pattern database (`external_patterns.py` + `patterns.py`) covers:

| Category | Count | Examples |
|----------|-------|----------|
| **Cloud Providers** | 150+ | AWS (Access/Secret), GCP, Azure, DigitalOcean, Heroku, Alibaba Cloud |
| **SaaS & APIs** | 400+ | Stripe, Slack, Twilio, SendGrid, MailChimp, PayPal, Square, Shopify |
| **DevOps & CI/CD** | 200+ | GitHub tokens, GitLab CI, Docker, NPM, PyPI, Artifactory, Snyk |
| **PII / Privacy** | 97+ | Credit Cards, IBANs, SSNs, Passport Numbers, Phone Numbers, Emails |
| **Crypto** | 20+ | Bitcoin addresses, Ethereum private keys, Wallet seeds |
| **Infrastructure** | 100+ | Database URIs (Mongo, Postgres), Redis auth, SSH Private Keys |

---

## 🛡️ Security & Privacy

- **100% Local Processing**: AI analysis runs on your machine via Ollama. No data leaves your network.
- **Safe Scanning**: Built-in rate limiting and hardware monitoring prevent system overload.

---

##  Contributing

Contributions are welcome! If you have new regex patterns or features:
1. Fork the repo.
2. Create your feature branch.
3. Submit a Pull Request.

---

## ⚠️ Disclaimer

This tool is designed for **security professionals and authorized testing only**. Usage of ReconFusionAI for attacking targets without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

**Made with and  for the Cyber Security Community**
