# ReconFusionAI 

**Intelligent Web Asset Scanner with AI-Powered Contextual Analysis**

ReconFusionAI is an advanced security reconnaissance tool that combines regex pattern matching with AI contextual reasoning to detect exposed secrets, credentials, and vulnerabilities across web applications.

---

##  Features

### Multi-Layer Detection System
- **98 Detection Patterns** (63 CRITICAL + 35 DISCOVERY)
- **AI Contextual Analysis** using Ollama (Qwen 2.5:1.5b)
- **Contextual Fusion Scoring** - Intelligent risk assessment
- **WordPress-Specific Patterns** (20 specialized patterns)
- **Cloud Services Detection** (AWS, Google, Azure, DigitalOcean, Heroku)
- **CI/CD Secrets** (GitHub, GitLab, NPM, Docker)
- **Payment Systems** (Stripe, PayPal, Square)

### Advanced Capabilities
- **Hardware Monitoring** - Auto-cooldown on CPU/GPU overheating
- **AI Result Caching** (SQLite with TTL)
- **LRU Cache** for memory-efficient deduplication
- **Dual Output System**:
  - `findings.json` - Critical secrets with AI analysis
  - `discoveries.json` - Reconnaissance data (S3 buckets, IPs, params)

---

##  Requirements

### System Requirements
- **Python**: 3.8+
- **Ollama**: Latest version
- **OS**: Linux, macOS, Windows (with WSL)

### Python Dependencies
```bash
pip install -r requirements.txt
```

### AI Model (Ollama)
```bash
# Install Ollama (if not installed)
curl https://ollama.ai/install.sh | sh

# Pull required model
ollama pull qwen2.5:1.5b
```

---

##  Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/ReconFusionAI.git
cd ReconFusionAI

# Install Python dependencies
pip install -r requirements.txt

# Install Ollama model
ollama pull qwen2.5:1.5b

# Copy and configure settings
cp config.json config.json.example
nano config.json
```

---

##  Configuration

Edit `config.json`:

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

### Telegram Setup (Optional)
1. Create a bot via [@BotFather](https://t.me/BotFather)
2. Get your chat ID from [@userinfobot](https://t.me/userinfobot)
3. Update `config.json` with your credentials
4. Set `"enabled": true`

---

##  Usage

### Basic Scan
```bash
python3 reconfusionai.py urls.txt
```

### Skip HTTP Validation (s-prefix)
```bash
# For trusted URLs, skip Phase 1 filtering
python3 reconfusionai.py s-urls.txt
```

### Input File Format
Create a text file with one URL per line:
```
https://example.com
https://api.example.com/config.js
https://staging.example.com/debug
```

---

##  Output Files

### findings.json
Critical secrets with full AI analysis:
```json
{
  "timestamp": "2025-12-09T03:00:00",
  "url": "https://example.com/config.js",
  "severity": "CRITICAL",
  "final_score": 0.92,
  "reasoning_chain": [
    "→ Regex detected: STRIPE_KEY",
    "→ AI identified as: Stripe production API key",
    "→ AI risk assessment: 0.95",
    "→ Final score: 0.92 (CRITICAL)"
  ],
  "regex_findings": [...],
  "ai_analysis": [...],
  "heuristic_enhancement": {...}
}
```

### discoveries.json
Reconnaissance data (no AI analysis):
```json
{
  "timestamp": "2025-12-09T03:00:00",
  "url": "https://example.com/app.js",
  "pattern_name": "S3_BUCKET",
  "match": "company-backups.s3.amazonaws.com",
  "line_number": 127
}
```

---

##  Detection Coverage

### Cloud Providers (11 patterns)
- AWS (Access Keys, Secret Keys, Session Tokens)
- Google Cloud (API Keys, OAuth tokens)
- Azure (Access Keys, SAS tokens)
- Heroku, DigitalOcean, Mailgun

### Authentication & Keys (29 patterns)
- Private Keys (RSA, OpenSSH, PGP, Google Service Account)
- JWT Tokens, Bearer tokens, Basic Auth
- OAuth2 Refresh tokens

### CI/CD & DevOps (5 patterns)
- GitHub, GitLab tokens
- NPM access tokens
- Docker authentication
- Slack, Discord webhooks

### WordPress (20 patterns)
- Database credentials
- Authentication keys & salts
- Debug logs, config backups
- User enumeration endpoints
- Vulnerable plugins

### Reconnaissance (35 patterns)
- S3 buckets, Google Storage, Azure Blobs
- Internal IPs, internal domains
- Dangerous parameters (XSS/SSRF/LFI indicators)
- Client-side vulnerabilities (innerHTML, eval, postMessage)

---

##  How It Works

### 4-Stage Contextual Fusion Pipeline

```

  Stage 1: Regex Detection with Context     
  Extract secrets with surrounding context  

               
               

  Stage 2: AI Contextual Reasoning          
  AI analyzes PURPOSE, RISK, RELATIONSHIP    

               
               

  Stage 3: Heuristic Enhancement            
  Type-specific rules (JWT, AWS, Stripe)    

               
               

  Stage 4: Fusion Scoring                   
  Intelligent risk calculation with chain   

```

**NOT** a simple weighted average - true contextual understanding!

---

##  Security & Privacy

- **Local AI Processing** - All analysis runs locally via Ollama
- **No Cloud Dependencies** - No data sent to external services (except optional Telegram)
- **Configurable Alerts** - Telegram notifications are optional
- **Cache Isolation** - AI cache stored locally in SQLite

---

##  Performance

- **Concurrent Scanning**: 10 URLs simultaneously (configurable)
- **Hardware Monitoring**: Auto-throttle on overheating
- **Optimized Prompts**: ~400 chars vs traditional ~1500 chars
- **AI Caching**: 60% reduction in redundant analysis
- **Memory Efficient**: LRU cache with 10K entry limit

---

##  Troubleshooting

### Ollama Connection Error
```bash
# Check Ollama is running
ollama list

# Restart Ollama
systemctl restart ollama  # Linux
brew services restart ollama  # macOS
```

### High CPU/GPU Usage
Adjust thresholds in `config.json`:
```json
{
  "hardware": {
    "cpu_threshold": 70,
    "gpu_temp_threshold": 75
  }
}
```

### No Findings
- Increase chunk size for deeper scanning
- Check Ollama model is downloaded: `ollama pull qwen2.5:1.5b`
- Verify URLs are accessible

---

##  License

MIT License - See LICENSE file for details

---

##  Disclaimer

This tool is for **authorized security testing only**. Unauthorized scanning of systems you don't own or have permission to test is illegal. The authors are not responsible for misuse.

---

##  Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

##  Contact

For issues and feature requests, please use GitHub Issues.

---

**Made with  for the Bug Bounty Community**
