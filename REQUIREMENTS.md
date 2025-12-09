# ReconFusionAI - Complete Requirements Guide

## Python Version
- **Required**: Python 3.8 or higher
- **Recommended**: Python 3.9+

### Why Python 3.8+?
- `dataclasses` (built-in from 3.7)
- `asyncio` improvements (3.7+)
- Type hints support (`typing` module)

---

## Python Libraries

### External Libraries (Install Required)
These need to be installed via `pip install -r requirements.txt`:

1. **httpx** (>=0.24.0)
   - Async HTTP client
   - Used for: Web requests, API calls
   
2. **psutil** (>=5.9.0)
   - System monitoring
   - Used for: CPU/GPU monitoring, hardware throttling
   
3. **tqdm** (>=4.65.0)
   - Progress bars
   - Used for: Visual progress indicators during scanning

### Built-in Libraries (No Installation Needed)
These come with Python by default:

- `asyncio` - Async programming
- `json` - JSON parsing
- `re` - Regular expressions
- `os` - Operating system interface
- `sys` - System parameters
- `subprocess` - Process management
- `hashlib` - Hashing (MD5 for cache)
- `math` - Mathematical functions
- `sqlite3` - Database (for AI cache)
- `time` - Time functions
- `logging` - Logging system
- `typing` - Type hints
- `datetime` - Date/time operations
- `urllib` - URL parsing
- `collections` - OrderedDict for LRU cache
- `dataclasses` - Data structures

---

## External Software

### Ollama (AI Model Runtime)
**Required**: Yes

**Installation:**
```bash
# Linux
curl https://ollama.ai/install.sh | sh

# macOS
brew install ollama

# Windows (WSL)
curl https://ollama.ai/install.sh | sh
```

**Model Download:**
```bash
ollama pull qwen2.5:1.5b
```

**Why Qwen 2.5:1.5b?**
- Fast inference (~0.5s per analysis)
- Low memory footprint (~2GB RAM)
- Good accuracy for secret detection
- Runs on CPU

**Alternative Models:**
You can try other models in `config.json`:
- `qwen2.5:0.5b` - Faster, less accurate
- `qwen2.5:3b` - Slower, more accurate
- `llama2:7b` - Alternative (requires more RAM)

---

## Optional Requirements

### Telegram (for Alerts)
**Required**: No (completely optional)

If you want Telegram notifications:
1. Create bot via [@BotFather](https://t.me/BotFather)
2. Get your chat ID from [@userinfobot](https://t.me/userinfobot)
3. Update `config.json`:
   ```json
   {
     "telegram": {
       "bot_token": "YOUR_TOKEN",
       "chat_id": "YOUR_CHAT_ID",
       "enabled": true
     }
   }
   ```

### GPU Monitoring Tools (Optional)
For GPU temperature monitoring:

**NVIDIA:**
- `nvidia-smi` (comes with NVIDIA drivers)

**AMD:**
- `rocm-smi` (install ROCm toolkit)

**Generic:**
- `lm-sensors` (Linux)
  ```bash
  sudo apt install lm-sensors
  sudo sensors-detect
  ```

---

## Installation Steps

### 1. Check Python Version
```bash
python3 --version  # Should be 3.8+
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Ollama
```bash
# Linux/macOS
curl https://ollama.ai/install.sh | sh

# Verify installation
ollama --version
```

### 4. Download AI Model
```bash
ollama pull qwen2.5:1.5b
```

### 5. Configure Tool
```bash
cp config.json.example config.json
nano config.json  # Edit as needed
```

---

## Verification

### Test Python Dependencies
```bash
python3 -c "import httpx, psutil, tqdm; print(' All dependencies installed')"
```

### Test Ollama
```bash
ollama list  # Should show qwen2.5:1.5b
```

### Test Tool
```bash
python3 reconfusionai.py urls_example.txt
```

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'httpx'"
```bash
pip install httpx psutil tqdm
```

### "Ollama connection error"
```bash
# Start Ollama service
ollama serve  # Keep this running in background
```

### "Python version too old"
```bash
# Install Python 3.9
sudo apt install python3.9 python3.9-pip  # Ubuntu/Debian
brew install python@3.9  # macOS
```

---

## Summary

### Must Have:
 Python 3.8+
 httpx, psutil, tqdm
 Ollama
 qwen2.5:1.5b model

### Optional:
 Telegram bot (for alerts)
 GPU monitoring tools
 Virtual environment (recommended)

### No Installation Needed:
 All standard Python libraries (asyncio, json, re, etc.)

---

**Total Download Size:**
- Python libraries: ~5MB
- Ollama: ~100MB
- Qwen 2.5:1.5b model: ~900MB

**Total Disk Space:** ~1GB
