#!/usr/bin/env python3
"""
ReconFusionAI - Intelligent Web Asset Scanner
Contextual AI-powered secret detection with multi-source intelligence fusion
"""

import asyncio
import httpx
import logging
import os
import sys
import json
import re
import subprocess
import psutil
import hashlib
import math
import sqlite3
import time
from typing import Optional, Dict, List, Tuple, Set
from datetime import datetime, timedelta
from urllib.parse import urlparse
from collections import Counter, OrderedDict
from dataclasses import dataclass, asdict, field
from tqdm import tqdm
from tqdm.asyncio import tqdm as atqdm

# ============================================================
# CONFIGURATION
# ============================================================
CONCURRENT_REQUESTS = 10
TIMEOUT = 15.0
MAX_CHUNK_SIZE_JS = 150 * 1024
MAX_CHUNK_SIZE_DEFAULT = 1024
MAX_DEEP_SCAN_SIZE = 300 * 1024
AI_RATE_LIMIT_DELAY = 0.5

# Optimization Settings
CONTEXT_WINDOW_LINES = 3
MAX_AI_TOKENS = 512
MINIFIED_LINE_THRESHOLD = 300
MIN_SECRET_ENTROPY = 3.0

# Cache Settings
MAX_SNIPPET_CACHE_SIZE = 10000  # LRU cache max entries
AI_CACHE_TTL_HOURS = 1  # AI results TTL
AI_CACHE_DB = "ai_cache.db"

# Deep Scan Settings
MAX_DEEP_SCAN_SIZE = 300 * 1024  # 300KB

# Hardware Monitoring
CPU_THRESHOLD = 85
GPU_TEMP_THRESHOLD = 80
COOLDOWN_DURATION = 30

# Telegram Configuration
TELEGRAM_BOT_TOKEN = ""  # Loaded from config.json
TELEGRAM_CHAT_ID = ""  # Loaded from config.json

# Ollama
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:1.5b"

# User Agent
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Ignore patterns
IGNORE_SIGNATURES = [
    "lorem ipsum",
    "example.com",
    "test@test.com"
]

# Allowed Content Types
ALLOWED_CONTENT_TYPES = [
    "text/html",
    "application/json",
    "application/javascript",
    "text/javascript",
    "text/plain"
]

# Risk Thresholds
THRESHOLD_CRITICAL = 0.75
THRESHOLD_HIGH = 0.6

# ============================================================
# CRITICAL PATTERNS (Send to AI for Analysis)
# ============================================================
CRITICAL_PATTERNS = {
    # --- Cloud Providers ---
    'AWS_ACCESS_KEY': re.compile(r'((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})'),
    'AWS_SECRET_KEY': re.compile(r'["\']([0-9a-zA-Z\/+]{40})["\']'),
    'GOOGLE_API_KEY': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    'GOOGLE_OAUTH': re.compile(r'ya29\.[0-9A-Za-z\-_]+'),
    'FIREBASE': re.compile(r'[a-z0-9.-]+\.firebaseio\.com'),
    'AZURE_ACCESS_KEY': re.compile(r'[a-zA-Z0-9]{88}'),
    'HEROKU_API_KEY': re.compile(r'[h|H]eroku\s*[=:]\s*["\']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']'),
    'DIGITALOCEAN_TOKEN': re.compile(r'dop_v1_[a-f0-9]{64}'),
    'MAILGUN': re.compile(r'key-[0-9a-zA-Z]{32}'),
    
    # --- CI/CD & Dev Tools ---
    'GITHUB_TOKEN': re.compile(r'((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})'),
    'GITHUB_OAUTH': re.compile(r'[a-f0-9]{40}'),
    'GITLAB_TOKEN': re.compile(r'glpat-[0-9a-zA-Z\-_]{20}'),
    'NPM_ACCESS_TOKEN': re.compile(r'npm_[a-z0-9]{36}'),
    'DOCKER_AUTH': re.compile(r'{"auths":{[^}]+}}'),
    
    # --- Messaging & Social ---
    'SLACK_TOKEN': re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})'),
    'SLACK_WEBHOOK': re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'),
    'DISCORD_WEBHOOK': re.compile(r'https://discordapp\.com/api/webhooks/[0-9]+/[A-Za-z0-9-]+'),
    'TWILIO_SID': re.compile(r'AC[a-zA-Z0-9_\-]{32}'),
    'TELEGRAM_BOT': re.compile(r'[0-9]+:AA[0-9A-Za-z\-_]{33}'),
    
    # --- Payment & Security ---
    'STRIPE_KEY': re.compile(r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}'),
    'PAYPAL_TOKEN': re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),
    'SQUARE_ACCESS_TOKEN': re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}'),
    'PRIVATE_KEY': re.compile(r'-----BEGIN (?:RSA|DSA|EC|PGP) PRIVATE KEY'),
    'RSA_PRIVATE': re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
    'JWT_TOKEN': re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    
    # --- Generic High-Entropy Secrets ---
    'GENERIC_API_KEY': re.compile(r'(?i)(?:api_key|apikey|access_token|auth_token|api_secret|client_secret)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|"]|[\s|\']|[\s|`])([0-9a-z]{32,})', re.IGNORECASE),
    'PASSWORD_ASSIGNMENT': re.compile(r'(?i)(?:password|passwd|pwd|secret)(?:[0-9a-z\-_\t .]{0,20})(?:=|:)(?:[\s|"]|[\s|\']|[\s|`])([0-9a-zA-Z@#$%]{8,})', re.IGNORECASE),
    
    # --- Authorization & Authentication ---
    'AUTH_BEARER': re.compile(r'Authorization[:\s]*Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)', re.IGNORECASE),
    'BASIC_AUTH': re.compile(r'Authorization[:\s]*Basic\s+([A-Za-z0-9+/=]{16,})', re.IGNORECASE),
    'AWS_SESSION_TOKEN': re.compile(r'(ASIA[0-9A-Z]{16,})'),
    'REFRESH_TOKEN': re.compile(r'refresh_token["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']', re.IGNORECASE),
    
    # --- Private Keys (Extended) ---
    'OPENSSH_PRIVATE_KEY': re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
    'PGP_PRIVATE_KEY': re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    'GSA_PRIVATE_KEY_JSON': re.compile(r'"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----', re.IGNORECASE),
    
    # --- Azure & Cloud Tokens ---
    'AZURE_SAS_SIG': re.compile(r'sig=[A-Za-z0-9%\-_.]{16,}', re.IGNORECASE),
    
    # --- Database Credentials ---
    'DATABASE_URL': re.compile(r'(postgres|mysql|mssql|sqlserver)://[^\s\'"]{5,}', re.IGNORECASE),
    
    # --- Exposed Files & Configs ---
    'GIT_REPO_EXPOSED': re.compile(r'/(?:\.git/(?:HEAD|config|index|objects|refs)|\.gitignore\b)', re.IGNORECASE),
    'DOTENV_EXPOSED': re.compile(r'\.env\b|(?:DB_PASSWORD|DATABASE_URL|APP_KEY)=', re.IGNORECASE),
    
    # --- Debug & Development ---
    'PHPINFO_OR_DEBUG': re.compile(r'phpinfo\(|display_errors\s*=\s*on|dump\(|var_dump\(', re.IGNORECASE),
    'LONG_BASE64': re.compile(r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']'),
    'COMMENT_CREDENTIAL_HINTS': re.compile(r'<!--[^>]{0,200}(password|passwd|pwd|secret|api[_\s-]?key|token)[^>]{0,200}-->', re.IGNORECASE),
    
    # --- WordPress Critical (Database & Auth) ---
    'WP_DB_PASSWORD': re.compile(r'define\s*\(\s*[\'"]DB_PASSWORD[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\);'),
    'WP_DB_USER': re.compile(r'define\s*\(\s*[\'"]DB_USER[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\);'),
    'WP_AUTH_KEY': re.compile(r'define\s*\(\s*[\'"](?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\);'),
    'WP_SQL_DUMP_HEADER': re.compile(r'--\s+Host:\s+.*Database:\s+'),
    'WP_SQL_INSERT_USERS': re.compile(r'INSERT\s+INTO\s+[`"\']?wp_users[`"\']?'),
    'WP_FATAL_ERROR': re.compile(r'Fatal error:\s+Uncaught Error:'),
    'WP_DEBUG_STACKTRACE': re.compile(r'#\d+\s+.*wp-content/plugins/'),
}

# ============================================================
# DISCOVERY PATTERNS (Save to file directly - No AI)
# ============================================================
DISCOVERY_PATTERNS = {
    # --- Storage Buckets (Potential Takeover/Data Leak) ---
    'S3_BUCKET': re.compile(r'[a-z0-9.-]+\.s3\.amazonaws\.com'),
    'S3_BUCKET_ALT': re.compile(r'[a-z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com'),
    'GOOGLE_STORAGE': re.compile(r'[a-z0-9.-]+\.storage\.googleapis\.com'),
    'AZURE_BLOB': re.compile(r'[a-z0-9.-]+\.blob\.core\.windows\.net'),
    'DIGITALOCEAN_SPACE': re.compile(r'[a-z0-9.-]+\.digitaloceanspaces\.com'),
    
    # --- Databases & Services ---
    'FIREBASE_DB': re.compile(r'[a-z0-9.-]+\.firebaseio\.com'),
    'MONGODB_URI': re.compile(r'mongodb://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@'),
    'REDIS_URI': re.compile(r'redis://:[a-zA-Z0-9_]+@'),
    'POSTGRES_URI': re.compile(r'postgres://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@'),
    
    # --- Interesting Parameters (XSS/SSRF/LFI/IDOR) ---
    'DANGEROUS_PARAMS': re.compile(r'[\?&](?:redirect|url|path|file|dest|target|source|callback|return|id|user|account|debug|admin|token|auth|key)=', re.IGNORECASE),
    
    # --- Network & Internal ---
    'INTERNAL_IP': re.compile(r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b'),
    'INTERNAL_DOMAIN': re.compile(r'[a-z0-9.-]+\.(?:internal|staging|dev|local|test|corp|intranet)\.[a-z]{2,}', re.IGNORECASE),
    
    # --- Sensitive PII/Info ---
    'EMAIL_ADDRESS': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    'DEV_COMMENT': re.compile(r'(?i)(?:TODO|FIXME|HACK|BUG|XXX|NOTE)[:\s](.{10,100})'),
    
    # --- Client-Side Vulnerabilities ---
    'INNERHTML_USAGE': re.compile(r'\.innerHTML\s*=', re.IGNORECASE),
    'EVAL_USAGE': re.compile(r'\beval\s*\(', re.IGNORECASE),
    'POSTMESSAGE': re.compile(r'\.postMessage\s*\(', re.IGNORECASE),
    'LOCATION_HASH': re.compile(r'location\.hash', re.IGNORECASE),
    'LOCATION_SEARCH': re.compile(r'location\.search', re.IGNORECASE),
    'WINDOW_NAME': re.compile(r'window\.name', re.IGNORECASE),
    
    # --- Backup & Archive Files ---
    'BACKUP_FILES': re.compile(r'\.(?:bak|backup|old|zip|tar\.gz|sql|tar|tgz)$', re.IGNORECASE),
    'WELL_KNOWN': re.compile(r'/.well-known/|/server-status|/admin/|/manager/html', re.IGNORECASE),
    'PACKAGE_MANIFEST': re.compile(r'package\.json|composer\.json|requirements\.txt', re.IGNORECASE),
    
    # --- WordPress Discovery (Exposed Files & Vulnerabilities) ---
    'WP_DEBUG_LOG': re.compile(r'wp-content/debug\.log'),
    'WP_CONFIG_BACKUP': re.compile(r'wp-config\.php\.(?:bak|old|swp|txt|save|orig)'),
    'WP_INSTALL_FILE': re.compile(r'wp-admin/install\.php'),
    'WP_XMLRPC': re.compile(r'xmlrpc\.php'),
    'WP_JSON_USERS': re.compile(r'wp-json/wp/v2/users'),
    'WP_AUTHOR_ARCHIVE': re.compile(r'/author/([a-zA-Z0-9_\-]+)/?'),
    'WP_YOAST_SEO_USERS': re.compile(r'"@type":"Person","name":"([^"]+)"'),
    'WP_TIMTHUMB': re.compile(r'(?:timthumb|thumb)\.php\?src='),
    'WP_VERSION_META': re.compile(r'<meta name="generator" content="WordPress ([0-9.]+)"'),
    'WP_OBSOLETE_PLUGIN': re.compile(r'/wp-content/plugins/(revslider|duplicator|contact-form-7|elementor)/'),
    'WP_DIRECTORY_LISTING': re.compile(r'Index of /wp-content/uploads'),
    'WP_FULL_PATH_DISCLOSURE': re.compile(r'/(?:var|home|usr)/www/[a-zA-Z0-9_/\-]+/wp-content/'),
    'WP_PHP_IN_UPLOADS': re.compile(r'wp-content/uploads/.*\.(?:php|php5|phtml)'),
}


# Load configuration
def load_config():
    config_file = "config.json"
    if not os.path.exists(config_file):
        print(f"{Colors.YELLOW}[!] config.json not found. Using default settings.{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Copy config.json.example and configure your settings.{Colors.RESET}")
        return {}
    
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"{Colors.RED}[!] Error loading config: {e}{Colors.RESET}")
        return {}

config = load_config()

# Update configuration from config.json
if config:
    TELEGRAM_BOT_TOKEN = config.get('telegram', {}).get('bot_token', '')
    TELEGRAM_CHAT_ID = config.get('telegram', {}).get('chat_id', '')
    TELEGRAM_ENABLED = config.get('telegram', {}).get('enabled', False)
    OLLAMA_URL = config.get('ollama', {}).get('url', 'http://localhost:11434/api/generate')
    OLLAMA_MODEL = config.get('ollama', {}).get('model', 'qwen2.5:1.5b')
    CONCURRENT_REQUESTS = config.get('scanning', {}).get('concurrent_requests', 10)
    TIMEOUT = config.get('scanning', {}).get('timeout', 15.0)
    THRESHOLD_CRITICAL = config.get('thresholds', {}).get('critical', 0.75)
    THRESHOLD_HIGH = config.get('thresholds', {}).get('high', 0.6)
    CPU_THRESHOLD = config.get('hardware', {}).get('cpu_threshold', 85)
    GPU_TEMP_THRESHOLD = config.get('hardware', {}).get('gpu_temp_threshold', 80)
else:
    TELEGRAM_ENABLED = False

# ANSI Colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Reduce logging verbosity - only show warnings and errors
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AssetHunter")

# LRU Cache for snippet deduplication
class LRUCache:
    def __init__(self, max_size: int = MAX_SNIPPET_CACHE_SIZE):
        self.cache: OrderedDict = OrderedDict()
        self.max_size = max_size
    
    def contains(self, key: str) -> bool:
        if key in self.cache:
            # Move to end (most recently used)
            self.cache.move_to_end(key)
            return True
        return False
    
    def add(self, key: str):
        if key in self.cache:
            self.cache.move_to_end(key)
        else:
            self.cache[key] = True
            if len(self.cache) > self.max_size:
                # Remove oldest (first) item
                self.cache.popitem(last=False)
    
    def size(self) -> int:
        return len(self.cache)

snippet_cache = LRUCache()

# SQLite AI Cache
class AICache:
    def __init__(self, db_path: str = AI_CACHE_DB, ttl_hours: int = AI_CACHE_TTL_HOURS):
        self.db_path = db_path
        self.ttl = timedelta(hours=ttl_hours)
        self._init_db()
    
    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS ai_cache (
                    snippet_hash TEXT PRIMARY KEY,
                    response TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON ai_cache(timestamp)')
            conn.commit()
            conn.close()
            logger.debug(f"[AI CACHE] Initialized at {self.db_path}")
        except Exception as e:
            logger.error(f"[AI CACHE] Init failed: {e}")
    
    def get(self, snippet_hash: str) -> Optional[str]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute(
                'SELECT response, timestamp FROM ai_cache WHERE snippet_hash = ?',
                (snippet_hash,)
            )
            row = cursor.fetchone()
            conn.close()
            
            if row:
                response, timestamp = row
                # Check TTL
                if datetime.now() - datetime.fromtimestamp(timestamp) < self.ttl:
                    logger.debug(f"[AI CACHE] HIT for {snippet_hash[:8]}...")
                    return response
                else:
                    logger.debug(f"[AI CACHE] EXPIRED for {snippet_hash[:8]}...")
                    self.delete(snippet_hash)
            return None
        except Exception as e:
            logger.error(f"[AI CACHE] Get error: {e}")
            return None
    
    def set(self, snippet_hash: str, response: str):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                'INSERT OR REPLACE INTO ai_cache (snippet_hash, response, timestamp) VALUES (?, ?, ?)',
                (snippet_hash, response, time.time())
            )
            conn.commit()
            conn.close()
            logger.debug(f"[AI CACHE] SET for {snippet_hash[:8]}...")
        except Exception as e:
            logger.error(f"[AI CACHE] Set error: {e}")
    
    def delete(self, snippet_hash: str):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('DELETE FROM ai_cache WHERE snippet_hash = ?', (snippet_hash,))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"[AI CACHE] Delete error: {e}")
    
    def cleanup_expired(self):
        try:
            cutoff = (datetime.now() - self.ttl).timestamp()
            conn = sqlite3.connect(self.db_path)
            result = conn.execute('DELETE FROM ai_cache WHERE timestamp < ?', (cutoff,))
            deleted = result.rowcount
            conn.commit()
            conn.close()
            if deleted > 0:
                logger.info(f"[AI CACHE] Cleaned up {deleted} expired entries")
        except Exception as e:
            logger.error(f"[AI CACHE] Cleanup error: {e}")

ai_cache = AICache()

# ============================================================
# DATA STRUCTURES
# ============================================================

@dataclass
class RegexFinding:
    """Structured regex finding with full context."""
    pattern_name: str       # "API_KEY", "JWT", etc.
    pattern: str            # Actual regex pattern
    match: str              # Full matched text
    value: str              # Extracted secret value
    line_number: int        # Where in file
    context_snippet: str    # ±3 lines around match
    entropy: float          # Shannon entropy of value

@dataclass
class AIAnalysis:
    """AI's contextual understanding of a finding."""
    pattern: str                # Which regex pattern
    purpose: str                # "Stripe API key", "JWT auth token"
    risk_level: float           # 0.0-1.0
    reasoning: str              # Why this risk level
    context_relationship: str   # "production config", "debug code"
    confidence: float           # AI's confidence in analysis
    matched_value: str = ""     # Actual matched secret value (linked from RegexFinding)

@dataclass
class HeuristicEnhancement:
    """Type-specific heuristic modifiers."""
    risk_modifier: float        # ±0.5 adjustment
    applied_rules: List[str]    # Which rules triggered
    metadata: Dict              # Additional context

@dataclass
class FusionAssessment:
    """Final contextually-fused assessment."""
    url: str
    final_score: float
    severity: str               # CRITICAL/HIGH/MEDIUM/LOW
    regex_findings: List[Dict]  # List of RegexFinding dicts
    ai_analysis: List[Dict]     # List of AIAnalysis dicts
    heuristic_enhancement: Dict  # HeuristicEnhancement dict
    reasoning_chain: List[str]  # Step-by-step explanation

# ============================================================
# UTILITIES
# ============================================================

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return entropy

def is_high_entropy_secret(secret: str) -> bool:
    """
    Validate if a secret has sufficient randomness.
    Length-dependent thresholds to reduce false positives.
    """
    length = len(secret)
    
    # Too short
    if length < 8:
        return False
    
    # Calculate entropy
    entropy = calculate_entropy(secret)
    
    # Length-dependent thresholds
    if length < 12:
        # Short secrets need higher entropy (3.5+)
        return entropy >= 3.5
    elif length < 20:
        # Medium secrets (3.2+)
        return entropy >= 3.2
    else:
        # Long secrets (3.0+)
        return entropy >= MIN_SECRET_ENTROPY
    
    # Additional check: reject if too many repeated characters
    if len(set(secret)) < length * 0.3:  # Less than 30% unique chars
        return False
    
    return True

def get_line_number(text: str, char_index: int) -> int:
    """Get line number for a character index."""
    return text[:char_index].count('\n') + 1

def get_context_window(text: str, match_index: int, window_lines: int = CONTEXT_WINDOW_LINES) -> str:
    """Extract context around a match (N lines before/after)."""
    lines = text.split('\n')
    
    # Find line number of match
    char_count = 0
    match_line = 0
    for i, line in enumerate(lines):
        char_count += len(line) + 1
        if char_count >= match_index:
            match_line = i
            break
    
    # Extract window
    start_line = max(0, match_line - window_lines)
    end_line = min(len(lines), match_line + window_lines + 1)
    
    context = '\n'.join(lines[start_line:end_line])
    
    # Limit to MAX_AI_TOKENS characters
    if len(context) > MAX_AI_TOKENS * 4:
        context = context[:MAX_AI_TOKENS * 4]
    
    return context

def get_snippet_hash(text: str) -> str:
    """Generate MD5 hash of snippet for deduplication."""
    return hashlib.md5(text.encode()).hexdigest()

def is_duplicate_snippet(text: str) -> bool:
    """Check if this snippet was already analyzed (LRU cache)."""
    snippet_hash = get_snippet_hash(text)
    if snippet_cache.contains(snippet_hash):
        return True
    snippet_cache.add(snippet_hash)
    return False

class RateLimiter:
    def __init__(self, delay_seconds: float):
        self.delay = delay_seconds
        self.last_call_time = None
        self.lock = asyncio.Lock()
    
    async def wait(self):
        async with self.lock:
            if self.last_call_time is not None:
                elapsed = asyncio.get_event_loop().time() - self.last_call_time
                if elapsed < self.delay:
                    await asyncio.sleep(self.delay - elapsed)
            self.last_call_time = asyncio.get_event_loop().time()

class HardwareMonitor:
    def __init__(self, cpu_threshold: int = CPU_THRESHOLD, gpu_temp_threshold: int = GPU_TEMP_THRESHOLD):
        self.cpu_threshold = cpu_threshold
        self.gpu_temp_threshold = gpu_temp_threshold
        self.cooldown_duration = COOLDOWN_DURATION
        
    def get_cpu_usage(self) -> float:
        try:
            return psutil.cpu_percent(interval=0.1)
        except Exception:
            return 0.0
    
    def get_gpu_temperature(self) -> Optional[float]:
        # Try NVIDIA
        try:
            result = subprocess.run(
                ['nvidia-smi', '--query-gpu=temperature.gpu', '--format=csv,noheader,nounits'],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                return float(result.stdout.strip().split('\n')[0])
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, IndexError):
            pass
        
        # Try AMD
        try:
            result = subprocess.run(['rocm-smi', '--showtemp'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Temperature' in line or 'Temp' in line:
                        temps = re.findall(r'(\d+\.?\d*)\s*[Cc]', line)
                        if temps:
                            return float(temps[0])
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
            pass
        
        # Try sensors
        try:
            result = subprocess.run(['sensors'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if any(kw in line.lower() for kw in ['gpu', 'edge', 'junction']):
                        temps = re.findall(r'\+(\d+\.?\d*).C', line)
                        if temps:
                            return float(temps[0])
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
            pass
        
        return None
    
    async def throttle_if_needed(self):
        cpu_usage = self.get_cpu_usage()
        gpu_temp = self.get_gpu_temperature()
        
        needs_cooldown = False
        reasons = []
        
        if cpu_usage > self.cpu_threshold:
            needs_cooldown = True
            reasons.append(f"CPU: {cpu_usage:.1f}%")
        
        if gpu_temp is not None and gpu_temp > self.gpu_temp_threshold:
            needs_cooldown = True
            reasons.append(f"GPU: {gpu_temp:.1f}°C")
        
        if needs_cooldown:
            reason_str = ", ".join(reasons)
            logger.warning(f"{Colors.YELLOW}[WARNING] Overheating ({reason_str}). Pausing {self.cooldown_duration}s...{Colors.RESET}")
            await asyncio.sleep(self.cooldown_duration)
            logger.info(f"{Colors.GREEN}[COOLDOWN] Resuming{Colors.RESET}")

# ============================================================
# STAGE 1: REGEX DETECTION WITH CONTEXT
# ============================================================

def extract_regex_findings(text: str) -> List[RegexFinding]:
    """
    Extract all regex matches with full context.
    Returns structured findings for AI analysis.
    """
    findings = []
    
    for pattern_name, pattern in CRITICAL_PATTERNS.items():
        for match in re.finditer(pattern, text):
            # Extract the secret value
            try:
                secret = match.group(1) if match.groups() else match.group(0)
            except IndexError:
                secret = match.group(0)
            
            # Entropy check
            if not is_high_entropy_secret(secret):
                logger.debug(f"[ENTROPY] Low entropy secret rejected: {pattern_name}")
                continue
            
            # Get line number and context
            line_num = get_line_number(text, match.start())
            context = get_context_window(text, match.start())
            
            finding = RegexFinding(
                pattern_name=pattern_name,
                pattern=pattern.pattern,
                match=match.group(0),
                value=secret,
                line_number=line_num,
                context_snippet=context,
                entropy=calculate_entropy(secret)
            )
            
            findings.append(finding)
            logger.info(f"{Colors.CYAN}[REGEX] {pattern_name} detected at line {line_num}{Colors.RESET}")
    
    return findings

@dataclass
class DiscoveryFinding:
    """Reconnaissance finding (no AI analysis needed)."""
    pattern_name: str
    match: str
    line_number: int
    url: str = ""

def extract_discovery_findings(text: str, url: str = "") -> List[DiscoveryFinding]:
    """
    Extract reconnaissance patterns (S3 buckets, IPs, params, etc.)
    These are saved directly without AI analysis.
    """
    findings = []
    
    for pattern_name, pattern in DISCOVERY_PATTERNS.items():
        for match in re.finditer(pattern, text):
            line_num = get_line_number(text, match.start())
            
            finding = DiscoveryFinding(
                pattern_name=pattern_name,
                match=match.group(0),
                line_number=line_num,
                url=url
            )
            
            findings.append(finding)
            logger.info(f"{Colors.BLUE}[DISCOVERY] {pattern_name} found: {match.group(0)[:50]}{Colors.RESET}")
    
    return findings


# ============================================================
# STAGE 2: AI CONTEXTUAL REASONING
# ============================================================

async def call_ollama(client: httpx.AsyncClient, prompt: str, format_json: bool = True) -> Optional[str]:
    try:
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        }
        if format_json:
            payload["format"] = "json"
        
        response = await client.post(OLLAMA_URL, json=payload, timeout=30.0)
        
        if response.status_code == 200:
            return response.json().get("response", "")
        else:
            logger.error(f"[OLLAMA] HTTP {response.status_code}: {response.text[:200]}")
        return None
    except httpx.TimeoutException as e:
        logger.error(f"[OLLAMA] Timeout: {e}")
        return None
    except httpx.RequestError as e:
        logger.error(f"[OLLAMA] Request error: {e}")
        return None
    except Exception as e:
        logger.exception(f"[OLLAMA] Unexpected error: {e}")
        return None

async def ai_contextual_analysis(
    client: httpx.AsyncClient,
    regex_findings: List[RegexFinding],
    full_text: str,
    url: str,
    hw_monitor: HardwareMonitor = None
) -> List[AIAnalysis]:
    """
    Send regex findings to AI for contextual reasoning.
    AI understands WHAT regex found and WHY it matters.
    """
    if hw_monitor:
        await hw_monitor.throttle_if_needed()
    
    if not regex_findings:
        # No regex findings - do generic AI scan
        return []
    
    # Check AI cache first
    cache_key_parts = [f"{f.pattern_name}:{f.value[:20]}" for f in regex_findings]
    cache_key = hashlib.md5(":".join(cache_key_parts).encode()).hexdigest()
    
    cached_response = ai_cache.get(cache_key)
    if cached_response:
        logger.info(f"{Colors.GREEN}[AI CACHE] Using cached response{Colors.RESET}")
        response_text = cached_response
    else:
        # Build concise, few-shot prompt
        findings_summary = ", ".join([f"{f.pattern_name} (line {f.line_number})" for f in regex_findings])
        
        # Use ONLY the first finding's context (most relevant)
        primary_context = regex_findings[0].context_snippet[:200]
        
        # Metadata summary
        metadata = f"URL: {url.split('?')[0]}, Patterns: {findings_summary}"
        
        prompt = f"""Security analyst task: Assess secret risk.

FINDINGS: {findings_summary}
CONTEXT: {primary_context}
METADATA: {metadata}

For pattern {regex_findings[0].pattern_name}:
- PURPOSE: (e.g., "Stripe prod key", "JWT token", "AWS key")
- RISK: 0.0-1.0 (test=0.3, debug=0.5, prod client-side=0.9)
- RELATIONSHIP: (e.g., "production config", "test fixture")

Example:
{{"findings": [{{"pattern": "API_KEY", "purpose": "Stripe prod key", "risk_level": 0.9, "reasoning": "Live key, client-side", "context_relationship": "prod config", "confidence": 0.85}}]}}

Reply JSON only:"""
        
        response_text = await call_ollama(client, prompt, format_json=True)
        if not response_text:
            return []
        
        # Cache the response
        ai_cache.set(cache_key, response_text)
    
    try:
        result = json.loads(response_text)
        analyses = []
        
        # Link AI findings to regex findings by pattern
        regex_by_pattern = {f.pattern_name: f for f in regex_findings}
        
        for ai_finding in result.get("findings", []):
            pattern_name = ai_finding.get("pattern", "UNKNOWN")
            matched_value = ""
            
            # Link to regex finding for matched_value
            if pattern_name in regex_by_pattern:
                matched_value = regex_by_pattern[pattern_name].value
            
            analysis = AIAnalysis(
                pattern=pattern_name,
                purpose=ai_finding.get("purpose", "Unknown purpose"),
                risk_level=max(0.0, min(1.0, float(ai_finding.get("risk_level", 0.5)))),
                reasoning=ai_finding.get("reasoning", "No reasoning provided"),
                context_relationship=ai_finding.get("context_relationship", "Unknown relationship"),
                confidence=max(0.0, min(1.0, float(ai_finding.get("confidence", 0.5)))),
                matched_value=matched_value
            )
            analyses.append(analysis)
            
            logger.info(f"{Colors.MAGENTA}[AI] {analysis.pattern} identified as: {analysis.purpose}{Colors.RESET}")
        
        return analyses
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"[AI PARSE ERROR] {e}")
        return []

# ============================================================
# STAGE 3: HEURISTIC ENHANCEMENT
# ============================================================

def apply_heuristic_enhancement(
    ai_analyses: List[AIAnalysis],
    url: str,
    status_code: int,
    content_type: str,
    full_content: str
) -> HeuristicEnhancement:
    """
    Apply type-specific heuristics based on AI's understanding.
    This is CONTEXTUAL - rules depend on what AI identified.
    """
    risk_modifier = 0.0
    applied_rules = []
    metadata = {}
    
    for analysis in ai_analyses:
        purpose_lower = analysis.purpose.lower()
        
        # JWT-specific heuristics
        if "jwt" in purpose_lower or analysis.pattern == "JWT":
            # Check for expiry
            if "exp" not in full_content.lower() and "expir" not in full_content.lower():
                risk_modifier += 0.2
                applied_rules.append("JWT without explicit expiry field")
            
            # Check for dangerous scope
            if "admin" in full_content.lower() or "root" in full_content.lower():
                risk_modifier += 0.3
                applied_rules.append("JWT with elevated privileges (admin/root)")
            
            metadata["token_type"] = "JWT"
        
        # AWS-specific heuristics
        elif "aws" in purpose_lower or analysis.pattern == "AWS_ACCESS":
            # Validate AKIA format (use matched_value from AIAnalysis)
            if "AKIA" in analysis.matched_value or "AKIA" in full_content:
                risk_modifier += 0.3
                applied_rules.append("Valid AWS access key ID format (AKIA)")
            
            # Check for AWS region indicators
            if any(region in full_content.lower() for region in ["us-east-1", "eu-west-1", "ap-southeast"]):
                risk_modifier += 0.2
                applied_rules.append("AWS region indicators found (production likely)")
            
            metadata["cloud_provider"] = "AWS"
        
        # API Key heuristics
        elif "api" in purpose_lower and "key" in purpose_lower:
            # Check for known providers
            if "stripe" in purpose_lower or "sk_live" in full_content:
                risk_modifier += 0.4
                applied_rules.append("Stripe production API key detected")
                metadata["api_provider"] = "Stripe"
            elif "google" in purpose_lower or "gcp" in purpose_lower:
                risk_modifier += 0.3
                applied_rules.append("Google Cloud API key detected")
                metadata["api_provider"] = "Google Cloud"
            
            # Check for key rotation policy
            if "rotat" not in full_content.lower() and "expir" not in full_content.lower():
                risk_modifier += 0.1
                applied_rules.append("No evidence of key rotation policy")
        
        # CRITICAL: Production context
        if "production" in analysis.context_relationship.lower():
            risk_modifier += 0.3
            applied_rules.append("Secret in production context")
        elif "debug" in analysis.context_relationship.lower() or "test" in analysis.context_relationship.lower():
            risk_modifier -= 0.2
            applied_rules.append("Secret in debug/test context (lower risk)")
    
    # URL-based heuristics (legacy support)
    parsed_url = urlparse(url)
    path =parsed_url.path.lower()
    
    if '/admin/' in path and status_code == 200:
        risk_modifier += 0.2
        applied_rules.append("Secret exposed in admin endpoint")
    
    if any(path.endswith(ext) for ext in ['.bak', '.old', '.env', '.sql']):
        risk_modifier += 0.3
        applied_rules.append("Secret in backup/config file")
    
    # Cap modifier at ±0.5
    risk_modifier = max(-0.5, min(0.5, risk_modifier))
    
    return HeuristicEnhancement(
        risk_modifier=risk_modifier,
        applied_rules=applied_rules,
        metadata=metadata
    )

# ============================================================
# STAGE 4: FUSION SCORING
# ============================================================

def calculate_fusion_score(
    regex_findings: List[RegexFinding],
    ai_analyses: List[AIAnalysis],
    heuristic: HeuristicEnhancement,
    url: str
) -> FusionAssessment:
    """
    Intelligent scoring based on fused context.
    NOT a weighted average - true contextual integration.
    """
    reasoning_chain = []
    
    # Base risk from AI's assessment (most intelligent source)
    if ai_analyses:
        # Use highest risk from AI analyses
        base_risk = max(analysis.risk_level for analysis in ai_analyses)
        primary_analysis = max(ai_analyses, key=lambda a: a.risk_level)
        
        reasoning_chain.append(f"→ Regex detected: {', '.join([f.pattern_name for f in regex_findings])}")
        reasoning_chain.append(f"→ AI identified as: {primary_analysis.purpose}")
        reasoning_chain.append(f"→ AI risk assessment: {primary_analysis.risk_level:.2f} - {primary_analysis.reasoning}")
        reasoning_chain.append(f"→ Context: {primary_analysis.context_relationship}")
        
        # Apply confidence multiplier
        confidence_factor = primary_analysis.confidence
        base_risk *= confidence_factor
        reasoning_chain.append(f"→ Confidence-adjusted risk: {base_risk:.2f}")
    else:
        # Fallback if AI fails
        base_risk = 0.5 if regex_findings else 0.0
        reasoning_chain.append(f"→ Regex detected {len(regex_findings)} patterns (AI unavailable)")
    
    # Apply heuristic modifiers (clamp before multiplication)
    if heuristic.applied_rules:
        for rule in heuristic.applied_rules:
            reasoning_chain.append(f"   Heuristic: {rule}")
        reasoning_chain.append(f"→ Heuristic modifier: {heuristic.risk_modifier:+.2f}")
        base_risk = max(0.0, min(0.95, base_risk + heuristic.risk_modifier))  # Clamp before multiplication
    
    # Context amplification based on relationship
    if ai_analyses:
        if "production" in primary_analysis.context_relationship.lower():
            base_risk *= 1.2
            reasoning_chain.append(f"→ Production context amplification: ×1.2")
        elif "client" in primary_analysis.context_relationship.lower():
            base_risk *= 1.3
            reasoning_chain.append(f"→ Client-side exposure amplification: ×1.3")
        elif "debug" in primary_analysis.context_relationship.lower():
            base_risk *= 0.6
            reasoning_chain.append(f"→ Debug context reduction: ×0.6")
    
    # Multiple secrets multiplier
    if len(regex_findings) > 2:
        base_risk *= 1.2
        reasoning_chain.append(f"→ Multiple secrets detected ({len(regex_findings)}): ×1.2")
    
    # Clamp final score
    final_score = max(0.0, min(1.0, base_risk))
    
    # Determine severity
    if final_score >= THRESHOLD_CRITICAL:
        severity = "CRITICAL"
    elif final_score >= THRESHOLD_HIGH:
        severity = "HIGH"
    elif final_score >= 0.4:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    reasoning_chain.append(f"→ Final score: {final_score:.2f} ({severity})")
    
    return FusionAssessment(
        url=url,
        final_score=round(final_score, 3),
        severity=severity,
        regex_findings=[asdict(f) for f in regex_findings],
        ai_analysis=[asdict(a) for a in ai_analyses],
        heuristic_enhancement=asdict(heuristic),
        reasoning_chain=reasoning_chain
    )

# ============================================================
# STAGE 1: LOCAL FILTRATION (unchanged from V3.0)
# ============================================================

async def process_url(semaphore: asyncio.Semaphore, client: httpx.AsyncClient, url: str) -> Optional[Dict]:
    async with semaphore:
        try:
            async with client.stream("GET", url) as response:
                if response.status_code in [404, 401, 403, 500]:
                    try:
                        chunk_iter = response.aiter_bytes(chunk_size=2048)
                        sample = await chunk_iter.__anext__()
                        sample_text = sample.decode('utf-8', errors='ignore').lower()
                        
                        if 'stack trace' in sample_text or 'debug' in sample_text or 'exception' in sample_text:
                            logger.info(f"[DEBUG] Error page with debug info: {url} ({response.status_code})")
                        else:
                            return None
                    except StopAsyncIteration:
                        return None
                
                if response.status_code not in [200, 403] and response.status_code not in [404, 401, 500]:
                    return None

                content_type = response.headers.get("content-type", "").lower()
                is_allowed_type = any(t in content_type for t in ALLOWED_CONTENT_TYPES)
                if not is_allowed_type:
                    return None
                
                is_javascript = "javascript" in content_type
                chunk_size = MAX_CHUNK_SIZE_JS if is_javascript else MAX_CHUNK_SIZE_DEFAULT
                
                chunk_iterator = response.aiter_bytes(chunk_size=chunk_size)
                try:
                    initial_bytes = await chunk_iterator.__anext__()
                except StopAsyncIteration:
                    initial_bytes = b""
                
                try:
                    initial_text = initial_bytes.decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.error(f"[FILTER] Decode error for {url}: {e}")
                    return None

                initial_lower = initial_text.lower()
                for sig in IGNORE_SIGNATURES:
                    if sig in initial_lower:
                        return None
                
                return {
                    "url": url,
                    "initial_chunk": initial_text,
                    "content_type": content_type,
                    "status_code": response.status_code,
                    "chunk_size": len(initial_bytes),
                    "response_handle": response  # Keep for controlled deep-scan
                }

        except httpx.RequestError as e:
            logger.error(f"[FILTER] Request error for {url}: {e}")
            return None
        except Exception as e:
            logger.exception(f"[FILTER] Unexpected error for {url}: {e}")
            return None

# ============================================================
# RISK ASSESSMENT PIPELINE - CONTEXTUAL FUSION
# ============================================================

async def assess_risk_with_fusion(
    client: httpx.AsyncClient,
    item: Dict,
    rate_limiter: RateLimiter,
    hw_monitor: HardwareMonitor = None
) -> Optional[FusionAssessment]:
    """
    Contextual fusion assessment pipeline.
    Each stage builds upon the previous one.
    """
    url = item['url']
    content = item['initial_chunk']
    content_type = item['content_type']
    status_code = item['status_code']
    
    # Check for deduplication
    if is_duplicate_snippet(content):
        logger.debug(f"[DEDUP] Skipping duplicate snippet")
        return None
    
    # STAGE 0: Extract discovery patterns (parallel to critical path)
    # These are saved separately without AI analysis
    discovery_findings = extract_discovery_findings(content, url)
    if discovery_findings:
        await save_discovery_findings(discovery_findings)
    
    # STAGE 1: Extract regex findings with context
    regex_findings = extract_regex_findings(content)
    
    if not regex_findings:
        # No findings - skip AI (save resources)
        return None
    
    # STAGE 2: AI contextual analysis (AI sees regex findings)
    await rate_limiter.wait()
    ai_analyses = await ai_contextual_analysis(
        client, regex_findings, content, url, hw_monitor
    )
    
    # STAGE 3: Heuristic enhancement (heuristics see AI output)
    heuristic = apply_heuristic_enhancement(
        ai_analyses, url, status_code, content_type, content
    )
    
    # STAGE 4: Fusion scoring (combines all context)
    assessment = calculate_fusion_score(
        regex_findings, ai_analyses, heuristic, url
    )
    
    # Only report HIGH and above
    if assessment.final_score < THRESHOLD_HIGH:
        return None
    
    return assessment

async def save_discovery_findings(findings: List[DiscoveryFinding]):
    """Save reconnaissance findings to separate file."""
    if not findings:
        return
    
    discoveries_file = "discoveries.json"
    entries = []
    
    for finding in findings:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "url": finding.url,
            "pattern_name": finding.pattern_name,
            "match": finding.match,
            "line_number": finding.line_number
        }
        entries.append(entry)
    
    try:
        existing = []
        if os.path.exists(discoveries_file):
            with open(discoveries_file, 'r') as f:
                try:
                    existing = json.load(f)
                except json.JSONDecodeError:
                    existing = []
        
        existing.extend(entries)
        
        with open(discoveries_file, 'w') as f:
            json.dump(existing, f, indent=2)
        
        logger.info(f"{Colors.BLUE}[DISCOVERY] Saved {len(findings)} findings to {discoveries_file}{Colors.RESET}")
    except Exception as e:
        logger.error(f"[DISCOVERY] Save error: {e}")


# ============================================================
# REPORTING
# ============================================================

async def save_finding_to_file(assessment: FusionAssessment):
    findings_file = "findings.json"
    entry = {
        "timestamp": datetime.now().isoformat(),
        "url": assessment.url,
        "severity": assessment.severity,
        "final_score": assessment.final_score,
        "reasoning_chain": assessment.reasoning_chain,
        "regex_findings": assessment.regex_findings,
        "ai_analysis": assessment.ai_analysis,
        "heuristic_enhancement": assessment.heuristic_enhancement
    }
    
    try:
        findings = []
        if os.path.exists(findings_file):
            with open(findings_file, 'r') as f:
                try:
                    findings = json.load(f)
                except json.JSONDecodeError:
                    findings = []
        
        findings.append(entry)
        
        with open(findings_file, 'w') as f:
            json.dump(findings, f, indent=2)
        
        logger.info(f"[FILE]  Saved to {findings_file}")
    except Exception:
        pass

async def send_telegram_alert(client: httpx.AsyncClient, assessment: FusionAssessment):
    if not TELEGRAM_ENABLED or not TELEGRAM_BOT_TOKEN:
        return
    """Alert for CRITICAL findings with reasoning chain."""
    if assessment.severity != "CRITICAL":
        return
    
    reasoning = "\n".join(assessment.reasoning_chain)
    
    message = f""" *CRITICAL VULNERABILITY* 

 *URL:* `{assessment.url}`
 *Risk Score:* {assessment.final_score:.2f}/1.0

*Reasoning Chain:*
```
{reasoning}
```

⏰ {datetime.now().strftime("%H:%M:%S")}
"""
    
    # Console
    print(f"\n{Colors.RED}{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BOLD} CRITICAL ALERT {Colors.RESET}")
    print(f"{Colors.RED}{'='*60}{Colors.RESET}")
    print(f"{Colors.YELLOW}URL:{Colors.RESET} {assessment.url}")
    print(f"{Colors.YELLOW}Final Score:{Colors.RESET} {assessment.final_score:.2f}")
    print(f"\n{Colors.CYAN}Reasoning Chain:{Colors.RESET}")
    for step in assessment.reasoning_chain:
        print(f"  {step}")
    print(f"{Colors.RED}{'='*60}{Colors.RESET}\n")
    
    # Save
    await save_finding_to_file(assessment)
    
    # Telegram
    try:
        telegram_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
        
        response = await client.post(telegram_url, json=payload)
        if response.status_code == 200:
            logger.info("[TELEGRAM]  Alert sent")
        else:
            logger.error(f"[TELEGRAM] Failed: {response.text}")
    except Exception as e:
        logger.error(f"[TELEGRAM ERROR] {e}")

# ============================================================
# STARTUP BANNER
# ============================================================

def show_skull_banner():
    """Display horror skull ASCII art in red."""
    skull = """@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@...@..*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.@*....,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.../*.,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.@/...,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@...*#.,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.@%...,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%/@....&.*@#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*.....@..@.../@.....%@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,.@@@&.@@.....##......@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.,@,..#.(@@@@@@@,.....@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*..*..&@............@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.@(.&@@@@@&,......*@@@#..@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@&...@@..(@..(@,.............@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@&...,.&@.@@%............../@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@......@&..@*..@@&%&@@@/.......@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@....((...%@@%.../...%%........./@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@,.....,@@@/./@*%@@@@@@@@@@@@@%...@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@*....*@.,@@@@@@&..#@..,@,...........#@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@,@&.....@@@@@@@&.@@@@@#,........(@@@.,@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@%...../.@@@@@@@@@&..@#..@&..,@..........@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@,&@*...#@@@@@@@@@@@@@,................(@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@.......%@@@@@@@@@@@%.*&.,#@@@@@@@@@@#,...@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@.,@#...@@@@@@@@@@@@......,../@@@@@&.........@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@......@@@@@@@@@@&.*@(......@@@@@@@@@..........@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@/...(@@@@@@@@@@....../%,.@@@@@@@@@@@@@..........@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@.(@%......@@@@@@@@@@@@@@@@@.........,@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@......%@*.@@@@@@@@@@@@@@@@@@@@&.........#@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@,.@@......@@@@@@@@@@@@@@@@@@@@@@@@#.........@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@.....*@&.@@@@@@@@@@@@@@@@@@@@@@@@@@@@,........,@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@&.@@/....,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&..,......@@@@@@@@@@
@@@@@@@@@@@@@@@@@#.....#@.@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.........@@@@@@@@@
@@@@@@@@@@@@@@@@@..@@....@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.........@@@@@@@@
@@@@@@@@@@@@@@@@./....@.%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@........*@@@@@@@
@@@@@@@@@@@@@@@@..,@*...@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%.#......@@@@@@@
@@@@@@@@@@@@@@@@.@...(.,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@....#...@@@@@@@
@@@@@@@@@@@@@@@@...@/...@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.,@.....@@@@@@@
@@@@@@@@@@@@@@@@..@...,.@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@....,...@@@@@@@
@@@@@@@@@@@@@@@@....@,..&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@..#@....,@@@@@@@
@@@@@@@@@@@@@@@@@..@...@./@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@......,..@@@@@@@@
@@@@@@@@@@@@@@@@@@....&....@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@..@@@....@@@@@@@@@
@@@@@@@@@@@@@@@@@@@...%..*...@@@@@@@@@@@@@@@@@@@@@@@@@@@@@..........@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@....&...@.,@@@@@@@@@@@@@@@@@@@@@@@..@%/,.....@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@,./...@...,.,@@@@@@@@@@@@@@#...@@@@@#((..@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@...,%..##..@,..*....*,....#@@,.....#@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&..../#...@...,@...../@,.....@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#.#....@.....((....%@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"""
    
    print(f"{Colors.RED}{skull}{Colors.RESET}\n")

# ============================================================
# MAIN
# ============================================================

async def main():
    # Show skull banner
    show_skull_banner()
    urls = []
    skip_phase1 = False  # Flag to skip Phase 1
    
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        
        # Check if filename starts with "s-" to skip Phase 1
        filename = os.path.basename(input_file)
        if filename.startswith("s-"):
            skip_phase1 = True
            print(f"{Colors.YELLOW}[*] s- prefix detected: Skipping Phase 1 (HTTP check){Colors.RESET}")
        
        try:
            with open(input_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(urls)} URLs from {input_file}")
        except FileNotFoundError:
            print("File not found.")
            sys.exit(1)
    else:
        print("[*] No input file. Using test URLs.")
        urls = [
            "https://www.google.com",
            "https://code.jquery.com/jquery-3.6.0.min.js",
            "http://testphp.vulnweb.com/AJAX/index.php",
            "http://testphp.vulnweb.com/login.php"
        ]

    # Cleanup expired AI cache entries
    ai_cache.cleanup_expired()
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}ASSET HUNTER V3.1 (CONTEXTUAL FUSION - PRODUCTION){Colors.RESET}")
    print(f"{Colors.CYAN} True Multi-Source Integration + Production Hardening{Colors.RESET}")
    print(f"{Colors.CYAN} LRU Cache | AI Cache (1h TTL) | Optimized Prompts | Enhanced Logging{Colors.RESET}\n")

    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)
    headers = {"User-Agent": USER_AGENT}
    
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False, headers=headers) as http_client:
        
        # Phase 1: Filter (or skip if s- prefix)
        if skip_phase1:
            print(f"{Colors.YELLOW}[Phase 1] SKIPPED - Creating mock items for direct analysis{Colors.RESET}")
            # Create mock items for all URLs without HTTP check
            survivors = []
            for url in tqdm(urls, desc=f"{Colors.CYAN}Creating mock items{Colors.RESET}", ncols=100, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}'):
                # Create a mock item with minimal content for AI to analyze
                mock_item = {
                    "url": url,
                    "initial_chunk": "",  # Empty content, AI will fetch if needed
                    "content_type": "text/html",
                    "status_code": 200,
                    "chunk_size": 0,
                    "response_handle": None
                }
                survivors.append(mock_item)
            print(f"{Colors.GREEN} All URLs ready: {len(survivors)} / {len(urls)} (Phase 1 bypassed){Colors.RESET}")
        else:
            print(f"{Colors.CYAN}[Phase 1] HTTP Filtering...{Colors.RESET}")
            tasks = [process_url(semaphore, http_client, url) for url in urls]
            
            # Use tqdm for progress bar
            results = []
            with tqdm(total=len(tasks), desc=f"{Colors.CYAN}Filtering URLs{Colors.RESET}", ncols=100, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    results.append(result)
                    pbar.update(1)
            
            survivors = [r for r in results if r is not None]
            print(f"{Colors.GREEN} Survivors: {len(survivors)} / {len(urls)}{Colors.RESET}")
        
        # Phase 2: Contextual Fusion Assessment
        if survivors:
            print(f"\n{Colors.CYAN}[Phase 2] AI Contextual Analysis...{Colors.RESET}")
            rate_limiter = RateLimiter(AI_RATE_LIMIT_DELAY)
            hw_monitor = HardwareMonitor()
            
            # Check Ollama
            try:
                await http_client.get("http://localhost:11434/api/tags")
            except:
                print(f"{Colors.RED} ERROR: Ollama not running!{Colors.RESET}")
                return

            assessments = []
            
            # Progress bar for AI analysis
            with tqdm(total=len(survivors), desc=f"{Colors.MAGENTA}Analyzing content{Colors.RESET}", ncols=100, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
                for item in survivors:
                    assessment = await assess_risk_with_fusion(http_client, item, rate_limiter, hw_monitor)
                    if assessment:
                        assessments.append(assessment)
                        # Show finding inline
                        if assessment.severity == "CRITICAL":
                            tqdm.write(f"{Colors.RED}   CRITICAL: {assessment.url} (Score: {assessment.final_score:.2f}){Colors.RESET}")
                        elif assessment.severity == "HIGH":
                            tqdm.write(f"{Colors.YELLOW}   HIGH: {assessment.url} (Score: {assessment.final_score:.2f}){Colors.RESET}")
                    pbar.update(1)
            
            # Phase 3: Reporting
            if assessments:
                print(f"\n{Colors.CYAN}[Phase 3] Reporting{Colors.RESET}")
                with tqdm(total=len(assessments), desc=f"{Colors.GREEN}Saving findings{Colors.RESET}", ncols=100, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
                    for assessment in assessments:
                        await send_telegram_alert(http_client, assessment)
                        if assessment.severity != "CRITICAL":
                            await save_finding_to_file(assessment)
                        pbar.update(1)
                
                print(f"\n{Colors.GREEN} Scan complete. {len(assessments)} findings saved.{Colors.RESET}")
                print(f"{Colors.CYAN} Cache: {snippet_cache.size()} unique snippets analyzed{Colors.RESET}")
            else:
                print(f"\n{Colors.GREEN} Scan complete. No findings.{Colors.RESET}")

if __name__ == "__main__":
    asyncio.run(main())
