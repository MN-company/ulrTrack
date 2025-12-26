import random
import string
import requests
import os
import math
from typing import Tuple, Optional, Dict, List, Set, Any
from functools import lru_cache
from .config import Config

# Global session for connection pooling (Speed boost)
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
session.mount('http://', adapter)
session.mount('https://', adapter)

def is_bot_ua(ua_string: str) -> bool:
    """Enhanced heuristic to detect bots, crawlers, and headless browsers."""
    if not ua_string: return False
    bots = [
        'bot', 'crawl', 'slurp', 'spider', 'curl', 'wget', 'facebook', 'whatsapp', 'telegram', 
        'expand', 'preview', 'peeker', 'twitter', 'discord', 'slack', 'go-http-client', 'python-requests',
        'headless', 'phantomjs', 'puppeteer', 'selenium', 'urlscan', 'lighthouse', 'gtmetrix', 'pingdom'
    ]
    ua_lower = ua_string.lower()
    return any(bot in ua_lower for bot in bots)

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text: return 0.0
    entropy = 0.0
    length = len(text)
    for x in set(text):
        p_x = text.count(x) / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def is_gibberish_email(email: str) -> Tuple[bool, Optional[str]]:
    """
    Detects keyboard-smash or garbage emails based on heuristics.
    Returns (True, Reason) if gibberish, (False, None) otherwise.
    """
    if not email or '@' not in email: return True, "Invalid Format"
    
    local_part = email.split('@')[0].lower()
    
    # 1. Length Checks
    if len(local_part) < 3: return True, "Too Short"
    
    # 2. Entropy Check
    ent = calculate_entropy(local_part)
    if ent < 1.0 and len(local_part) > 3: return True, "Low Entropy (Repetitive)"
    
    # 3. Consonant Clusters
    vowels = "aeiouy"
    consec_cons = 0
    max_consec_cons = 0
    for char in local_part:
        if char.isalpha():
            if char not in vowels:
                consec_cons += 1
                max_consec_cons = max(max_consec_cons, consec_cons)
            else:
                consec_cons = 0
    
    if max_consec_cons > 5: return True, "High Consonant Cluster"
    
    # 4. Keyboard Smash Patterns (Basic)
    bad_patterns = ['asdf', 'qwer', 'zxcv', '1234', 'test', 'demo', 'qwerty']
    if any(p in local_part for p in bad_patterns):
        return True, "Common Pattern"

    return False, None

def validate_email_strict(email: str) -> Tuple[bool, str]:
    """Strict validation combining syntax, gibberish check, and domain rules."""
    import re
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False, "Invalid Syntax"
        
    is_bad, reason = is_gibberish_email(email)
    if is_bad:
        return False, f"Gibberish Detected: {reason}"
        
    return True, "Valid"

def generate_slug(length: int = 6) -> str:
    """Generates a random alphanumeric slug."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

@lru_cache(maxsize=1000)
def shorten_with_isgd(url: str) -> Optional[str]:
    """Shortens a URL using is.gd API for masking (Cached)."""
    try:
        resp = session.get(f"https://is.gd/create.php?format=simple&url={url}", timeout=5)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception as e:
        print(f"is.gd Error: {e}")
    return None

@lru_cache(maxsize=2000)
def get_geo_data(ip: str) -> Dict[str, Any]:
    """Fetch ISP, Geo, AND Proxy/Hosting data from ip-api.com (Cached)."""
    try:
        fields = "status,country,city,lat,lon,isp,org,as,proxy,hosting,mobile,query,countryCode"
        resp = session.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=1.5)
        data = resp.json()
        if data.get('status') == 'success':
            return data
    except:
        pass
    return {}

def get_reverse_dns(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup to get hostname from IP."""
    import socket
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return None

def parse_referrer(url: str) -> Dict[str, Any]:
    """Extract intelligence from referrer URL."""
    if not url:
        return {'domain': None, 'platform': 'Direct', 'utm': {}}
    
    from urllib.parse import urlparse, parse_qs
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.replace('www.', '')
        
        # Identify platform
        platform = 'Unknown'
        if 'google' in domain: platform = 'Google'
        elif 'facebook' in domain or 'fb.com' in domain: platform = 'Facebook'
        elif 'twitter' in domain or 't.co' in domain or 'x.com' in domain: platform = 'Twitter/X'
        elif 'linkedin' in domain: platform = 'LinkedIn'
        elif 'instagram' in domain: platform = 'Instagram'
        elif 'youtube' in domain: platform = 'YouTube'
        elif 'tiktok' in domain: platform = 'TikTok'
        elif 'reddit' in domain: platform = 'Reddit'
        elif 'telegram' in domain or 't.me' in domain: platform = 'Telegram'
        elif 'whatsapp' in domain: platform = 'WhatsApp'
        else: platform = domain
        
        # Extract UTM params
        utm = {}
        for key in ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content']:
            val = parse_qs(parsed.query).get(key)
            if val: utm[key] = val[0]
        
        return {'domain': domain, 'platform': platform, 'utm': utm}
    except:
        return {'domain': url, 'platform': 'Unknown', 'utm': {}}

# ============================================
# V31: ADVANCED OSINT UTILITIES
# ============================================

def email_permutations(email: str) -> Dict[str, Any]:
    """Generate name permutations from email address."""
    if not email or '@' not in email:
        return {'first_names': [], 'last_names': [], 'full_names': [], 'company': None}
    
    local_part, domain = email.split('@')
    
    import re
    local_clean = re.sub(r'\d+$', '', local_part.lower())
    local_clean = local_clean.replace('_', '.').replace('-', '.')
    parts = local_clean.split('.')
    
    first_names = []
    last_names = []
    full_names = []
    
    if len(parts) >= 2:
        # mario.rossi pattern
        first_names.append(parts[0].capitalize())
        last_names.append(parts[-1].capitalize())
        full_names.append(f"{parts[0].capitalize()} {parts[-1].capitalize()}")
    elif len(parts) == 1 and len(parts[0]) > 3:
        word = parts[0]
        full_names.append(word.capitalize())
    
    # Extract company from domain
    company = None
    if domain and not any(x in domain for x in ['gmail', 'yahoo', 'hotmail', 'outlook', 'icloud', 'proton', 'live', 'aol']):
        company = domain.split('.')[0].capitalize()
    
    return {
        'first_names': list(set(first_names))[:5],
        'last_names': list(set(last_names))[:5],
        'full_names': list(set(full_names))[:10],
        'company': company
    }

@lru_cache(maxsize=500)
def get_gravatar_profile(email: str) -> Optional[Dict[str, Any]]:
    """Fetch extended Gravatar profile data (Cached)."""
    import hashlib
    if not email: return None
    
    email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    
    try:
        url = f"https://www.gravatar.com/{email_hash}.json"
        resp = session.get(url, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            entry = data.get('entry', [{}])[0]
            return {
                'displayName': entry.get('displayName'),
                'preferredUsername': entry.get('preferredUsername'),
                'profileUrl': entry.get('profileUrl'),
                'photos': [p.get('value') for p in entry.get('photos', [])],
                'urls': [u.get('value') for u in entry.get('urls', [])],
                'accounts': [{'name': a.get('shortname'), 'url': a.get('url')} for a in entry.get('accounts', [])]
            }
    except:
        pass
    return None

def get_gaia_id(email: str) -> Optional[str]:
    """Attempt to extract Google Gaia ID from email via public endpoints."""
    if not email or 'gmail' not in email.lower(): return None
    
    try:
        url = f"https://www.google.com/s2/photos/public/{email}"
        resp = session.head(url, allow_redirects=True, timeout=3)
        
        if resp.url and '/u/0/' in resp.url:
            parts = resp.url.split('/')
            for p in enumerate(parts):
                if p[1].isdigit() and len(p[1]) > 10:
                    return p[1]
    except:
        pass
    return None

def load_domain_list(filename: str) -> Set[str]:
    """Helper to load domain lists from server/data."""
    domains = set()
    try:
        path = os.path.join(os.path.dirname(__file__), 'data', filename)
        if os.path.exists(path):
            with open(path, 'r') as f:
                domains = {line.strip().lower() for line in f if line.strip()}
    except Exception as e:
        print(f"Error loading {filename}: {e}")
    return domains

# Load once on start
DISPOSABLE_DOMAINS = load_domain_list('disposable_domains.txt')
PRIVACY_DOMAINS = load_domain_list('privacy_domains.txt')

def is_disposable_email(email: str) -> bool:
    domain = email.split('@')[-1].lower()
    return domain in DISPOSABLE_DOMAINS

def is_privacy_email(email: str) -> bool:
    domain = email.split('@')[-1].lower()
    return domain in PRIVACY_DOMAINS

def verify_turnstile(token: str, ip: str) -> bool:
    secret = Config.TURNSTILE_SECRET_KEY
    if not secret: 
        print("ERROR: TURNSTILE_SECRET_KEY missing in Verify.")
        return False
    
    try:
        resp = session.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={'secret': secret, 'response': token, 'remoteip': ip},
            timeout=5
        )
        data = resp.json()
        return data.get('success', False)
    except Exception as e:
        print(f"Turnstile Connection Error: {e}")
        return False
def update_env_file(updates: Dict[str, str]):
    """Safely updates keys in the .env file."""
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
    if not os.path.exists(env_path):
        return

    with open(env_path, 'r') as f:
        lines = f.readlines()

    new_lines = []
    updated_keys = set()
    
    for line in lines:
        cleaned = line.strip()
        # Handle comments and empty lines
        if not cleaned or cleaned.startswith('#'):
            new_lines.append(line)
            continue
            
        key = cleaned.split('=')[0].strip()
        if key in updates:
            new_lines.append(f"{key}={updates[key]}\n")
            updated_keys.add(key)
        else:
            new_lines.append(line)
    
    # Add new keys
    for key, val in updates.items():
        if key not in updated_keys:
            new_lines.append(f"{key}={val}\n")
            
    with open(env_path, 'w') as f:
        f.writelines(new_lines)
