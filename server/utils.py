import random
import string
import requests
import os
from .config import Config

def is_bot_ua(ua_string):
    """Enhanced heuristic to detect bots, crawlers, and headless browsers."""
    bots = [
        'bot', 'crawl', 'slurp', 'spider', 'curl', 'wget', 'facebook', 'whatsapp', 'telegram', 
        'expand', 'preview', 'peeker', 'twitter', 'discord', 'slack', 'go-http-client', 'python-requests',
        'headless', 'phantomjs', 'puppeteer', 'selenium', 'urlscan', 'lighthouse', 'gtmetrix', 'pingdom'
    ]
    ua_lower = ua_string.lower()
    return any(bot in ua_lower for bot in bots)

def generate_slug(length=6):
    """Generates a random alphanumeric slug."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def shorten_with_isgd(url):
    """Shortens a URL using is.gd API for masking."""
    try:
        resp = requests.get(f"https://is.gd/create.php?format=simple&url={url}", timeout=5)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception as e:
        print(f"is.gd Error: {e}")
    return None

def get_geo_data(ip):
    """Fetch ISP, Geo, AND Proxy/Hosting data from ip-api.com."""
    try:
        fields = "status,country,city,lat,lon,isp,org,as,proxy,hosting,mobile,query,countryCode"
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=1.5)
        data = resp.json()
        if data.get('status') == 'success':
            return data
    except:
        pass
    return {}

def get_reverse_dns(ip):
    """Perform reverse DNS lookup to get hostname from IP."""
    import socket
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return None

def parse_referrer(url):
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

def email_permutations(email):
    """Generate name permutations from email address."""
    if not email or '@' not in email:
        return {'first_names': [], 'last_names': [], 'full_names': [], 'company': None}
    
    local_part, domain = email.split('@')
    
    # Remove trailing numbers (e.g. gobberpaolo92 -> gobberpaolo)
    import re
    local_clean = re.sub(r'\d+$', '', local_part.lower())
    local_clean = local_clean.replace('_', '.').replace('-', '.')
    parts = local_clean.split('.')
    
    first_names = []
    last_names = []
    full_names = []
    
    if len(parts) >= 2:
        # mario.rossi pattern - most reliable
        first_names.append(parts[0].capitalize())
        last_names.append(parts[-1].capitalize())
        full_names.append(f"{parts[0].capitalize()} {parts[-1].capitalize()}")
    elif len(parts) == 1 and len(parts[0]) > 3:
        # Single word like "gobberpaolo" - try to split intelligently
        word = parts[0]
        
        # Try common name patterns (first 4-7 chars might be first name)
        # We'll just store the raw username, let AI figure it out
        full_names.append(word.capitalize())
        
        # Don't make wild guesses - let AI handle ambiguous cases
    
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

def get_gravatar_profile(email):
    """Fetch extended Gravatar profile data."""
    import hashlib
    if not email:
        return None
    
    email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    
    try:
        # Gravatar JSON profile endpoint
        url = f"https://www.gravatar.com/{email_hash}.json"
        resp = requests.get(url, timeout=3)
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

def get_gaia_id(email):
    """Attempt to extract Google Gaia ID from email via public endpoints."""
    if not email or 'gmail' not in email.lower():
        return None
    
    try:
        # Technique: Google Calendar public embed
        # This can sometimes reveal a Gaia ID in redirects
        import hashlib
        email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
        
        # Try Google People API (public profile check)
        url = f"https://www.google.com/s2/photos/public/{email}"
        resp = requests.head(url, allow_redirects=True, timeout=3)
        
        # If redirected, the URL might contain the Gaia ID
        if resp.url and '/u/0/' in resp.url:
            # Extract ID from URL pattern
            parts = resp.url.split('/')
            for i, p in enumerate(parts):
                if p.isdigit() and len(p) > 10:
                    return p
        return None
    except:
        return None

def load_domain_list(filename):
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

def is_disposable_email(email):
    domain = email.split('@')[-1].lower()
    return domain in DISPOSABLE_DOMAINS

def is_privacy_email(email):
    domain = email.split('@')[-1].lower()
    return domain in PRIVACY_DOMAINS

def verify_turnstile(token, ip):
    secret = Config.TURNSTILE_SECRET_KEY
    if not secret: 
        print("ERROR: TURNSTILE_SECRET_KEY missing in Verify.")
        return False
    
    try:
        resp = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={'secret': secret, 'response': token, 'remoteip': ip}
        )
        data = resp.json()
        if not data.get('success'):
            print(f"Turnstile Failed: {data.get('error-codes')}")
        return data.get('success', False)
    except Exception as e:
        print(f"Turnstile Connection Error: {e}")
        return False
