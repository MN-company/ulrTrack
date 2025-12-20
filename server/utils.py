import random
import string
import requests
import os
from .config import Config

def is_bot_ua(ua_string):
    """Simple heuristic to detect bots."""
    bots = [
        'bot', 'crawl', 'slurp', 'spider', 'curl', 'wget', 'facebook', 'whatsapp', 'telegram', 
        'expand', 'preview', 'peeker', 'twitter', 'discord', 'slack', 'go-http-client', 'python-requests'
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
        fields = "status,country,city,lat,lon,isp,proxy,hosting,mobile,query,countryCode"
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=1.5)
        data = resp.json()
        if data.get('status') == 'success':
            return data
    except:
        pass
    return {}

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
