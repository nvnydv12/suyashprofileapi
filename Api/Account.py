import requests
import json
import os
import random
import time
import base64
from Configuration.APIConfiguration import RELEASEVERSION, DEBUG

TOKENS_FILE = os.path.join(os.path.dirname(__file__), '..', 'Configuration', 'tokens.json')

# In-memory token cache: {server_key: {"token": "...", "expires_at": float}}
_TOKEN_CACHE = {}

# Fresh IND accounts pool from DARK_MASTER for instant failover
IND_ACCOUNTS_POOL = [
    ("8003725136", "861945DDA2623F3D521CEC3A37692210DE748D4BB4B18DCE9173180210F26586"),
    ("8003725190", "F73D0C8C51A3730A0E751F88DAC92D8018706A30B9D3D228D7D30A38B1058F9C"),
    ("8003725224", "81DF4E031648ED36FDB8EA80C9D7CBEADDC361F810E0AE5BF42402911269954A"),
    ("8003725265", "6F92B5D90ED9DB580057C2D72DCEC7E7B8C05DC0A107AF37FFE8C6CFC6533555"),
    ("8003725297", "637F62B516F272E4D714DA9CDD820A645E8F2207AEE74AB2C591B220EAD7B682"),
    ("8003725243", "AE1852FFE02B18CF3CDF3266EC32E1C9DAD1178D3AFB0D034A6FB9BC9BAD3381"),
    ("8003725425", "D757E8CC430063D201C9E91B8060D45528384D8DC412813289943DB2F0551A2E"),
    ("8003725387", "5D1296A7BCD3A12304E316176D0803C5E9E13DF06A906948837CC05247B052D3")
]

def get_jwt_exp(token: str) -> int:
    """Decode JWT without verifying signature to extract exp timestamp."""
    try:
        if not token or len(token) < 20:
            return 0
        parts = token.split('.')
        if len(parts) >= 2:
            payload = parts[1] + '=' * (-len(parts[1]) % 4)
            data = json.loads(base64.urlsafe_b64decode(payload))
            return int(data.get('exp', 0))
    except Exception:
        pass
    return 0

def is_token_valid(token: str) -> bool:
    """Check if token is not expired (with 120s safety margin)."""
    if not token or len(token) < 30:
        return False
    exp = get_jwt_exp(token)
    if exp > 0:
        return (exp - time.time()) > 120
    return True

def clear_token_cache(server=None):
    """Purge token cache for a server or all servers (used when 401 is encountered)."""
    global _TOKEN_CACHE
    if server:
        _TOKEN_CACHE.pop(server.upper(), None)
    else:
        _TOKEN_CACHE.clear()

def load_cached_tokens(server="IND"):
    """Load from in-memory cache first, then fallback to tokens.json if not expired."""
    server_key = (server or "IND").upper()
    
    # 1. Check in-memory cache
    if server_key in _TOKEN_CACHE:
        entry = _TOKEN_CACHE[server_key]
        tok = entry.get('token')
        if is_token_valid(tok):
            return tok
        else:
            _TOKEN_CACHE.pop(server_key, None)

    # 2. Check tokens.json file (only use if not expired)
    try:
        if os.path.exists(TOKENS_FILE):
            with open(TOKENS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                server_tokens = data.get(server_key, [])
                if server_tokens:
                    for item in server_tokens:
                        token = item.get('token') if isinstance(item, dict) else item
                        if token and is_token_valid(str(token)):
                            _TOKEN_CACHE[server_key] = {
                                'token': str(token).strip(),
                                'expires_at': get_jwt_exp(str(token))
                            }
                            return str(token).strip()
    except Exception as e:
        if DEBUG:
            print(f"[!] Error loading cached tokens: {e}")
            
    return None

def fetch_jwt_from_api(uid, password, region="IND"):
    """Fetch fresh JWT from remote JWT generator APIs with failover."""
    api_urls = [
        f"https://jwtsuyash.vercel.app/token?uid={uid}&password={password}",
        f"https://ob-55-jwt-two.vercel.app/token?uid={uid}&password={password}",
    ]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json"
    }

    for url in api_urls:
        try:
            resp = requests.get(url, headers=headers, timeout=12)
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("token") or data.get("jwt") or (data.get("data", {}).get("token") if isinstance(data.get("data"), dict) else None)
                if token:
                    token = str(token).strip()
                    if token.startswith("Bearer "):
                        token = token.replace("Bearer ", "").strip()
                    if len(token) > 30 and token.startswith("ey"):
                        return token
        except Exception as e:
            if DEBUG:
                print(f"[!] JWT fetch error from {url}: {e}")
            continue

    return None

def get_garena_token(uid, password, server="IND", force_refresh=False):
    """
    Get Garena game Bearer token.
    1. Returns valid cached token (instant response, 0ms lag).
    2. Automatically fetches fresh JWT when missing, expired, or forced.
    3. Handles fallback accounts if the primary account fails.
    """
    server_upper = (server or "IND").upper()

    if force_refresh:
        clear_token_cache(server_upper)

    # 1. Use cached token if valid
    if not force_refresh:
        cached_tok = load_cached_tokens(server_upper)
        if cached_tok:
            return {
                'access_token': cached_tok,
                'open_id': server_upper
            }

    # 2. Fetch fresh token from JWT API
    token = fetch_jwt_from_api(uid, password, server_upper)

    # 3. Fallback accounts if primary failed (e.g. if account banned or rate limited)
    if not token:
        if server_upper == "IND":
            candidates = IND_ACCOUNTS_POOL
        else:
            candidates = [
                ("7881118340", "86CE7D21FB862C317D6AB0D1266FB32FF2086E32E539744F86A3361ADC300884"),
                ("7876699711", "EF8E6EC033A3564DFB43084601BD128E4AABB4C8854037A1AC86F513AE223C92")
            ]
        for fb_uid, fb_pwd in candidates:
            if str(fb_uid) != str(uid):
                token = fetch_jwt_from_api(fb_uid, fb_pwd, server_upper)
                if token:
                    break

    if token:
        exp = get_jwt_exp(token)
        _TOKEN_CACHE[server_upper] = {
            'token': token,
            'expires_at': exp if exp > 0 else (time.time() + 3600)
        }
        return {
            'access_token': token,
            'open_id': server_upper
        }

    # 4. Emergency fallback to cached token
    cached_fallback = load_cached_tokens(server_upper)
    if cached_fallback:
        return {
            'access_token': cached_fallback,
            'open_id': server_upper
        }

    return {"debug_error": f"Failed to obtain Garena token for server {server_upper}. Service temporarily unavailable."}

def get_major_login(logintoken, openid_or_server="IND"):
    """
    Maps region to correct Garena regional game server URL.
    IND routes to official https://client.ind.freefiremobile.com for authentic live player responses.
    """
    region = (openid_or_server or "IND").upper()

    REGION_CONFIG = {
        "IND": "https://client.ind.freefiremobile.com",
        "BD": "https://clientbp.ppmainecoonghj.com",
        "SG": "https://clientbp.ppmainecoonghj.com",
        "RU": "https://clientbp.ppmainecoonghj.com",
        "CIS": "https://clientbp.ppmainecoonghj.com",
        "US": "https://client.us.freefiremobile.com",
        "NA": "https://client.us.freefiremobile.com",
        "SAC": "https://client.us.freefiremobile.com",
        "BR": "https://client.us.freefiremobile.com",
        "TW": "https://client.us.freefiremobile.com",
        "ID": "https://clientbp.ppmainecoonghj.com",
        "VN": "https://clientbp.ppmainecoonghj.com",
        "TH": "https://clientbp.ppmainecoonghj.com",
        "ME": "https://clientbp.ppmainecoonghj.com",
        "PK": "https://clientbp.ppmainecoonghj.com"
    }

    server_url = REGION_CONFIG.get(region, "https://client.ind.freefiremobile.com" if region == "IND" else "https://clientbp.ppmainecoonghj.com")

    return {
        'token': logintoken,
        'serverUrl': server_url
    }
