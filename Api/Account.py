import requests
import json
import os
import random
import time
import base64
from Configuration.APIConfiguration import RELEASEVERSION, DEBUG

TOKENS_FILE = os.path.join(os.path.dirname(__file__), '..', 'Configuration', 'tokens.json')

# Cooldown tracking: {str(uid): float(cooldown_until_timestamp)}
_ACCOUNT_COOLDOWNS = {}

# Active token cache per account: {str(uid): {"token": str, "expires_at": float, "server": str}}
_ACCOUNT_TOKENS = {}

# Token string to account UID mapping: {str(token): str(uid)}
_TOKEN_TO_UID = {}

# Round-robin counter per server
_RR_COUNTER = {}

# Verified working initialized Indian accounts pool (svr: 3)
IND_ACCOUNTS_POOL = [
    ("4718507823", "506D5EF550F365C89806066468D5327C9FC7E40F60548BF9FE7BAA64D1ACF099"),
    ("4718508029", "98A796FACDCBE9C9E1A169A1C589936D988FD0BAC1E7902FE5A0706DB77F5326"),
    ("4718548116", "D25435CB701067838FBC9836D3DFB7423FC19B06F7868B88CDB1EB270B9BD164"),
    ("4718548400", "D97F7650F59A2CC15047551DBC5F624DDE5D8EC9D576E315FF6610F7D10CB08C"),
]

# Fresh verified accounts pool for high-availability rotation across global regions
GLOBAL_ACCOUNTS_POOL = [
    ("7881118340", "86CE7D21FB862C317D6AB0D1266FB32FF2086E32E539744F86A3361ADC300884"),  # SG (svr: 1)
    ("7881197800", "36644BD83DA230C788A39F199F2CF8EF27ABFC65C51C66458019E37037CDBE73"),  # PK (svr: 1)
    ("7881331930", "64B6B6331A4BF91AE3BA117398E543A1D805342E91CA707585ECE1E1D390CDBF"),  # CIS (svr: 1)
    ("7876509571", "4115B671E3308EAAE76B7E4C727616A7DCD8A6697D17B9F6968ADC23FBFFA169"),  # US (svr: 2)
    ("7876699711", "EF8E6EC033A3564DFB43084601BD128E4AABB4C8854037A1AC86F513AE223C92")   # BD (svr: 1)
]

HEALTHY_ACCOUNTS_POOL = IND_ACCOUNTS_POOL + GLOBAL_ACCOUNTS_POOL

FALLBACK_ACCOUNTS = {
    "IND": IND_ACCOUNTS_POOL,
    "DEFAULT": GLOBAL_ACCOUNTS_POOL
}

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

def load_tokens_from_file():
    """Load valid tokens from tokens.json into memory cache."""
    try:
        if os.path.exists(TOKENS_FILE):
            with open(TOKENS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for srv, items in data.items():
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                tok = item.get('token')
                                uid = str(item.get('uid', ''))
                                if tok and is_token_valid(tok):
                                    exp = get_jwt_exp(tok)
                                    _ACCOUNT_TOKENS[uid] = {
                                        'token': tok,
                                        'expires_at': exp,
                                        'server': srv.upper()
                                    }
                                    _TOKEN_TO_UID[tok] = uid
    except Exception as e:
        if DEBUG:
            print(f"[!] Error loading cached tokens: {e}")

def mark_token_rate_limited(token: str, server: str = "IND", cooldown_seconds: int = 300):
    """
    Marks the account that produced this token as rate-limited (HTTP 429).
    Puts the account on cooldown for cooldown_seconds (default 5 min).
    Evicts the token from active cache so subsequent requests use a healthy account.
    """
    token_str = str(token).strip()
    uid = _TOKEN_TO_UID.get(token_str)
    
    if not uid:
        for u, entry in list(_ACCOUNT_TOKENS.items()):
            if entry.get('token') == token_str:
                uid = u
                break
                
    if uid:
        _ACCOUNT_COOLDOWNS[str(uid)] = time.time() + cooldown_seconds
        _ACCOUNT_TOKENS.pop(str(uid), None)
        print(f"[!] Rate limit (429) recorded for account {uid}. Cooling down for {cooldown_seconds}s.")
    else:
        print(f"[!] Rate limit (429) recorded for token preview {token_str[:15]}...")

def mark_token_expired(token: str, server: str = "IND"):
    """
    Marks token as expired / unauthorized (HTTP 401).
    Removes it from the cache so a fresh token is generated.
    """
    token_str = str(token).strip()
    uid = _TOKEN_TO_UID.get(token_str)
    if not uid:
        for u, entry in list(_ACCOUNT_TOKENS.items()):
            if entry.get('token') == token_str:
                uid = u
                break
    if uid:
        _ACCOUNT_TOKENS.pop(str(uid), None)
    _TOKEN_TO_UID.pop(token_str, None)
    print(f"[!] Token expired/invalid for {uid or token_str[:15]}. Evicted from cache.")

def clear_token_cache(server=None):
    """Purge token cache for a server or all servers (used when reset is required)."""
    global _ACCOUNT_TOKENS, _TOKEN_TO_UID
    if server:
        srv = server.upper()
        for uid, entry in list(_ACCOUNT_TOKENS.items()):
            if entry.get('server') == srv:
                tok = entry.get('token')
                _ACCOUNT_TOKENS.pop(uid, None)
                if tok in _TOKEN_TO_UID:
                    _TOKEN_TO_UID.pop(tok, None)
    else:
        _ACCOUNT_TOKENS.clear()
        _TOKEN_TO_UID.clear()

def load_cached_tokens(server="IND"):
    """Load any valid token for server (backwards compatibility)."""
    server_key = (server or "IND").upper()
    if not _ACCOUNT_TOKENS:
        load_tokens_from_file()
        
    for uid, entry in list(_ACCOUNT_TOKENS.items()):
        if entry.get('server', 'IND') == server_key:
            tok = entry.get('token')
            if is_token_valid(tok):
                return tok
            else:
                _ACCOUNT_TOKENS.pop(uid, None)
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

def get_garena_token(uid=None, password=None, server="IND", force_refresh=False):
    """
    Get Garena game Bearer token with round-robin load-balancing and automatic
    failover across healthy accounts.
    """
    server_upper = (server or "IND").upper()
    now = time.time()
    
    # 1. Ensure file tokens loaded into memory
    if not _ACCOUNT_TOKENS:
        load_tokens_from_file()

    # 2. Build account candidates pool
    pool = list(FALLBACK_ACCOUNTS.get(server_upper, FALLBACK_ACCOUNTS["DEFAULT"]))
    if uid and password:
        cand = (str(uid), str(password))
        if cand not in pool:
            pool.insert(0, cand)

    # 3. Filter accounts based on cooldown
    available = []
    cooling_down = []
    for acc_uid, acc_pwd in pool:
        acc_uid_str = str(acc_uid)
        cd_until = _ACCOUNT_COOLDOWNS.get(acc_uid_str, 0)
        if now < cd_until:
            cooling_down.append((acc_uid_str, acc_pwd, cd_until))
        else:
            available.append((acc_uid_str, acc_pwd))

    # If all accounts are cooling down, pick the one that cools down first
    if not available:
        if cooling_down:
            cooling_down.sort(key=lambda x: x[2])
            available = [(cooling_down[0][0], cooling_down[0][1])]
        else:
            available = pool

    # 4. Round-robin rotation across available healthy accounts
    if server_upper not in _RR_COUNTER:
        _RR_COUNTER[server_upper] = 0
    start_idx = _RR_COUNTER[server_upper] % len(available)
    _RR_COUNTER[server_upper] = (_RR_COUNTER[server_upper] + 1) % 1000000
    
    ordered_accounts = available[start_idx:] + available[:start_idx]

    # 5. Check cache for valid token from ordered accounts
    if not force_refresh:
        for acc_uid, acc_pwd in ordered_accounts:
            entry = _ACCOUNT_TOKENS.get(acc_uid)
            if entry and entry.get('token'):
                tok = entry['token']
                if is_token_valid(tok):
                    _TOKEN_TO_UID[tok] = acc_uid
                    return {
                        'access_token': tok,
                        'open_id': server_upper,
                        'uid': acc_uid
                    }
                else:
                    _ACCOUNT_TOKENS.pop(acc_uid, None)

    # 6. Fetch fresh token from JWT API for candidate accounts
    for acc_uid, acc_pwd in ordered_accounts:
        fresh_token = fetch_jwt_from_api(acc_uid, acc_pwd, server_upper)
        if fresh_token and is_token_valid(fresh_token):
            exp = get_jwt_exp(fresh_token)
            _ACCOUNT_TOKENS[acc_uid] = {
                'token': fresh_token,
                'expires_at': exp if exp > 0 else (now + 14400),
                'server': server_upper
            }
            _TOKEN_TO_UID[fresh_token] = acc_uid
            return {
                'access_token': fresh_token,
                'open_id': server_upper,
                'uid': acc_uid
            }

    # 7. Fallback to any valid token in cache
    for acc_uid, entry in list(_ACCOUNT_TOKENS.items()):
        tok = entry.get('token')
        if tok and is_token_valid(tok):
            return {
                'access_token': tok,
                'open_id': server_upper,
                'uid': acc_uid
            }

    return {"debug_error": f"Failed to obtain Garena token for server {server_upper}. Service temporarily unavailable."}

def get_major_login(logintoken, openid_or_server="IND"):
    """
    Maps token and region to the correct Garena regional game server URL.
    Uses the token's JWT 'svr' header to guarantee signature validity:
      svr '1' -> clientbp.ppmainecoonghj.com (Asia/Global Regional Gateway)
      svr '2' -> client.us.freefiremobile.com (Americas Gateway)
      svr '3' -> client.ind.freefiremobile.com (IND Official Gateway)
    Falls back to REGION_CONFIG if header cannot be read.
    """
    if logintoken and len(str(logintoken)) > 20:
        try:
            parts = str(logintoken).split('.')
            if len(parts) >= 2:
                header_b64 = parts[0] + '=' * (-len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))
                svr = str(header.get('svr', ''))
                if svr == '2':
                    return {
                        'token': logintoken,
                        'serverUrl': "https://client.us.freefiremobile.com"
                    }
                elif svr == '1':
                    return {
                        'token': logintoken,
                        'serverUrl': "https://clientbp.ppmainecoonghj.com"
                    }
                elif svr == '3':
                    return {
                        'token': logintoken,
                        'serverUrl': "https://clientbp.freefireind.in"
                    }
        except Exception:
            pass

    region = (openid_or_server or "IND").upper()

    REGION_CONFIG = {
        "IND": "https://clientbp.freefireind.in",
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

    server_url = REGION_CONFIG.get(region, "https://clientbp.ppmainecoonghj.com")

    return {
        'token': logintoken,
        'serverUrl': server_url
    }
