import requests
import json
import os
import random
import time
from Configuration.APIConfiguration import RELEASEVERSION, DEBUG

TOKENS_FILE = os.path.join(os.path.dirname(__file__), '..', 'Configuration', 'tokens.json')

def load_cached_tokens(server="IND"):
    """Load pre-cached active tokens from tokens.json"""
    try:
        if os.path.exists(TOKENS_FILE):
            with open(TOKENS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                server_tokens = data.get(server.upper(), [])
                if server_tokens:
                    # Pick a random token from pool
                    chosen = random.choice(server_tokens)
                    token = chosen.get('token') if isinstance(chosen, dict) else chosen
                    if token and len(str(token)) > 30:
                        return str(token).strip()
    except Exception as e:
        if DEBUG:
            print(f"[!] Error loading cached tokens: {e}")
    return None

def get_garena_token(uid, password, server="IND"):
    """
    Get Garena game Bearer token.
    First checks local cached tokens for instant response (no rate limit / no downtime).
    Falls back to jwtsuyash API if needed.
    """
    server_upper = (server or "IND").upper()

    # 1. For IND server, use active game tokens from pool
    if server_upper == "IND":
        cached_tok = load_cached_tokens("IND")
        if cached_tok:
            return {
                'access_token': cached_tok,
                'open_id': 'IND'
            }

    # 2. For other servers or if cache empty, call JWT API
    url = f"https://jwtsuyash.vercel.app/token?uid={uid}&password={password}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=12)
        if response.status_code == 200:
            data = response.json()
            token = data.get("token", "").strip()
            
            if token and len(token) > 30 and not token.startswith("Bearer "):
                return {
                    'access_token': token,
                    'open_id': server_upper
                }
            elif token.startswith("Bearer "):
                token = token.replace("Bearer ", "").strip()
                return {
                    'access_token': token,
                    'open_id': server_upper
                }
    except Exception as e:
        if DEBUG:
            print(f"[!] JWT API Request Error: {e}")

    # 3. Fallback: try cached tokens if available
    cached_fallback = load_cached_tokens(server_upper) or load_cached_tokens("IND")
    if cached_fallback:
        return {
            'access_token': cached_fallback,
            'open_id': server_upper
        }

    return {"debug_error": f"Failed to obtain Garena token for server {server_upper}. Service temporarily unavailable."}

def get_major_login(logintoken, openid_or_server="IND"):
    """
    Maps region to correct Garena regional game server URL.
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
