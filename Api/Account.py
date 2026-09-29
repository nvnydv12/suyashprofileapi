import requests
import json
from Configuration.APIConfiguration import RELEASEVERSION, DEBUG


def get_garena_token(uid, password):
    """
    Get Garena token using uid and password via the new JWT API.
    
    Args:
        uid (str): User ID
        password (str): Password
    
    Returns:
        dict: Custom dict to mock legacy auth flow
    """
    url = f"https://jwtsuyash.vercel.app/token?uid={uid}&password={password}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        if DEBUG:
            print("[I] JWT RES:", data)
            
        if "token" in data:
            return {
                'access_token': data["token"],
                'open_id': data.get("region", "IND")
            }
    except Exception as e:
        print(f"Error making request to JWT API: {e}")
    return None


def get_major_login(logintoken, openid):
    """
    Mock major login returning the token and mapped serverUrl.
    
    Args:
        logintoken (str): The JWT token string
        openid (str): Region mapped in get_garena_token
    
    Returns:
        dict: JSON mapping for legacy login response
    """
    REGION_CONFIG = {
        "BD": "https://clientbp.ppmainecoonghj.com",
        "IND": "https://client.ind.freefiremobile.com",
        "BR": "https://client.us.freefiremobile.com",
        "SG": "https://clientbp.ppmainecoonghj.com",
        "RU": "https://clientbp.ppmainecoonghj.com",
        "CIS": "https://clientbp.ppmainecoonghj.com",
        "US": "https://client.us.freefiremobile.com",
        "TW": "https://client.us.freefiremobile.com",
        "ID": "https://clientbp.ppmainecoonghj.com",
        "VN": "https://clientbp.ppmainecoonghj.com",
        "TH": "https://clientbp.ppmainecoonghj.com",
        "ME": "https://clientbp.ppmainecoonghj.com",
        "PK": "https://clientbp.ppmainecoonghj.com"
    }
    
    server_url = REGION_CONFIG.get(openid, "https://clientbp.ppmainecoonghj.com")
    
    return {
        'token': logintoken,
        'serverUrl': server_url
    }