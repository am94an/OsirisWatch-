# utils/network_utils.py

import requests
from config import API_URL

def check_api_connection():
    try:
        response = requests.get(API_URL)
        if response.status_code == 201:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        return False