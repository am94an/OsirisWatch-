import requests
import time
from config import AUTH_URL, AUTH_REFRESH_URL, USERNAME, PASSWORD
from .logger import setup_logger

logger = setup_logger()

class AuthManager:
    def __init__(self):
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = 0
        self.logger = logger

    def get_auth_headers(self):
        if not self.access_token or time.time() >= self.token_expiry:
            self.refresh_tokens()
        return {'Authorization': f'Bearer {self.access_token}'}

    def refresh_tokens(self):
        try:
            if self.refresh_token:
                # محاولة تحديث التوكن
                response = requests.post(
                    AUTH_REFRESH_URL,
                    json={'refresh': self.refresh_token}
                )
            else:
                # الحصول على توكن جديد
                response = requests.post(
                    AUTH_URL,
                    json={'username': USERNAME, 'password': PASSWORD}
                )

            if response.status_code == 200:
                data = response.json()
                self.access_token = data['access']
                self.refresh_token = data['refresh']
                self.token_expiry = time.time() + 300  # 5 دقائق
                self.logger.info("Successfully refreshed authentication tokens")
            else:
                self.logger.error(f"Failed to refresh tokens: {response.status_code}")
                raise Exception("Authentication failed")

        except Exception as e:
            self.logger.error(f"Error refreshing tokens: {str(e)}")
            raise

auth_manager = AuthManager() 