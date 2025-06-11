import jwt  
from django.conf import settings
from django.contrib.auth.models import User
from datetime import datetime, timedelta

def generate_token(user):
    payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(minutes=15),  
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

def check_token(user, token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return payload['user_id'] == user.id
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False
