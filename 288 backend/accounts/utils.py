import jwt  
from django.conf import settings
from django.contrib.auth.models import User
from datetime import datetime, timedelta
from django.http import HttpResponseForbidden
from functools import wraps
from django.http import HttpRequest

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

def has_permission(permission_name):
    """
    وظيفة ديكوريتور للتحقق من صلاحيات المستخدم
    مثال الاستخدام: @has_permission('can_view_users')
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(view_instance, *args, **kwargs):
            # Get the request object - handle both function and class-based views
            request = view_instance if isinstance(view_instance, HttpRequest) else view_instance.request
            
            # تحقق من وجود المستخدم وملف التعريف والمجموعة
            user = request.user
            if not user.is_authenticated:
                return HttpResponseForbidden("يجب تسجيل الدخول")
            
            try:
                profile = user.userprofile
            except:
                return HttpResponseForbidden("ملف تعريف المستخدم غير موجود")
            
            # المسؤول لديه جميع الصلاحيات
            if profile.role == 'Admin':
                return view_func(view_instance, *args, **kwargs)
            
            # تحقق من وجود مجموعة صلاحيات
            if not profile.permission_group:
                return HttpResponseForbidden("ليس لديك مجموعة صلاحيات")
            
            # تحقق من الصلاحية المطلوبة
            if hasattr(profile.permission_group, permission_name) and getattr(profile.permission_group, permission_name):
                return view_func(view_instance, *args, **kwargs)
            
            return HttpResponseForbidden("ليس لديك الصلاحية المطلوبة")
            
        return _wrapped_view
    return decorator

def check_object_permission(user, obj, permission_type='view'):
    """
    التحقق من صلاحية المستخدم على كائن معين
    
    Args:
        user: المستخدم
        obj: الكائن المراد التحقق منه
        permission_type: نوع الصلاحية (view, add, edit, delete)
    
    Returns:
        bool: True إذا كان لديه صلاحية، False إذا لم يكن
    """
    if not user.is_authenticated:
        return False
    
    try:
        profile = user.userprofile
    except:
        return False
    
    # المسؤول لديه جميع الصلاحيات
    if profile.role == 'Admin':
        return True
    
    # تحقق من وجود مجموعة صلاحيات
    if not profile.permission_group:
        return False
    
    # تحديد أي صلاحية نتحقق منها بناءً على نوع الكائن
    obj_type = obj.__class__.__name__.lower()
    permission_attr = f'can_{permission_type}_{obj_type}s'
    
    if hasattr(profile.permission_group, permission_attr):
        return getattr(profile.permission_group, permission_attr)
    
    return False
