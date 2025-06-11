import time
import logging
from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
import ipaddress

logger = logging.getLogger('api.middleware')

class RateLimitMiddleware:
    """
    وسيط لتقييد معدل الطلبات باستخدام ذاكرة التخزين المؤقت.
    يحمي النظام من الهجمات وسوء استخدام واجهة برمجة التطبيقات.
    يعمل مع أي نوع من أنواع الذاكرة المؤقتة المكونة في Django.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        # تكوين
        self.rate_limit_duration = 60  # بالثواني، 60 ثانية = 1 دقيقة
        self.rate_limit_requests = 60  # عدد الطلبات المسموح بها لكل IP في المدة
        
        # حدود مختلفة للمسارات الحساسة
        self.sensitive_paths = {
            '/api/login/': 10,  # 10 محاولات تسجيل دخول في الدقيقة
            '/api/forget_password/': 5,  # 5 محاولات إعادة تعيين كلمة المرور في الدقيقة
            '/api/token/': 10,  # 10 محاولات للحصول على JWT token في الدقيقة
        }
        
        # القائمة البيضاء للشبكات الداخلية
        self.whitelisted_networks = [
            '127.0.0.1/32',  # localhost
            '10.0.0.0/8',     # شبكة داخلية
            '172.16.0.0/12',  # شبكة داخلية
            '192.168.0.0/16', # شبكة داخلية
        ]
        
        try:
            self.whitelisted_netobj = [ipaddress.ip_network(net) for net in self.whitelisted_networks]
        except Exception as e:
            self.whitelisted_netobj = []
            logger.error(f"Error initializing whitelisted networks: {str(e)}")
        
        # قائمة IPs المحظورة مؤقتاً
        self.blacklist_duration = 3600  # ساعة واحدة
        
        logger.info(f"Rate limit middleware initialized: {self.rate_limit_requests} requests per {self.rate_limit_duration} seconds")
        
    def _get_client_ip(self, request):
        """
        استخراج عنوان IP الحقيقي للعميل مع مراعاة وجود proxy
        """
        try:
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                # أخذ أول عنوان IP في حالة وجود سلسلة
                ip = x_forwarded_for.split(',')[0].strip()
            else:
                ip = request.META.get('REMOTE_ADDR', '')
            return ip
        except Exception as e:
            logger.error(f"Error getting client IP: {str(e)}")
            return "0.0.0.0"  # عنوان IP افتراضي في حالة وجود خطأ
        
    def _is_whitelisted(self, ip):
        """
        التحقق مما إذا كان عنوان IP ضمن القائمة البيضاء
        """
        try:
            # التحقق المباشر من الخادم المحلي
            if ip in ('127.0.0.1', 'localhost', '::1'):
                return True
                
            client_ip = ipaddress.ip_address(ip)
            return any(client_ip in network for network in self.whitelisted_netobj)
        except ValueError:
            logger.warning(f"Invalid IP address format: {ip}")
            return False
        except Exception as e:
            logger.error(f"Error checking whitelist: {str(e)}")
            return False
    
    def _is_blacklisted(self, ip):
        """
        التحقق مما إذا كان عنوان IP محظوراً مؤقتاً
        """
        try:
            blacklist_key = f"ratelimit_blacklist_{ip}"
            return cache.get(blacklist_key) is not None
        except Exception as e:
            logger.error(f"Error checking blacklist: {str(e)}")
            return False
    
    def _blacklist_ip(self, ip):
        """
        إضافة عنوان IP إلى القائمة السوداء المؤقتة
        """
        try:
            blacklist_key = f"ratelimit_blacklist_{ip}"
            cache.set(blacklist_key, 1, self.blacklist_duration)
            logger.warning(f"IP {ip} has been blacklisted for {self.blacklist_duration} seconds due to rate limit violations")
        except Exception as e:
            logger.error(f"Error blacklisting IP {ip}: {str(e)}")
    
    def _check_rate_limit(self, request, client_ip):
        """
        فحص ما إذا كان العميل تجاوز حد معدل الطلبات
        """
        try:
            path = request.path
            
            # تحديد الحد الأقصى للطلبات بناءً على المسار
            max_requests = self.rate_limit_requests
            for sensitive_path, limit in self.sensitive_paths.items():
                if path.startswith(sensitive_path):
                    max_requests = limit
                    break
                    
            # إنشاء مفتاح في الذاكرة المؤقتة خاص بعنوان IP والمسار
            cache_key = f"ratelimit_{client_ip}_{path.replace('/', '_')}"
            count = cache.get(cache_key, 0)
            
            # إذا كان هذا أول طلب، قم بإنشاء العداد
            if count == 0:
                cache.set(cache_key, 1, self.rate_limit_duration)
                return True
            
            # تحديث العداد وفحص الحد
            if count < max_requests:
                # نستخدم set مع قيمة جديدة بدلاً من incr لأنه متوافق مع جميع أنواع الذاكرة المؤقتة
                cache.set(cache_key, count + 1, self.rate_limit_duration)
                return True
            else:
                # العميل تجاوز الحد
                violations_key = f"ratelimit_violations_{client_ip}"
                violations = cache.get(violations_key, 0)
                
                # إذا تجاوز العميل الحد بشكل متكرر، قم بإضافته إلى القائمة السوداء
                if violations >= 5:  # بعد 5 انتهاكات
                    self._blacklist_ip(client_ip)
                else:
                    cache.set(violations_key, violations + 1, 24 * 3600)  # تخزين لمدة يوم
                    
                logger.warning(f"Rate limit exceeded for IP {client_ip} on path {path} - count: {count}/{max_requests}")
                return False
        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            return True  # السماح بالطلب في حالة حدوث خطأ لمنع منع الوصول بشكل غير مقصود

    def __call__(self, request):
        try:
            # لا تطبق تقييد المعدل على الطلبات الصادرة من المشرف
            if request.user.is_authenticated and request.user.is_staff:
                return self.get_response(request)
                
            client_ip = self._get_client_ip(request)
            
            # التحقق من القائمة البيضاء
            if self._is_whitelisted(client_ip):
                return self.get_response(request)
                
            # التحقق من القائمة السوداء
            if self._is_blacklisted(client_ip):
                return JsonResponse({
                    'error': 'You have been temporarily blocked due to suspicious activity. Please try again later.'
                }, status=429)
            
            # فحص معدل الطلبات
            if not self._check_rate_limit(request, client_ip):
                return JsonResponse({
                    'error': 'Too many requests. Please try again later.'
                }, status=429)
            
            # إرسال الطلب إلى المستقبل التالي في حالة اجتياز الفحص
            return self.get_response(request)
        except Exception as e:
            logger.error(f"Unexpected error in RateLimitMiddleware: {str(e)}")
            return self.get_response(request)  # السماح بالطلب في حالة حدوث خطأ 