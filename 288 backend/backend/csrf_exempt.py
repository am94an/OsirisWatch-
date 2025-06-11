from django.conf import settings
from django.middleware.csrf import CsrfViewMiddleware

class CustomCsrfViewMiddleware(CsrfViewMiddleware):
    def process_view(self, request, callback, callback_args, callback_kwargs):
        # Get the exempt URLs from settings
        exempt_urls = getattr(settings, 'CSRF_EXEMPT_URLS', [])
        
        # Check if the current path starts with any of the exempt URLs
        for exempt_url in exempt_urls:
            if request.path.startswith(exempt_url):
                return None
                
        # Otherwise, use the default CSRF protection
        return super().process_view(request, callback, callback_args, callback_kwargs) 