from .models import UserProfile
from django.db.models import Q

def user_data(request):
    notifications = []
    
    if request.user.is_authenticated:
        try:
            # Get notifications from the user object instead of userprofile
            notifications = request.user.notifications.filter(is_read=False).order_by('-sent_at')
        except Exception as e:
            # Log error and continue with empty notifications
            print(f"Error fetching notifications: {str(e)}")
            notifications = []
    
    return {
        'notifications': notifications,
    }
