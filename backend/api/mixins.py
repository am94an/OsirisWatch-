from rest_framework.views import APIView
from django.contrib.auth.models import User
from accounts.models import UserProfile, Notification
from .serializers import NotificationSerializer

class IncludeUserDataMixin:
    def get_user_data(self, user):
        try:
            user_profile = UserProfile.objects.get(user=user)
            user_role = user_profile.role
            profile_image_url = user_profile.profile_image.url if user_profile.profile_image else None
        except UserProfile.DoesNotExist:
            user_role = "User"
            profile_image_url = None

        user_notifications = Notification.objects.filter(user=user)
        serialized_notifications = NotificationSerializer(user_notifications, many=True)

        return {
            "user_info": {
                "name": user.username,
                "role": user_role,
                "profile_image": profile_image_url,
                "notifications": serialized_notifications.data,
                "notification_count": user_notifications.count(),
            }
        }

class CalculateChangeMixin:
    """
    Mixin to calculate percentage change between two values.
    Used for statistics and trend analysis in dashboard views.
    """
    def calculate_change(self, current, previous):
        if previous == 0:
            return 0, "neutral"
        change = ((current - previous) / previous) * 100
        trend = "up" if change > 0 else "down"
        return round(change, 2), trend