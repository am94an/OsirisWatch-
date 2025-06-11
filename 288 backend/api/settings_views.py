from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from django.contrib.auth.models import User
from accounts.models import UserProfile, System_Settings, PermissionGroup
from .permissions import IsAdminOrAnalyst
from .mixins import IncludeUserDataMixin
from .serializers import SystemSettingsSerializer
from django.utils import timezone

class UserSettingsView(IncludeUserDataMixin, APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get(self, request):
        """Get user's personal settings"""
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            
            # Get notification preferences
            notification_preferences = {
                "email_notifications": getattr(user_profile, 'email_notifications', True),
                "sms_notifications": getattr(user_profile, 'sms_notifications', False),
                "push_notifications": getattr(user_profile, 'push_notifications', True),
                "notify_on_alerts": getattr(user_profile, 'notify_on_alerts', True),
                "notify_on_threats": getattr(user_profile, 'notify_on_threats', True),
                "notify_on_reports": getattr(user_profile, 'notify_on_reports', True),
            }
            
            # Get interface settings
            interface_settings = {
                "theme": getattr(user_profile, 'theme', 'light'),
                "dashboard_layout": getattr(user_profile, 'dashboard_layout', 'default'),
                "language": getattr(user_profile, 'language', 'en'),
            }
            
            # Get user profile data
            profile_data = {
                "username": request.user.username,
                "email": request.user.email,
                "first_name": request.user.first_name,
                "last_name": request.user.last_name,
                "role": user_profile.role,
                "profile_image": user_profile.profile_image.url if user_profile.profile_image else None,
                "phone_number": user_profile.phone_number,
                "bio": user_profile.bio,
            }
            
            return Response({
                "profile": profile_data,
                "notification_preferences": notification_preferences,
                "interface_settings": interface_settings
            }, status=status.HTTP_200_OK)
            
        except UserProfile.DoesNotExist:
            return Response({"error": "User profile not found"}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request):
        """Update user's personal settings"""
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            data = request.data
            
            # Update user model fields
            user = request.user
            if 'first_name' in data:
                user.first_name = data['first_name']
            if 'last_name' in data:
                user.last_name = data['last_name']
            if 'email' in data:
                user.email = data['email']
            user.save()
            
            # Update profile fields
            if 'phone_number' in data:
                user_profile.phone_number = data['phone_number']
            if 'bio' in data:
                user_profile.bio = data['bio']
            
            # Update notification preferences
            if 'notification_preferences' in data:
                prefs = data['notification_preferences']
                for key, value in prefs.items():
                    if hasattr(user_profile, key):
                        setattr(user_profile, key, value)
            
            # Update interface settings
            if 'interface_settings' in data:
                settings = data['interface_settings']
                for key, value in settings.items():
                    if hasattr(user_profile, key):
                        setattr(user_profile, key, value)
            
            user_profile.save()
            
            return Response({"message": "Settings updated successfully"}, status=status.HTTP_200_OK)
            
        except UserProfile.DoesNotExist:
            return Response({"error": "User profile not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request):
        """Update user's profile image"""
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            profile_image = request.FILES.get('profile_image')

            if not profile_image:
                return Response({"error": "No image file provided"}, status=status.HTTP_400_BAD_REQUEST)

            # Update profile image
            user_profile.profile_image = profile_image
            user_profile.save()

            return Response({
                "message": "Profile image updated successfully",
                "profile_image": user_profile.profile_image.url
            }, status=status.HTTP_200_OK)

        except UserProfile.DoesNotExist:
            return Response({"error": "User profile not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class SystemSettingsView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrAnalyst]

    def get(self, request):
        """Get system settings"""
        try:
            settings = System_Settings.objects.get(id=1)
            serializer = SystemSettingsSerializer(settings)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except System_Settings.DoesNotExist:
            # Create default settings if they don't exist
            settings = System_Settings.objects.create(
                system_name="Osiris Network Analysis System",
                version="1.0.0",
                maintenance_mode=False,
                max_login_attempts=5,
                notification_settings={"email": True, "sms": False}
            )
            serializer = SystemSettingsSerializer(settings)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        """Update system settings"""
        try:
            settings = System_Settings.objects.get(id=1)
            serializer = SystemSettingsSerializer(settings, data=request.data, partial=True)
            
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except System_Settings.DoesNotExist:
            return Response({"error": "System settings not found"}, status=status.HTTP_404_NOT_FOUND)

class SecuritySettingsView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrAnalyst]

    def get(self, request):
        """Get security settings"""
        try:
            settings = System_Settings.objects.get(id=1)
            
            security_settings = {
                "max_login_attempts": settings.max_login_attempts,
                "security_policy": settings.security_policy,
                "backup_settings": settings.backup_settings,
                "last_backup": settings.last_backup,
                "maintenance_mode": settings.maintenance_mode
            }
            
            return Response(security_settings, status=status.HTTP_200_OK)
            
        except System_Settings.DoesNotExist:
            return Response({"error": "System settings not found"}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request):
        """Update security settings"""
        try:
            settings = System_Settings.objects.get(id=1)
            data = request.data
            
            if 'max_login_attempts' in data:
                settings.max_login_attempts = data['max_login_attempts']
            if 'security_policy' in data:
                settings.security_policy = data['security_policy']
            if 'backup_settings' in data:
                settings.backup_settings = data['backup_settings']
            if 'maintenance_mode' in data:
                settings.maintenance_mode = data['maintenance_mode']
            
            settings.save()
            
            return Response({"message": "Security settings updated successfully"}, status=status.HTTP_200_OK)
            
        except System_Settings.DoesNotExist:
            return Response({"error": "System settings not found"}, status=status.HTTP_404_NOT_FOUND)

class NotificationSettingsView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrAnalyst]

    def get(self, request):
        """Get notification settings"""
        try:
            settings = System_Settings.objects.get(id=1)
            
            notification_settings = {
                "system_notifications": settings.notification_settings,
                "email_enabled": settings.notification_settings.get('email', True),
                "sms_enabled": settings.notification_settings.get('sms', False),
                "push_enabled": settings.notification_settings.get('push', True)
            }
            
            return Response(notification_settings, status=status.HTTP_200_OK)
            
        except System_Settings.DoesNotExist:
            return Response({"error": "System settings not found"}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request):
        """Update notification settings"""
        try:
            settings = System_Settings.objects.get(id=1)
            data = request.data
            
            current_settings = settings.notification_settings.copy()
            current_settings.update(data)
            
            settings.notification_settings = current_settings
            settings.save()
            
            return Response({"message": "Notification settings updated successfully"}, status=status.HTTP_200_OK)
            
        except System_Settings.DoesNotExist:
            return Response({"error": "System settings not found"}, status=status.HTTP_404_NOT_FOUND) 