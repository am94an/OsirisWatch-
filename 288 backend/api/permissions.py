from rest_framework import permissions
from rest_framework.permissions import BasePermission
from accounts.models import UserProfile
from rest_framework.response import Response
from rest_framework import status

class IsAdminOrAnalyst(BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            return user_profile.role in ['Admin', 'Analyst']
        except UserProfile.DoesNotExist:
            return False

def has_permission(permission_name):
    def decorator(view_func):
        def wrapper(self, request, *args, **kwargs):
            if not request.user or not request.user.is_authenticated:
                return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
            try:
                user_profile = UserProfile.objects.get(user=request.user)
                if not user_profile.permission_group:
                    return Response({'error': 'No permission group assigned'}, status=status.HTTP_403_FORBIDDEN)
                has_permission = getattr(user_profile.permission_group, permission_name, False)
                if not has_permission:
                    return Response({'error': f'Permission denied: {permission_name}'}, status=status.HTTP_403_FORBIDDEN)
                return view_func(self, request, *args, **kwargs)
            except UserProfile.DoesNotExist:
                return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)
        return wrapper
    return decorator

class CanManageUsers(BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            if not user_profile.permission_group:
                return False
            return any([
                user_profile.permission_group.can_view_users,
                user_profile.permission_group.can_edit_users,
                user_profile.permission_group.can_delete_users
            ])
        except UserProfile.DoesNotExist:
            return False

class CanEditUsers(BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            return user_profile.permission_group and user_profile.permission_group.can_edit_users
        except UserProfile.DoesNotExist:
            return False

class CanDeleteUsers(BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            return user_profile.permission_group and user_profile.permission_group.can_delete_users
        except UserProfile.DoesNotExist:
            return False

class IsAdminOrAnalyst(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        try:
            user_profile = request.user.userprofile
            is_admin = user_profile.role == 'Admin'
            is_analyst = user_profile.role == 'Analyst'
            if is_admin:
                return True
            if is_analyst:
                if request.method in ['GET', 'POST']:
                    return True
                return False
            return False
        except Exception:
            return False
    
    def has_object_permission(self, request, view, obj):
        if not request.user.is_authenticated:
            return False
        try:
            user_profile = request.user.userprofile
            is_admin = user_profile.role == 'Admin'
            is_analyst = user_profile.role == 'Analyst'
            if is_admin:
                return True
            if is_analyst:
                if request.method == 'POST':
                    requested_role = request.data.get('role')
                    return requested_role in ['Viewer', 'Device']
                try:
                    target_user_profile = obj.userprofile
                    return target_user_profile.role in ['Viewer', 'Device']
                except Exception:
                    return False
            return False
        except Exception:
            return False 