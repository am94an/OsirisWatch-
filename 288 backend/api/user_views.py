from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from accounts.models import UserProfile, PermissionGroup
from accounts.utils import has_permission, check_object_permission
from .serializers import UserSerializer
from .permissions import IsAdminOrAnalyst

class UserListView(APIView):
    permission_classes = [IsAuthenticated]
    
    @has_permission('can_view_users')
    def get(self, request):
        """
        Get list of users - only available to users with view permission
        """
        try:
            users = User.objects.select_related('userprofile', 'userprofile__permission_group').all()
            user_data = []
            current_user_profile = request.user.userprofile
            
            for user in users:
                try:
                    profile = user.userprofile
                    # Get permissions from permission group
                    permissions = {}
                    if profile.permission_group:
                        permissions = {
                            'dashboard': {
                                'read': profile.permission_group.can_view_dashboard,
                                'write': profile.permission_group.can_view_dashboard,
                                'delete': profile.permission_group.can_view_dashboard
                            },
                            'reports': {
                                'read': profile.permission_group.can_view_reports,
                                'write': profile.permission_group.can_edit_reports,
                                'delete': profile.permission_group.can_delete_reports
                            },
                            'users': {
                                'read': profile.permission_group.can_view_users,
                                'write': profile.permission_group.can_edit_users,
                                'delete': profile.permission_group.can_delete_users
                            },
                            'settings': {
                                'read': profile.permission_group.can_view_notifications,
                                'write': profile.permission_group.can_manage_notifications,
                                'delete': profile.permission_group.can_manage_notifications
                            }
                        }
                    
                    # Check if current user can edit/delete this user
                    can_edit = False
                    can_delete = False
                    
                    if current_user_profile and current_user_profile.permission_group:
                        # Admin can edit/delete anyone
                        if current_user_profile.role == 'Admin':
                            can_edit = True
                            can_delete = True
                        # Analyst can only edit/delete users with Viewer or Device role
                        elif current_user_profile.role == 'Analyst':
                            if profile.role in ['Viewer', 'Device']:
                                can_edit = current_user_profile.permission_group.can_edit_users
                                can_delete = current_user_profile.permission_group.can_delete_users
                    
                    user_data.append({
                        'id': user.id,
                        'username': user.username,
                        'firstName': user.first_name,
                        'lastName': user.last_name,
                        'email': user.email,
                        'mobile': profile.phone_number or '',
                        'role': profile.role,
                        'date': user.date_joined,
                        'permissions': permissions,
                        'can_edit': can_edit,
                        'can_delete': can_delete
                    })
                except Exception as e:
                    print(f"Error processing user {user.username}: {str(e)}")
                    continue
            
            # Add current user's permissions to the response
            current_user_permissions = {}
            if current_user_profile and current_user_profile.permission_group:
                current_user_permissions = {
                    'dashboard': {
                        'read': current_user_profile.permission_group.can_view_dashboard,
                        'write': current_user_profile.permission_group.can_view_dashboard,
                        'delete': current_user_profile.permission_group.can_view_dashboard
                    },
                    'reports': {
                        'read': current_user_profile.permission_group.can_view_reports,
                        'write': current_user_profile.permission_group.can_edit_reports,
                        'delete': current_user_profile.permission_group.can_delete_reports
                    },
                    'users': {
                        'read': current_user_profile.permission_group.can_view_users,
                        'write': current_user_profile.permission_group.can_edit_users,
                        'delete': current_user_profile.permission_group.can_delete_users
                    },
                    'settings': {
                        'read': current_user_profile.permission_group.can_view_notifications,
                        'write': current_user_profile.permission_group.can_manage_notifications,
                        'delete': current_user_profile.permission_group.can_manage_notifications
                    }
                }
            
            return Response({
                'users': user_data,
                'current_user_permissions': current_user_permissions
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {'error': f'Error fetching users: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @has_permission('can_add_users')
    def post(self, request):
        """
        Add new user - only available to users with add permission
        """
        try:
            data = request.data
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            firstName = data.get('firstName')
            lastName = data.get('lastName')
            mobile = data.get('mobile')
            role = data.get('role', 'User')
            permissions = data.get('permissions', {})
            
            if not all([username, email, password, firstName, lastName]):
                return Response(
                    {'error': 'Missing required fields'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if username or email already exists
            if User.objects.filter(username=username).exists():
                return Response(
                    {'error': 'Username already exists'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            if User.objects.filter(email=email).exists():
                return Response(
                    {'error': 'Email already exists'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=firstName,
                last_name=lastName
            )
            
            # Update profile
            profile = user.userprofile
            profile.role = role
            profile.phone_number = mobile
            
            # Create or update permission group based on permissions
            if permissions:
                permission_group = PermissionGroup.objects.create(
                    name=f"Custom Group for {username}",
                    can_view_dashboard=permissions.get('dashboard', {}).get('read', False),
                    can_view_reports=permissions.get('reports', {}).get('read', False),
                    can_edit_reports=permissions.get('reports', {}).get('write', False),
                    can_delete_reports=permissions.get('reports', {}).get('delete', False),
                    can_view_users=permissions.get('users', {}).get('read', False),
                    can_edit_users=permissions.get('users', {}).get('write', False),
                    can_delete_users=permissions.get('users', {}).get('delete', False),
                    can_view_notifications=permissions.get('settings', {}).get('read', False),
                    can_manage_notifications=permissions.get('settings', {}).get('write', False)
                )
                profile.permission_group = permission_group
            
            profile.save()
            
            return Response({
                'message': 'User created successfully',
                'user_id': user.id
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response(
                {'error': f'Error creating user: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get_user(self, user_id):
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None
    
    @has_permission('can_view_users')
    def get(self, request, user_id):
        """
        Get user details - only available to users with view permission
        """
        user = self.get_user(user_id)
        if not user:
            return Response(
                {'error': 'User not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        try:
            profile = user.userprofile
            
            # Get permissions from permission group
            permissions = {}
            if profile.permission_group:
                permissions = {
                    'dashboard': {
                        'read': profile.permission_group.can_view_dashboard,
                        'write': profile.permission_group.can_view_dashboard,
                        'delete': profile.permission_group.can_view_dashboard
                    },
                    'reports': {
                        'read': profile.permission_group.can_view_reports,
                        'write': profile.permission_group.can_edit_reports,
                        'delete': profile.permission_group.can_delete_reports
                    },
                    'users': {
                        'read': profile.permission_group.can_view_users,
                        'write': profile.permission_group.can_edit_users,
                        'delete': profile.permission_group.can_delete_users
                    },
                    'settings': {
                        'read': profile.permission_group.can_view_notifications,
                        'write': profile.permission_group.can_manage_notifications,
                        'delete': profile.permission_group.can_manage_notifications
                    }
                }
            
            user_data = {
                'id': user.id,
                'username': user.username,
                'firstName': user.first_name,
                'lastName': user.last_name,
                'email': user.email,
                'mobile': profile.phone_number or '',
                'role': profile.role,
                'date': user.date_joined,
                'permissions': permissions
            }
            return Response(user_data, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'User profile not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
    
    @has_permission('can_edit_users')
    def put(self, request, user_id):
        """
        Update user - only available to users with edit permission
        """
        user = self.get_user(user_id)
        if not user:
            return Response(
                {'error': 'User not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        try:
            data = request.data
            profile = user.userprofile
            
            # Update user fields
            if 'firstName' in data:
                user.first_name = data['firstName']
            if 'lastName' in data:
                user.last_name = data['lastName']
            if 'email' in data:
                user.email = data['email']
            if 'password' in data:
                user.set_password(data['password'])
            user.save()
            
            # Update profile fields
            if 'role' in data:
                profile.role = data['role']
            if 'mobile' in data:
                profile.phone_number = data['mobile']
            
            # Update permissions
            permissions = data.get('permissions', {})
            if profile.permission_group:
                permission_group = profile.permission_group
            else:
                permission_group = PermissionGroup.objects.create(
                    name=f"Custom Group for {user.username}"
                )
            
            # Update permission group
            permission_group.can_view_dashboard = permissions.get('dashboard', {}).get('read', False)
            permission_group.can_view_reports = permissions.get('reports', {}).get('read', False)
            permission_group.can_edit_reports = permissions.get('reports', {}).get('write', False)
            permission_group.can_delete_reports = permissions.get('reports', {}).get('delete', False)
            permission_group.can_view_users = permissions.get('users', {}).get('read', False)
            permission_group.can_edit_users = permissions.get('users', {}).get('write', False)
            permission_group.can_delete_users = permissions.get('users', {}).get('delete', False)
            permission_group.can_view_notifications = permissions.get('settings', {}).get('read', False)
            permission_group.can_manage_notifications = permissions.get('settings', {}).get('write', False)
            
            permission_group.save()
            profile.permission_group = permission_group
            profile.save()
            
            return Response({'message': 'User updated successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {'error': f'Error updating user: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @has_permission('can_delete_users')
    def delete(self, request, user_id):
        """
        Delete user - only available to users with delete permission
        """
        user = self.get_user(user_id)
        if not user:
            return Response(
                {'error': 'User not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        try:
            user.delete()
            return Response({'message': 'User deleted successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {'error': f'Error deleting user: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PermissionGroupListView(APIView):
    permission_classes = [IsAuthenticated]
    
    @has_permission('can_view_users')
    def get(self, request):
        """
        Get list of permission groups - only available to users with view permission
        """
        groups = PermissionGroup.objects.all()
        
        group_data = []
        for group in groups:
            # Convert permissions to dictionary
            permissions = {field.name: getattr(group, field.name)
                          for field in PermissionGroup._meta.fields
                          if field.name.startswith('can_')}
            
            group_data.append({
                'id': group.id,
                'name': group.name,
                'description': group.description,
                'permissions': permissions
            })
                
        return Response(group_data, status=status.HTTP_200_OK)
    
    @has_permission('can_add_users')
    def post(self, request):
        """
        Add new permission group - only available to users with add permission
        """
        data = request.data
        name = data.get('name')
        description = data.get('description', '')
        permissions = data.get('permissions', {})
        
        if not name:
            return Response({'error': 'Group name is required'}, 
                            status=status.HTTP_400_BAD_REQUEST)
        
        if PermissionGroup.objects.filter(name=name).exists():
            return Response({'error': 'Group name already exists'}, 
                            status=status.HTTP_400_BAD_REQUEST)
        
        # Create permission group
        group = PermissionGroup.objects.create(
            name=name,
            description=description
        )
        
        # Update permissions
        for perm_name, value in permissions.items():
            if hasattr(group, perm_name) and perm_name.startswith('can_'):
                setattr(group, perm_name, value)
                
        group.save()
        
        return Response({
            'message': 'Permission group created successfully',
            'group_id': group.id
        }, status=status.HTTP_201_CREATED)

class PermissionGroupDetailView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get_group(self, group_id):
        try:
            return PermissionGroup.objects.get(id=group_id)
        except PermissionGroup.DoesNotExist:
            return None
    
    @has_permission('can_view_users')
    def get(self, request, group_id):
        """
        Get permission group details
        """
        group = self.get_group(group_id)
        if not group:
            return Response({'error': 'Permission group not found'}, 
                            status=status.HTTP_404_NOT_FOUND)
        
        # Convert permissions to dictionary
        permissions = {field.name: getattr(group, field.name)
                      for field in PermissionGroup._meta.fields
                      if field.name.startswith('can_')}
        
        group_data = {
            'id': group.id,
            'name': group.name,
            'description': group.description,
            'permissions': permissions
        }
            
        return Response(group_data, status=status.HTTP_200_OK)
    
    @has_permission('can_edit_users')
    def put(self, request, group_id):
        """
        Update permission group
        """
        group = self.get_group(group_id)
        if not group:
            return Response({'error': 'Permission group not found'}, 
                            status=status.HTTP_404_NOT_FOUND)
        
        data = request.data
        
        # Update group data
        if 'name' in data:
            if data['name'] != group.name and PermissionGroup.objects.filter(name=data['name']).exists():
                return Response({'error': 'Group name already exists'}, 
                                status=status.HTTP_400_BAD_REQUEST)
            group.name = data['name']
            
        if 'description' in data:
            group.description = data['description']
            
        # Update permissions
        permissions = data.get('permissions', {})
        for perm_name, value in permissions.items():
            if hasattr(group, perm_name) and perm_name.startswith('can_'):
                setattr(group, perm_name, value)
                
        group.save()
        
        return Response({'message': 'Permission group updated successfully'}, 
                        status=status.HTTP_200_OK)
    
    @has_permission('can_delete_users')
    def delete(self, request, group_id):
        """
        Delete permission group
        """
        group = self.get_group(group_id)
        if not group:
            return Response({'error': 'Permission group not found'}, 
                            status=status.HTTP_404_NOT_FOUND)
        
        # Check if group is in use
        if UserProfile.objects.filter(permission_group=group).exists():
            return Response({'error': 'Cannot delete group that is in use by users'}, 
                            status=status.HTTP_400_BAD_REQUEST)
        
        group.delete()
        return Response({'message': 'Permission group deleted successfully'}, 
                        status=status.HTTP_200_OK) 