from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.urls import reverse
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.utils import timezone
import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import get_object_or_404
from datetime import datetime, timedelta
from .serializers import LoginSerializer, SignupSerializer, ForgetPasswordSerializer, ResetPasswordSerializer, NotificationSerializer, AgentSerializer, NetworkFlowSerializer, AlertSerializer, ThreatSerializer, ReportSerializer
from accounts.models import UserProfile, Notification, PermissionGroup
from .models import Threat, NetworkFlow, SuspiciousIP, UserLogin, Agent, AttackType, Alert, Report, System_Settings
from accounts.utils import generate_token, check_token
from django.db.models import Count, Sum, Avg, F, Q, ExpressionWrapper, DurationField
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework import generics
from .mixins import IncludeUserDataMixin, CalculateChangeMixin
from rest_framework.permissions import IsAdminUser
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django.contrib.auth.hashers import make_password
from .permissions import IsAdminOrAnalyst
from django.http import JsonResponse
from django.views import View
from django.views.decorators.http import require_http_methods
from predictions.views import create_network_flow as predictions_create_network_flow
import uuid
from django.core.cache import cache
from django.db.models import Value
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Q
from datetime import datetime, timedelta
import csv
from django.http import HttpResponse


class ProtectedAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "This is a protected view."}, status=status.HTTP_200_OK)


class CreateProfilesView(APIView):
    def get(self, request):
        users = User.objects.all()
        for user in users:
            if not UserProfile.objects.filter(user=user).exists():
                UserProfile.objects.create(
                    user=user, 
                    role='User', 
                    profile_image='media/profile_images/avatar.png' 
                )
                print(f"Created profile for {user.username}")
        return Response({"message": "Profiles created successfully for all existing users"}, status=status.HTTP_200_OK)


class UpdateProfileImageView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        user = request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
            profile_image = request.FILES.get('profile_image')

            if profile_image:
                user_profile.profile_image = profile_image
                user_profile.save()

            return Response({"message": "Profile image updated successfully", "profile_image": user_profile.profile_image.url}, status=status.HTTP_200_OK)

        except UserProfile.DoesNotExist:
            return Response({"error": "User profile not found"}, status=status.HTTP_404_NOT_FOUND)


@method_decorator(csrf_exempt, name='dispatch')
class LoginAPIView(APIView):
    """
    API View for user authentication.
    
    This endpoint allows users to authenticate and obtain JWT tokens.
    """
    authentication_classes = []  # No authentication required for login
    permission_classes = []      # No permissions required for login
    
    def post(self, request):
        print("=== Login attempt received ===")
        print(f"Request data: {request.data}")
        print(f"Request content type: {request.content_type}")
        
        # Handle different content types
        if request.content_type == 'application/x-www-form-urlencoded':
            # Form data
            username = request.data.get('username', '')
            password = request.data.get('password', '')
        else:
            # JSON data
            serializer = LoginSerializer(data=request.data)
            if not serializer.is_valid():
                print(f"Serializer errors: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
        
        # Log authentication attempt
        print(f"Attempting to authenticate user: {username}")
        
        # Try to authenticate
        user = authenticate(username=username, password=password)
        
        # Handle authentication result
        if user is not None:
            print(f"Authentication successful for user: {username}")
            # Create tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            
            # Log successful login
            try:
                UserLogin.objects.create(user=user)
                print(f"Login recorded for user: {username}")
            except Exception as e:
                print(f"Error recording login: {str(e)}")
            
            # Get user profile info
            try:
                profile = UserProfile.objects.get(user=user)
                role = profile.role
                profile_image = profile.profile_image.url if profile.profile_image else None
                print(f"Found profile for user {username}, role: {role}")
            except UserProfile.DoesNotExist:
                print(f"No profile found for user {username}, using defaults")
                role = "User"
                profile_image = None
            
            # Return successful response
            response_data = {
                "access": access_token,
                "refresh": str(refresh),
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "role": role,
                    "profile_image": profile_image
                }
            }
            print("Login successful, returning tokens")
            return Response(response_data, status=status.HTTP_200_OK)
        else:
            print(f"Authentication failed for user: {username}")
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )


@method_decorator(csrf_exempt, name='dispatch')
class SignupAPIView(APIView):
    permission_classes = []      # No permissions required for signup
    
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            # Get the profile that was automatically created by signals
            user_profile = UserProfile.objects.get(user=user)
            
            # Set role as Analyst
            user_profile.role = 'Analyst'
            
            # Create permission group for Analyst
            permission_group = PermissionGroup.objects.create(
                name=f"Analyst Group for {user.username}",
                can_view_dashboard=True,
                can_view_reports=True,
                can_edit_reports=True,
                can_delete_reports=False,
                can_view_users=True,
                can_edit_users=False,
                can_delete_users=False,
                can_view_notifications=True,
                can_manage_notifications=True
            )
            
            # Assign permission group to user profile
            user_profile.permission_group = permission_group
            
            # Update notification preferences
            user_profile.notify_on_threats = True
            user_profile.notify_on_alerts = True
            user_profile.notify_on_reports = True
            user_profile.save()
            
            Notification.objects.create(user=user, message='Welcome to the platform!')
            return Response({"message": "Account created successfully. Please log in."}, status=status.HTTP_201_CREATED)
        
        print(serializer.errors)  # For debugging
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ForgetPasswordAPIView(APIView):
    def post(self, request):
        serializer = ForgetPasswordSerializer(data=request.data)
        
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                token = generate_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                link = f"http://127.0.0.1:3000{reverse('api:reset_password', kwargs={'uidb64': uid, 'token': token})}"

                send_mail(
                    'Password Reset',
                    f'You can reset your password using this link: {link}',
                    'from@example.com',
                    [user.email],
                    fail_silently=False,
                )
                return Response({"message": "Password reset link has been sent to your email."}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"error": "Email is not registered."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordAPIView(APIView):
    def post(self, request, uidb64, token):
        serializer = ResetPasswordSerializer(data=request.data)

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)

            if not check_token(user, token):
                return Response({"error": "The password reset link is invalid or has expired."}, status=status.HTTP_400_BAD_REQUEST)

        except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
            print(f"Error: {e}")
            return Response({"error": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)

        if serializer.is_valid():
            new_password = serializer.validated_data['password']
            user.set_password(new_password)
            user.save()
            return Response({"message": "Password successfully changed."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        return Response({'status': 'success'}, status=status.HTTP_200_OK)


class MarkNotificationAsReadView(APIView):
    permission_classes = [IsAuthenticated]

    @method_decorator(csrf_exempt)
    def post(self, request, notification_id):
        try:
            notification = get_object_or_404(Notification, id=notification_id, user=request.user)
            notification.is_read = True
            notification.save()
            return Response({"message": "Notification marked as read"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class MarkAllNotificationsAsReadView(APIView):
    permission_classes = [IsAuthenticated]

    @method_decorator(csrf_exempt)
    def post(self, request):
        try:
            # Get all unread notifications for the current user
            notifications = Notification.objects.filter(user=request.user, is_read=False)
            # Mark all as read
            notifications.update(is_read=True)
            return Response({"message": "All notifications marked as read"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


def calculate_time_frame_start(time_frame):
    now = timezone.now()
    if time_frame == 'Day':
        return now - timedelta(days=1)
    elif time_frame == 'Week':
        return now - timedelta(weeks=1)
    elif time_frame == 'Month':
        return now - timedelta(days=30)
    elif time_frame == 'Year':
        return now - timedelta(days=365)
    return now - timedelta(days=365)  # Default to 1 year

def get_cached_or_calculate(key, calculation_func, timeout=300):
    result = cache.get(key)
    if result is None:
        result = calculation_func()
        cache.set(key, result, timeout)
    return result

def calculate_total_events(flows):
    return flows.aggregate(
        total=Sum('packet_count')
    )['total'] or 0

def calculate_active_events(flows, time_frame_start):
    return flows.filter(
        start_time__gte=time_frame_start,
        end_time__isnull=True
    ).count()

def calculate_avg_response_time(alerts, time_frame_start):
    # Get all resolved alerts within the time frame
    resolved_alerts = alerts.filter(
        status__iexact='resolved',
        created_at__gte=time_frame_start
    ).exclude(
        status__iexact='false_positive'  # Exclude false positives
    ).annotate(
        response_time=ExpressionWrapper(
            F('updated_at') - F('created_at'),
            output_field=DurationField()
        )
    )
    
    # Calculate average response time
    avg_time = resolved_alerts.aggregate(
        avg_time=Avg('response_time')
    )['avg_time']
    
    if avg_time is None:
        return 0
        
    # Convert timedelta to seconds and round to 2 decimal places
    return round(avg_time.total_seconds(), 2)

def calculate_affected_devices(flows, time_frame_start):
    # Get unique IPs involved in flows after time_frame_start
    affected_ips = flows.filter(
        start_time__gte=time_frame_start
    ).values_list('src_ip', 'dst_ip', flat=False).distinct()
    
    # Flatten the list of tuples and get unique IPs
    unique_ips = set()
    for src_ip, dst_ip in affected_ips:
        unique_ips.add(src_ip)
        unique_ips.add(dst_ip)
    
    # Get total number of unique IPs in the system
    total_ips = NetworkFlow.objects.values_list('src_ip', 'dst_ip', flat=False).distinct()
    total_unique_ips = set()
    for src_ip, dst_ip in total_ips:
        total_unique_ips.add(src_ip)
        total_unique_ips.add(dst_ip)
    
    # Calculate percentage
    if total_unique_ips:
        return round((len(unique_ips) / len(total_unique_ips)) * 100, 2)
    return 0

def calculate_alert_accuracy(alerts, time_frame_start):
    # Get all resolved alerts within the time frame
    resolved_alerts = alerts.filter(
        created_at__gte=time_frame_start
    )
    
    # Count true positives (alerts that were resolved as actual threats)
    true_positives = resolved_alerts.filter(
        status__iexact='resolved',  # Was resolved
        threat_type__isnull=False,  # Has a threat type
        severity__in=['high', 'critical']  # High severity alerts
    ).exclude(
        status__iexact='false_positive'  # Not a false positive
    ).count()
    
    # Count false positives (alerts that were resolved as false alarms)
    false_positives = resolved_alerts.filter(
        status__iexact='false_positive'
    ).count()
    
    # Count true negatives (alerts that were correctly identified as non-threats)
    true_negatives = resolved_alerts.filter(
        status__iexact='false_positive',
        severity__in=['low', 'medium']  # Low severity alerts
    ).count()
    
    # Calculate accuracy percentage using precision
    total_detected = true_positives + false_positives
    if total_detected > 0:
        precision = (true_positives / total_detected) * 100
        return round(precision, 2)
    return 0

def calculate_alert_trend(alerts):
    now = timezone.now()
    current_period_start = now - timedelta(days=7)
    previous_period_start = current_period_start - timedelta(days=7)
    
    current_period_alerts = alerts.filter(
        created_at__gte=current_period_start
    ).count()
    
    previous_period_alerts = alerts.filter(
        created_at__gte=previous_period_start,
        created_at__lt=current_period_start
    ).count()
    
    if previous_period_alerts > 0:
        return round(((current_period_alerts - previous_period_alerts) / previous_period_alerts) * 100, 2)
    return 0

class EventDetailsView(IncludeUserDataMixin, CalculateChangeMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Get query parameters with defaults
            time_frame = request.query_params.get('timeFrame', 'All-Time')
            chart_period = request.query_params.get('chartPeriod', 'Month')
            time_frame_start = calculate_time_frame_start(time_frame)

            # Get user's role and agents
            user = request.user
            is_admin = user.userprofile.role == 'Admin'
            user_agents = Agent.objects.filter(user=user) if not is_admin else None

            # Get all network flows for the user
            flows = NetworkFlow.objects.all()
            if not is_admin:
                flows = flows.filter(agents__in=user_agents)

            # Get all threats and alerts for these flows
            threats = Threat.objects.filter(flow_id__in=flows.values('id'))
            alerts = Alert.objects.filter(flow_id__in=flows.values('id'))
            suspicious_ips = SuspiciousIP.objects.filter(threat__flow_id__in=flows.values('id'))

            # Calculate statistics using helper functions
            cache_key_prefix = f"event_details_{user.id}_{time_frame}"
            
            total_events = get_cached_or_calculate(
                f"{cache_key_prefix}_total_events",
                lambda: calculate_total_events(flows)
            )
            
            active_events = get_cached_or_calculate(
                f"{cache_key_prefix}_active_events",
                lambda: calculate_active_events(flows, time_frame_start)
            )
            
            avg_response_time = get_cached_or_calculate(
                f"{cache_key_prefix}_avg_response_time",
                lambda: calculate_avg_response_time(alerts, time_frame_start)
            )
            
            affected_devices = get_cached_or_calculate(
                f"{cache_key_prefix}_affected_devices",
                lambda: calculate_affected_devices(flows, time_frame_start)
            )
            
            alert_accuracy = get_cached_or_calculate(
                f"{cache_key_prefix}_alert_accuracy",
                lambda: calculate_alert_accuracy(alerts, time_frame_start)
            )
            
            alert_trend = get_cached_or_calculate(
                f"{cache_key_prefix}_alert_trend",
                lambda: calculate_alert_trend(alerts)
            )

            # Process events data
            events_data = []
            for flow in flows:
                event = {
                    'id': flow.id,
                    'flow_id': flow.flow_id,
                    'timestamp': flow.start_time,
                    'source_ip': flow.src_ip,
                    'destination_ip': flow.dst_ip,
                    'protocol': flow.protocol,
                    'threat_level': flow.threat_level,
                    'threats': flow.threat_details if isinstance(flow.threat_details, list) else [],
                    'alerts': [{
                        'id': alert.id,
                        'severity': alert.severity,
                        'status': alert.status,
                        'description': alert.description,
                        'threat_type': alert.threat_type
                    } for alert in alerts.filter(flow=flow)],
                    'suspicious_ips': [{
                        'ip': ip.ip_address,
                        'reason': ip.reason
                    } for ip in suspicious_ips.filter(threat__flow=flow)]
                }
                events_data.append(event)

            # Sort events by timestamp
            events_data.sort(key=lambda x: x['timestamp'], reverse=True)

            # Calculate distributions
            threat_distribution = threats.values('category').annotate(
                count=Count('id')
            ).order_by('-count')

            alert_distribution = alerts.values('severity').annotate(
                count=Count('id')
            ).order_by('-count')

            # Prepare chart data based on period
            if chart_period == 'Day':
                labels = [f"{i:02d}:00" for i in range(24)]
                data = list(threats.filter(
                    created_at__gte=time_frame_start
                ).values('created_at__hour').annotate(
                    count=Count('id')
                ).order_by('created_at__hour').values_list('count', flat=True))
                data = data + [0] * (24 - len(data))
            elif chart_period == 'Week':
                labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
                data = list(threats.filter(
                    created_at__gte=time_frame_start
                ).values('created_at__week_day').annotate(
                    count=Count('id')
                ).order_by('created_at__week_day').values_list('count', flat=True))
                data = data + [0] * (7 - len(data))
            else:  # Month
                labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
                data = list(threats.filter(
                    created_at__gte=time_frame_start
                ).values('created_at__month').annotate(
                    count=Count('id')
                ).order_by('created_at__month').values_list('count', flat=True))
                data = data + [0] * (12 - len(data))

            return Response({
                'events': events_data,
                'statistics': {
                    'total_events': total_events,
                    'active_events': active_events,
                    'avg_response_time': avg_response_time,
                    'affected_devices': affected_devices,
                    'alert_accuracy': alert_accuracy,
                    'alert_trend': alert_trend,
                    'threat_distribution': list(threat_distribution),
                    'alert_distribution': list(alert_distribution)
                },
                'charts': {
                    'threatsOverTime': {
                        'labels': labels,
                        'data': data
                    }
                }
            })

        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ReportsView(IncludeUserDataMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_data = self.get_user_data(request.user)
        
        try:
            # Get user profile and check permissions
            user_profile = UserProfile.objects.get(user=request.user)
            if not user_profile.permission_group or not user_profile.permission_group.can_view_reports:
                return Response(
                    {"error": "You don't have permission to view reports."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Get reports based on user role and permissions
            if user_profile.role in ['Admin', 'Analyst']:
                reports = Report.objects.all().order_by('-created_at')
            else:
                reports = Report.objects.filter(user=request.user).order_by('-created_at')
                
            reports_data = []
            for report in reports:
                try:
                    # Parse the content if it's a string
                    content = report.content
                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except json.JSONDecodeError:
                            content = {"raw_content": content}
                    
                    # Get threat and alert information with better defaults
                    threat_info = {
                        "id": report.threat.id if report.threat else None,
                        "category": report.threat.category if report.threat else "Uncategorized",
                        "description": report.threat.description if report.threat else "No threat description available",
                        "confidence": report.threat.confidence if report.threat else 0.0
                    }
                    
                    alert_info = {
                        "id": report.alert.id if report.alert else None,
                        "severity": report.alert.severity if report.alert else "Medium",
                        "status": report.alert.status if report.alert else "New",
                        "description": report.alert.description if report.alert else "No alert description available",
                        "threat_type": report.alert.threat_type if report.alert else "Unknown Threat"
                    }
                    
                    # Format data according to frontend expectations with better defaults
                    report_data = {
                        "id": report.id,
                        "threatType": alert_info.get("threat_type", "Unknown Threat"),
                        "timestamp": report.created_at.strftime("%b %d, %Y, %H:%M"),
                        "targetDevice": content.get("target_device") or content.get("flow_analysis", {}).get("destination", {}).get("ip") or "No Target Device",
                        "threatStatus": report.report_status or "New",
                        "attackSource": content.get("source_ip") or content.get("flow_analysis", {}).get("source", {}).get("ip") or "Unknown Source",
                        "severityLevel": alert_info.get("severity", "Medium"),
                        "content": content,
                        "user": report.user.username,
                        "threat": threat_info,
                        "alert": alert_info
                    }
                    
                    reports_data.append(report_data)
                except Exception as e:
                    print(f"Error processing report {report.id}: {str(e)}")
                    continue
                
            return Response({
                'reports': reports_data,
                'user_data': user_data
            }, status=status.HTTP_200_OK)
            
        except UserProfile.DoesNotExist:
            return Response(
                {"error": "User profile not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": f"Error fetching reports: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    def post(self, request):
        user = request.user
        data = request.data
        
        try:
            # Check user permissions
            user_profile = UserProfile.objects.get(user=user)
            if not user_profile.permission_group or not user_profile.permission_group.can_add_reports:
                return Response(
                    {"error": "You don't have permission to create reports."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Validate required fields
            required_fields = ['alert_id', 'content']
            for field in required_fields:
                if field not in data:
                    return Response(
                        {"error": f"Missing required field: {field}"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                    
            alert = Alert.objects.get(id=data['alert_id'])
            
            # Get threat if available
            threat = None
            try:
                threat = alert.threat
            except Threat.DoesNotExist:
                pass
                
            # Create report
            report = Report.objects.create(
                user=user,
                alert=alert,
                threat=threat,
                content=data['content'],
                report_status='open'
            )
            
            return Response({
                "message": "Report created successfully",
                "report_id": report.id
            }, status=status.HTTP_201_CREATED)
            
        except Alert.DoesNotExist:
            return Response(
                {"error": "Alert not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except UserProfile.DoesNotExist:
            return Response(
                {"error": "User profile not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, report_id):
        """Update an existing report"""
        user = request.user
        data = request.data
        
        try:
            # Check user permissions
            user_profile = UserProfile.objects.get(user=user)
            if not user_profile.permission_group or not user_profile.permission_group.can_edit_reports:
                return Response(
                    {"error": "You don't have permission to edit reports."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Get the report
            report = Report.objects.get(id=report_id)
            
            # Update report fields
            if 'content' in data:
                report.content = data['content']
            if 'report_status' in data:
                report.report_status = data['report_status']
            
            report.save()
            
            return Response({
                "message": "Report updated successfully",
                "report_id": report.id
            }, status=status.HTTP_200_OK)
            
        except Report.DoesNotExist:
            return Response(
                {"error": "Report not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except UserProfile.DoesNotExist:
            return Response(
                {"error": "User profile not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NetworkFlowAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        if pk:
            flow = get_object_or_404(NetworkFlow, pk=pk)
            data = {
                "id": flow.id,
                "source_ip": flow.src_ip,
                "destination_ip": flow.dst_ip,
                "source_port": flow.src_port,
                "destination_port": flow.dst_port,
                "protocol": flow.protocol,
                "start_time": flow.start_time,
                "end_time": flow.end_time,
                "duration": str(flow.duration),
                "packet_count": flow.packet_count,
                "total_bytes": flow.total_bytes,
                "threat_level": flow.threat_level,
                "threat_details": flow.threat_details,
                "anomalies": flow.anomalies,
                "protocol_analysis": flow.protocol_analysis,
                "created_at": flow.created_at,
                "updated_at": flow.updated_at
            }
        else:
            flows = NetworkFlow.objects.all().order_by('-created_at')[:100]  # Limit to recent 100
            data = [{
                "id": flow.id, 
                "source_ip": flow.src_ip, 
                "destination_ip": flow.dst_ip,
                "protocol": flow.protocol,
                "start_time": flow.start_time,
                "end_time": flow.end_time,
                "packet_count": flow.packet_count,
                "total_bytes": flow.total_bytes,
                "threat_level": flow.threat_level
            } for flow in flows]
        
        return Response(data)
    
    @method_decorator(csrf_exempt, name='dispatch')
    def post(self, request):
        try:
            data = request.data
            serializer = NetworkFlowSerializer(data=data)
            
            if serializer.is_valid():
                flow = serializer.save()
                
                # Create alerts for high threat levels
                if flow.threat_level == 'high':
                    Alert.objects.create(
                        flow=flow,
                        severity='high',
                        description=f"High threat level detected in flow {flow.flow_id}",
                        threat_type=flow.threats[0] if flow.threats else 'unknown',
                        source='network_analysis'
                    )
                
                # Create threats for detected anomalies
                for threat in flow.threats:
                    Threat.objects.create(
                        flow=flow,
                        category=self._map_threat_to_category(threat),
                        description=f"Detected {threat} in network flow",
                        confidence=0.9 if flow.threat_level == 'high' else 0.7
                    )
                
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _map_threat_to_category(self, threat):
        threat_category_map = {
            'port_scan': 'scan',
            'large_packet_size': 'dos',
            'suspicious_port': 'suspicious',
            'brute_force': 'brute_force',
            'malware': 'malware'
        }
        return threat_category_map.get(threat, 'other')


class AlertAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        if pk:
            alert = get_object_or_404(Alert, pk=pk)
            data = {
                "id": alert.id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "description": alert.description,
                "alert_time": alert.alert_time,
                "flow": {
                    "id": alert.flow.id,
                    "source_ip": alert.flow.source_ip,
                    "destination_ip": alert.flow.destination_ip
                },
                "attack_type": alert.attack_type.type if alert.attack_type else None
            }
        else:
            alerts = Alert.objects.all().order_by('-alert_time')[:100]
            data = [{
                "id": alert.id, 
                "alert_type": alert.alert_type, 
                "severity": alert.severity,
                "alert_time": alert.alert_time
            } for alert in alerts]
        
        return Response(data)
    
    def post(self, request):
        try:
            data = request.data
            
            # Get required objects
            flow = get_object_or_404(NetworkFlow, pk=data.get("flow_id"))
            
            # Get attack type if provided
            attack_type = None
            if data.get("attack_type_id"):
                attack_type = get_object_or_404(AttackType, pk=data.get("attack_type_id"))
            
            # Create alert
            alert = Alert.objects.create(
                flow=flow,
                alert_type=data.get("alert_type"),
                severity=data.get("severity"),
                description=data.get("description", ""),
                alert_time=data.get("alert_time", timezone.now()),
                attack_type=attack_type
            )
            
            # Create notification for all admin/analyst users
            admin_profiles = UserProfile.objects.filter(role__in=['Admin', 'Analyst'])
            for profile in admin_profiles:
                Notification.objects.create(
                    user=profile.user,
                    alert=alert,
                    message=f"New {alert.severity} alert: {alert.alert_type}",
                    notification_type='push',
                )
            
            return Response({
                "id": alert.id, 
                "alert_type": alert.alert_type, 
                "severity": alert.severity
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ThreatAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        if pk:
            threat = get_object_or_404(Threat, pk=pk)
            data = {
                "id": threat.id,
                "category": threat.category,
                "confidence": threat.confidence,
                "description": threat.description,
                "created_at": threat.created_at,
                "flow": {
                    "id": threat.flow.id,
                    "src_ip": threat.flow.src_ip,
                    "dst_ip": threat.flow.dst_ip,
                    "protocol": threat.flow.protocol
                }
            }
        else:
            threats = Threat.objects.all().order_by('-created_at')[:100]
            data = [{
                "id": threat.id, 
                "category": threat.category, 
                "confidence": threat.confidence,
                "created_at": threat.created_at
            } for threat in threats]
        
        return Response(data)
    
    def post(self, request):
        try:
            data = request.data
            
            # Get required objects
            alert = get_object_or_404(Alert, pk=data.get("alert_id"))
            
            # Get attack type if provided
            attack_type = None
            if data.get("attack_type_id"):
                attack_type = get_object_or_404(AttackType, pk=data.get("attack_type_id"))
            
            # Create threat
            threat = Threat.objects.create(
                alert=alert,
                threat_name=data.get("threat_name"),
                threat_level=data.get("threat_level"),
                threat_source=data.get("threat_source", "Manual"),
                response_action=data.get("response_action", "Investigate"),
                attack_type=attack_type
            )
            
            return Response({
                "id": threat.id, 
                "threat_name": threat.threat_name, 
                "threat_level": threat.threat_level
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class SuspiciousIPAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        if pk:
            ip = get_object_or_404(SuspiciousIP, pk=pk)
            data = {
                "id": ip.id,
                "ip_address": ip.ip_address,
                "date": ip.date,
                "reason": ip.reason,
                "alert": ip.alert.id if ip.alert else None,
                "threat": ip.threat.id if ip.threat else None
            }
        else:
            ips = SuspiciousIP.objects.all().order_by('-date')[:100]
            data = [{
                "id": ip.id, 
                "ip_address": ip.ip_address, 
                "date": ip.date,
                "reason": ip.reason
            } for ip in ips]
        
        return Response(data)
    
    def post(self, request):
        try:
            data = request.data
            
            # Get related objects if provided
            alert = None
            threat = None
            
            if data.get("alert_id"):
                alert = get_object_or_404(Alert, pk=data.get("alert_id"))
                
            if data.get("threat_id"):
                threat = get_object_or_404(Threat, pk=data.get("threat_id"))
            
            # Create suspicious IP
            ip = SuspiciousIP.objects.create(
                ip_address=data.get("ip_address"),
                date=data.get("date", timezone.now().date()),
                reason=data.get("reason", "Manual addition"),
                alert=alert,
                threat=threat
            )
            
            return Response({
                "id": ip.id, 
                "ip_address": ip.ip_address, 
                "date": ip.date
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UserManagementView(IncludeUserDataMixin, APIView):
    """
    API View to handle user management actions.
    POST: Create a new user
    GET: List all users
    PUT: Update an existing user
    DELETE: Remove a user
    """
    permission_classes = [IsAuthenticated, IsAdminOrAnalyst]

    def get(self, request):
        users = User.objects.all()
        serialized_users = []

        for user in users:
            try:
                user_profile = UserProfile.objects.get(user=user)
                user_role = user_profile.role
            except UserProfile.DoesNotExist:
                user_role = 'No Role Assigned'

            serialized_users.append({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user_role,
                "is_active": user.is_active
            })

        user_data = self.get_user_data(request.user)
        return Response({'user_data': user_data, 'users': serialized_users}, status=status.HTTP_200_OK)

    def post(self, request):
        """Creates a new user"""
        data = request.data
        
        # Additional validation for analysts - they can only create viewers or devices
        if hasattr(request.user, 'userprofile') and request.user.userprofile.role == 'Analyst':
            role = data.get('role')
            if role not in ['Viewer', 'Device']:
                return Response(
                    {"error": "Analysts can only create users with 'Viewer' or 'Device' roles."},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        if 'username' not in data or 'email' not in data or 'password' not in data or 'role' not in data:
            return Response({"message": "Username, email, password, and role are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if username already exists
        if User.objects.filter(username=data['username']).exists():
            return Response({"error": f"Username '{data['username']}' already exists."}, status=status.HTTP_400_BAD_REQUEST)
            
        # Check if email already exists
        if User.objects.filter(email=data['email']).exists():
            return Response({"error": f"Email '{data['email']}' is already registered."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create(
            username=data['username'],
            email=data['email'],
            password=make_password(data['password']),
            is_active=data.get('is_active', True)
        )
        
        # Get the profile that was automatically created by signals
        user_profile = UserProfile.objects.get(user=user)
        # Update the role
        user_profile.role = data['role']
        user_profile.save()

        return Response({"message": f"User {user.username} created successfully with role {user_profile.role}."}, status=status.HTTP_201_CREATED)

    def put(self, request, user_id):
        user = get_object_or_404(User, id=user_id)
        data = request.data
        if 'username' not in data and 'email' not in data and 'password' not in data and 'role' not in data:
            return Response({"message": "At least one field (username, email, password, or role) must be provided for update."}, status=status.HTTP_400_BAD_REQUEST)

        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        if 'password' in data:
            user.password = make_password(data['password'])
        user.is_active = data.get('is_active', user.is_active)
        user.save()

        if 'role' in data:
            user_profile = UserProfile.objects.get(user=user)
            user_profile.role = data['role']
            user_profile.save()

        return Response({"message": f"User {user.username} updated successfully."}, status=status.HTTP_200_OK)

    def delete(self, request, user_id):
        user = get_object_or_404(User, id=user_id)
        
        try:
            user_profile = UserProfile.objects.get(user=user)
            user_profile.delete()
        except UserProfile.DoesNotExist:
            pass  

        user.delete()
        return Response({"message": f"User {user.username} and associated profile deleted successfully."}, status=status.HTTP_200_OK)


class SystemManagementView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        try:
            settings = System_Settings.objects.get(id=1) 
            system_settings = {
                "system_name": settings.system_name,
                "version": settings.version,
                "maintenance_mode": settings.maintenance_mode,
                "max_login_attempts": settings.max_login_attempts,
                "notification_settings": settings.notification_settings,

            }
        except System_Settings.DoesNotExist:
            system_settings = {
                "system_name": "Osiris Network Analysis System",
                "version": "1.0.0",
                "maintenance_mode": False,
                "max_login_attempts": 5,
                "notification_settings": {"email": True, "sms": False},

            }

        return Response(system_settings, status=status.HTTP_200_OK)

    def post(self, request):
        data = request.data
        try:
            if System_Settings.objects.count() > 1:
                return Response({"message": "Error: There can only be one settings record."}, status=status.HTTP_400_BAD_REQUEST)

            settings, created = System_Settings.objects.get_or_create(id=1, defaults={
                "system_name": "Osiris Network Analysis System",
                "version": "1.0.0",
                "maintenance_mode": False,
                "max_login_attempts": 5,
                "notification_settings": {"email": True, "sms": False},

            })

            settings.system_name = data.get("system_name", settings.system_name)
            settings.version = data.get("version", settings.version)
            settings.maintenance_mode = data.get("maintenance_mode", settings.maintenance_mode)
            settings.max_login_attempts = data.get("max_login_attempts", settings.max_login_attempts)
            settings.notification_settings = data.get("notification_settings", settings.notification_settings)
            settings.save()

            return Response({"message": "System settings updated successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": f"Error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)


import psutil 
from django.db import connection  

class CheckSystemHealthView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        # التحقق من حالة الخادم
        server_status, cpu_usage, memory_usage = self.check_server_status()
        
        # التحقق من حالة قاعدة البيانات
        database_status = self.check_database_status()

        health_status = {
            "server_status": server_status,
            "cpu_usage_percentage": cpu_usage,
            "memory_usage_percentage": memory_usage,
            "database_status": database_status
        }

        return Response(health_status, status=status.HTTP_200_OK)

    def check_server_status(self):
        try:
            cpu_usage = psutil.cpu_percent(interval=1) 
            memory_info = psutil.virtual_memory() 
            memory_usage = memory_info.percent 

            if cpu_usage < 90 and memory_usage < 90:
                return "Healthy", cpu_usage, memory_usage
            else:
                return "Warning", cpu_usage, memory_usage
        except Exception as e:
            return f"Error: {str(e)}", 0, 0

    def check_database_status(self):
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            return "Healthy"
        except Exception as e:
            return f"Error: {str(e)}"


class SettingsView(IncludeUserDataMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_data = self.get_user_data(request.user)
        
        # Get user settings
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            
            # Get system settings if admin
            system_settings = None
            if user_profile.role == 'Admin':
                system_settings, created = System_Settings.objects.get_or_create(
                    id=1,
                    defaults={
                        "system_name": "Osiris Network Analysis System",
                        "version": "1.0.0",
                        "maintenance_mode": False,
                        "max_login_attempts": 5,
                        "notification_settings": {"email": True, "sms": False},
                    }
                )
                system_settings = {
                    "system_name": system_settings.system_name,
                    "version": system_settings.version,
                    "maintenance_mode": system_settings.maintenance_mode,
                    "max_login_attempts": system_settings.max_login_attempts,
                    "notification_settings": system_settings.notification_settings,
                }
                
            # Get notification settings
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
            
            settings_data = {
                "user_profile": {
                    "username": request.user.username,
                    "email": request.user.email,
                    "role": user_profile.role,
                    "profile_image": user_profile.profile_image.url if user_profile.profile_image else None,
                },
                "notification_preferences": notification_preferences,
                "interface_settings": interface_settings,
                "system_settings": system_settings,
            }
            
            return Response({'settings': settings_data, 'user_data': user_data}, status=status.HTTP_200_OK)
            
        except UserProfile.DoesNotExist:
            return Response({"error": "User profile not found"}, status=status.HTTP_404_NOT_FOUND)
    
    def post(self, request):
        """Update user settings"""
        try:
            data = request.data
            user = request.user
            user_profile = UserProfile.objects.get(user=user)
            
            # Update user profile fields
            if data.get('email'):
                user.email = data.get('email')
                user.save()
                
            if data.get('notification_preferences'):
                notification_prefs = data.get('notification_preferences')
                
                # Update notification preferences
                for key, value in notification_prefs.items():
                    if hasattr(user_profile, key):
                        setattr(user_profile, key, value)
            
            if data.get('interface_settings'):
                interface_settings = data.get('interface_settings')
                
                # Update interface settings
                for key, value in interface_settings.items():
                    if hasattr(user_profile, key):
                        setattr(user_profile, key, value)
            
            # Update system settings if admin
            if data.get('system_settings') and user_profile.role == 'Admin':
                system_settings, created = System_Settings.objects.get_or_create(id=1)
                system_data = data.get('system_settings')
                
                if 'system_name' in system_data:
                    system_settings.system_name = system_data['system_name']
                
                if 'version' in system_data:
                    system_settings.version = system_data['version']
                
                if 'maintenance_mode' in system_data:
                    system_settings.maintenance_mode = system_data['maintenance_mode']
                
                if 'max_login_attempts' in system_data:
                    system_settings.max_login_attempts = system_data['max_login_attempts']
                
                if 'notification_settings' in system_data:
                    system_settings.notification_settings = system_data['notification_settings']
                
                system_settings.save()
            
            # Save user profile
            user_profile.save()
            
            return Response({"message": "Settings updated successfully"}, status=status.HTTP_200_OK)
            
        except UserProfile.DoesNotExist:
            return Response({"error": "User profile not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


from .models import Agent
from .serializers import AgentSerializer

class AddAgentView(generics.CreateAPIView):
    queryset = Agent.objects.all()
    serializer_class = AgentSerializer


class NotificationView(IncludeUserDataMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        print(f"=== NotificationView.get() ===")
        print(f"User: {request.user.username} (ID: {request.user.id})")
        
        user_data = self.get_user_data(request.user)
        
        # Get all notifications for the user, ordered by sent_at
        notifications = Notification.objects.filter(user=request.user).order_by('-sent_at')
        print(f"Found {notifications.count()} total notifications")
        print(f"Unread notifications: {notifications.filter(is_read=False).count()}")
        
        # If no notifications exist, create some default ones
        if notifications.count() == 0:
            print("Creating default notifications...")
            default_notifications = [
                {
                    'message': 'مرحباً بك في نظام Osiris!',
                    'notification_type': 'push',
                    'priority': 'high',
                    'is_read': False
                },
                {
                    'message': 'يمكنك الآن مراقبة وتحليل حركة الشبكة الخاصة بك',
                    'notification_type': 'push',
                    'priority': 'medium',
                    'is_read': False
                },
                {
                    'message': 'استخدم لوحة التحكم للوصول إلى جميع الميزات',
                    'notification_type': 'push',
                    'priority': 'low',
                    'is_read': False
                }
            ]
            
            for notification_data in default_notifications:
                Notification.objects.create(
                    user=request.user,
                    message=notification_data['message'],
                    notification_type=notification_data['notification_type'],
                    priority=notification_data['priority'],
                    is_read=notification_data['is_read']
                )
            
            # Fetch the newly created notifications
            notifications = Notification.objects.filter(user=request.user).order_by('-sent_at')
            print(f"Created {notifications.count()} default notifications")
        
        # Serialize the notifications
        serializer = NotificationSerializer(notifications, many=True)
        print(f"Serialized notifications: {serializer.data}")
        
        response_data = {
            'notifications': serializer.data,
            'user_data': user_data,
            'unread_count': notifications.filter(is_read=False).count()
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    def post(self, request):
        """Create a new notification"""
        data = request.data
        user_id = data.get('user_id')
        
        # Verify user has permission to create notifications for others
        if user_id and str(user_id) != str(request.user.id):
            user_profile = UserProfile.objects.get(user=request.user)
            if user_profile.role not in ['Admin', 'Analyst']:
                return Response({"error": "You don't have permission to create notifications for other users"}, 
                               status=status.HTTP_403_FORBIDDEN)
        
        # Get the user
        try:
            user = User.objects.get(id=user_id) if user_id else request.user
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
        # Create notification
        notification = Notification.objects.create(
            user=user,
            message=data.get('message', 'New notification'),
            notification_type=data.get('notification_type', 'push')
        )
        
        # If there's an alert_id or threat_id, associate with the notification
        if data.get('alert_id'):
            try:
                alert = Alert.objects.get(id=data.get('alert_id'))
                notification.alert = alert
                notification.save()
            except Alert.DoesNotExist:
                pass
                
        if data.get('threat_id'):
            try:
                threat = Threat.objects.get(id=data.get('threat_id'))
                notification.threat = threat
                notification.save()
            except Threat.DoesNotExist:
                pass
                
        return Response({
            "message": "Notification created successfully",
            "notification": NotificationSerializer(notification).data
        }, status=status.HTTP_201_CREATED)
    
    def put(self, request):
        """Mark multiple notifications as read"""
        notification_ids = request.data.get('notification_ids', [])
        
        if not notification_ids:
            return Response({"error": "No notification IDs provided"}, status=status.HTTP_400_BAD_REQUEST)
            
        updated_count = Notification.objects.filter(
            id__in=notification_ids, 
            user=request.user
        ).update(is_read=True)
        
        return Response({
            "message": f"{updated_count} notifications marked as read"
        }, status=status.HTTP_200_OK)

class HelpSupportView(IncludeUserDataMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_data = self.get_user_data(request.user)
        
        help_content = {
            "sections": [
                {
                    "title": "Getting Started",
                    "content": "Welcome to the Osiris Network Analysis System. This system helps you monitor and analyze your network traffic for potential security threats."
                },
                {
                    "title": "Dashboard",
                    "content": "The dashboard provides an overview of your network's security status, including threats detected, suspicious IPs, and user login activities."
                },
                {
                    "title": "Alerts",
                    "content": "Alerts notify you of potential security incidents that need attention. They are categorized by severity level."
                },
                {
                    "title": "Reports",
                    "content": "You can generate and view reports about security incidents for further analysis and documentation."
                },
                {
                    "title": "Contact Support",
                    "content": "For technical support, please contact our help desk at support@osiriswatch.com or call +1-800-123-4567."
                }
            ],
            "faqs": [
                {
                    "question": "How do I interpret the threat levels?",
                    "answer": "Threats are categorized as low, medium, or high. High-level threats require immediate attention, medium should be investigated soon, and low can be monitored."
                },
                {
                    "question": "Can I customize alert notifications?",
                    "answer": "Yes, you can set up notification preferences in your user settings to receive alerts via email, SMS, or push notifications."
                },
                {
                    "question": "How often is the data updated?",
                    "answer": "The dashboard data is updated in real-time for critical alerts. Regular statistics are updated every 15 minutes."
                }
            ]
        }

        return Response({'help': help_content, 'user_data': user_data}, status=status.HTTP_200_OK)

class ActivityView(IncludeUserDataMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_data = self.get_user_data(request.user)
        
        # Get activity filters from query params
        activity_type = request.query_params.get('type')
        days = int(request.query_params.get('days', 7))  # Default to 7 days
        
        # Calculate the date range
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        activity_data = {
            "time_range": {
                "start": start_date,
                "end": end_date
            },
            "user_logins": [],
            "alerts": [],
            "threats": []
        }
        
        # Get user logins if requested or no specific type specified
        if not activity_type or activity_type == 'user_logins':
            user_logins = UserLogin.objects.filter(
                timestamp__gte=start_date,
                timestamp__lte=end_date
            ).order_by('-timestamp')
            
            activity_data["user_logins"] = [{
                "id": login.id,
                "user": login.user.username,
                "timestamp": login.timestamp
            } for login in user_logins]
        
        # Get alerts if requested or no specific type specified
        if not activity_type or activity_type == 'alerts':
            alerts = Alert.objects.filter(
                alert_time__gte=start_date,
                alert_time__lte=end_date
            ).order_by('-alert_time')
            
            activity_data["alerts"] = [{
                "id": alert.id,
                "type": alert.alert_type,
                "severity": alert.severity,
                "time": alert.alert_time
            } for alert in alerts]
        
        # Get threats if requested or no specific type specified
        if not activity_type or activity_type == 'threats':
            threats = Threat.objects.filter(
                date__gte=start_date.date(),
                date__lte=end_date.date()
            ).order_by('-date')
            
            activity_data["threats"] = [{
                "id": threat.id,
                "name": threat.threat_name,
                "level": threat.threat_level,
                "date": threat.date
            } for threat in threats]
        
        return Response({'activity': activity_data, 'user_data': user_data}, status=status.HTTP_200_OK)

class ChangePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        user = request.user
        data = request.data
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not user.check_password(current_password):
            return Response(
                {"error": "Current password is incorrect."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if new_password != confirm_password:
            return Response(
                {"error": "New passwords do not match."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Password validation
        if len(new_password) < 8:
            return Response(
                {"error": "Password must be at least 8 characters long."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Update password
        user.set_password(new_password)
        user.save()
        
        # Update last_password_change in UserProfile
        try:
            profile = UserProfile.objects.get(user=user)
            profile.last_password_change = timezone.now()
            profile.save()
        except UserProfile.DoesNotExist:
            pass
            
        # Create a new JWT token
        refresh = RefreshToken.for_user(user)
        
        return Response({
            "message": "Password changed successfully.",
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }, status=status.HTTP_200_OK)


class UpdateProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    
    def get(self, request):
        user = request.user
        try:
            profile = UserProfile.objects.get(user=user)
            serializer = UserProfileSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response(
                {"error": "User profile not found."},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def put(self, request):
        user = request.user
        data = request.data
        
        try:
            profile = UserProfile.objects.get(user=user)
            
            # Update User model
            if 'first_name' in data:
                user.first_name = data['first_name']
            if 'last_name' in data:
                user.last_name = data['last_name']
                
            # Check if email is being updated
            if 'email' in data and data['email'] != user.email:
                # Check if email already exists
                if User.objects.exclude(pk=user.pk).filter(email=data['email']).exists():
                    return Response(
                        {"error": "This email is already in use by another user."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                user.email = data['email']
                profile.is_email_verified = False
                
                # Send verification email
                from accounts.views import create_verification_token
                create_verification_token(user)
                
            user.save()
            
            # Update UserProfile model
            if 'bio' in data:
                profile.bio = data['bio']
            if 'phone_number' in data:
                profile.phone_number = data['phone_number']
            if 'profile_image' in request.FILES:
                profile.profile_image = request.FILES['profile_image']
                
            profile.save()
            
            # Return updated profile
            serializer = UserProfileSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except UserProfile.DoesNotExist:
            return Response(
                {"error": "User profile not found."},
                status=status.HTTP_404_NOT_FOUND
            )


class VerifyEmailAPIView(APIView):
    def get(self, request, token):
        try:
            verification = EmailVerification.objects.get(
                token=token,
                expires_at__gt=timezone.now(),
                verified=False
            )
            
            # Mark email as verified
            verification.verified = True
            verification.save()
            
            # Update user profile
            profile = UserProfile.objects.get(user=verification.user)
            profile.is_email_verified = True
            profile.save()
            
            return Response(
                {"message": "Email verification successful."},
                status=status.HTTP_200_OK
            )
            
        except EmailVerification.DoesNotExist:
            return Response(
                {"error": "Invalid or expired verification link."},
                status=status.HTTP_400_BAD_REQUEST
            )


class ExportReportAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, report_id):
        try:
            report = Report.objects.get(id=report_id)
            
            # Check if user has permission to access this report
            if request.user != report.user and not request.user.is_staff:
                return Response(
                    {"error": "You don't have permission to access this report."},
                    status=status.HTTP_403_FORBIDDEN
                )
                
            # Get requested format
            export_format = request.query_params.get('format', 'text')
            
            # Update report format
            report.report_format = export_format
            report.save()
            
            # Generate report file based on format
            if export_format == 'pdf':
                # Generate PDF file (example implementation)
                # In a real application, use a PDF generation library
                return Response(
                    {"message": "PDF report generation started.", "report_id": report.id},
                    status=status.HTTP_202_ACCEPTED
                )
                
            elif export_format == 'csv':
                # Generate CSV file (example implementation)
                return Response(
                    {"message": "CSV report generation started.", "report_id": report.id},
                    status=status.HTTP_202_ACCEPTED
                )
                
            else:  # Default text format
                return Response(
                    {"content": report.content, "format": "text"},
                    status=status.HTTP_200_OK
                )
                
        except Report.DoesNotExist:
            return Response(
                {"error": "Report not found."},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def post(self, request, report_id):
        try:
            report = Report.objects.get(id=report_id)
            
            # Check if user has permission to access this report
            if request.user != report.user and not request.user.is_staff:
                return Response(
                    {"error": "You don't have permission to access this report."},
                    status=status.HTTP_403_FORBIDDEN
                )
                
            # Get requested format from post data
            data = request.data
            export_format = data.get('format', 'text')
            
            # Update report format
            report.report_format = export_format
            
            # Update report content if provided
            if 'content' in data:
                report.content = data['content']
                
            report.save()
            
            # Request report generation
            # In a real app, this would trigger a background task
            
            return Response(
                {"message": f"Report generation in {export_format} format started.", "report_id": report.id},
                status=status.HTTP_202_ACCEPTED
            )
                
        except Report.DoesNotExist:
            return Response(
                {"error": "Report not found."},
                status=status.HTTP_404_NOT_FOUND
            )


class BackupSystemAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        """Get list of backups."""
        backups = BackupRecord.objects.all().order_by('-backup_date')
        data = [
            {
                "id": backup.id,
                "filename": os.path.basename(backup.backup_file.name),
                "date": backup.backup_date,
                "size": backup.backup_size,
                "type": backup.backup_type,
                "created_by": backup.created_by.username if backup.created_by else None
            }
            for backup in backups
        ]
        
        return Response(data, status=status.HTTP_200_OK)
    
    def post(self, request):
        """Create a system backup."""
        backup_type = request.data.get('backup_type', 'full')
        
        # In a real application, this would be a background task
        try:
            # Example backup generation (simplified)
            timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f'backup_{timestamp}.zip'
            
            # Create a mock backup record
            backup_record = BackupRecord.objects.create(
                backup_file=f'backups/{backup_filename}',
                backup_size=1024 * 1024,  # Mock size of 1MB
                backup_type=backup_type,
                created_by=request.user
            )
            
            # Update system settings
            system_settings = System_Settings.objects.first()
            if system_settings:
                system_settings.last_backup = timezone.now()
                system_settings.save()
            
            return Response(
                {
                    "message": "Backup process started.",
                    "backup_id": backup_record.id,
                    "backup_type": backup_type
                },
                status=status.HTTP_202_ACCEPTED
            )
            
        except Exception as e:
            return Response(
                {"error": f"Backup failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RestoreBackupAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def get(self, request, backup_id):
        """Get backup details."""
        try:
            backup = BackupRecord.objects.get(id=backup_id)
            data = {
                "id": backup.id,
                "filename": os.path.basename(backup.backup_file.name),
                "date": backup.backup_date,
                "size": backup.backup_size,
                "type": backup.backup_type,
                "created_by": backup.created_by.username if backup.created_by else None
            }
            
            return Response(data, status=status.HTTP_200_OK)
            
        except BackupRecord.DoesNotExist:
            return Response(
                {"error": "Backup not found."},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def post(self, request, backup_id):
        """Restore system from a backup."""
        try:
            backup = BackupRecord.objects.get(id=backup_id)
            
            # Check confirmation
            if not request.data.get('confirm', False):
                return Response(
                    {"error": "Restoration requires explicit confirmation."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # In a real application, restoration would be a carefully implemented process
            # This is just a simplified mock implementation
            
            return Response(
                {
                    "message": "System restoration process started.",
                    "backup_id": backup.id
                },
                status=status.HTTP_202_ACCEPTED
            )
            
        except BackupRecord.DoesNotExist:
            return Response(
                {"error": "Backup not found."},
                status=status.HTTP_404_NOT_FOUND
            )


class SecurityIntegrationsAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        """Get list of security integrations."""
        # Mock data for integrations - in a real app, this would be stored in the database
        integrations = [
            {
                "id": 1,
                "name": "SIEM Integration",
                "type": "siem",
                "status": "active",
                "last_sync": timezone.now() - datetime.timedelta(hours=1)
            },
            {
                "id": 2,
                "name": "Firewall Integration",
                "type": "firewall",
                "status": "inactive",
                "last_sync": None
            },
            {
                "id": 3,
                "name": "Threat Intelligence Feed",
                "type": "threat_intel",
                "status": "active",
                "last_sync": timezone.now() - datetime.timedelta(days=1)
            }
        ]
        
        return Response(integrations, status=status.HTTP_200_OK)
    
    def post(self, request):
        """Create or update security integration."""
        data = request.data
        integration_type = data.get('type')
        
        if not integration_type:
            return Response(
                {"error": "Integration type is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Mock implementation - in a real app, this would create or update an integration
        # with a third-party security system
        
        return Response(
            {
                "message": f"{integration_type.capitalize()} integration set up successfully.",
                "integration_id": random.randint(1, 100)  # Mock ID
            },
            status=status.HTTP_201_CREATED
        )
    
    def delete(self, request):
        """Remove security integration."""
        integration_id = request.data.get('integration_id')
        
        if not integration_id:
            return Response(
                {"error": "Integration ID is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Mock implementation - in a real app, this would disable the integration
        
        return Response(
            {"message": "Integration removed successfully."},
            status=status.HTTP_200_OK
        )


class NetworkAnalysisView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Get time range from query params (default to last 24 hours)
            hours = int(request.query_params.get('hours', 24))
            time_threshold = timezone.now() - timedelta(hours=hours)

            # Get basic statistics
            total_flows = NetworkFlow.objects.filter(created_at__gte=time_threshold).count()
            total_bytes = NetworkFlow.objects.filter(created_at__gte=time_threshold).aggregate(
                total=Sum('total_bytes')
            )['total'] or 0

            # Get threat distribution
            threat_distribution = NetworkFlow.objects.filter(
                created_at__gte=time_threshold
            ).values('threat_level').annotate(
                count=Count('id')
            )

            # Get top source IPs by threat level
            top_sources = NetworkFlow.objects.filter(
                created_at__gte=time_threshold,
                threat_level='high'
            ).values('src_ip').annotate(
                count=Count('id'),
                total_bytes=Sum('total_bytes')
            ).order_by('-count')[:10]

            # Get protocol distribution
            protocol_distribution = NetworkFlow.objects.filter(
                created_at__gte=time_threshold
            ).values('protocol').annotate(
                count=Count('id')
            )

            # Get recent alerts
            recent_alerts = Alert.objects.filter(
                created_at__gte=time_threshold
            ).order_by('-created_at')[:10]

            response_data = {
                'time_range': f'Last {hours} hours',
                'total_flows': total_flows,
                'total_bytes': total_bytes,
                'threat_distribution': list(threat_distribution),
                'top_sources': list(top_sources),
                'protocol_distribution': list(protocol_distribution),
                'recent_alerts': AlertSerializer(recent_alerts, many=True).data
            }

            return Response(response_data)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ThreatAnalysisView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Get time range from query params
            hours = int(request.query_params.get('hours', 24))
            time_threshold = timezone.now() - timedelta(hours=hours)

            # Get threat categories distribution
            threat_categories = Threat.objects.filter(
                created_at__gte=time_threshold
            ).values('category').annotate(
                count=Count('id'),
                avg_confidence=Avg('confidence')
            )

            # Get threat trends over time
            threat_trends = Threat.objects.filter(
                created_at__gte=time_threshold
            ).extra(
                select={'hour': 'EXTRACT(hour from created_at)'}
            ).values('hour', 'category').annotate(
                count=Count('id')
            ).order_by('hour', 'category')

            # Get high confidence threats
            high_confidence_threats = Threat.objects.filter(
                created_at__gte=time_threshold,
                confidence__gte=0.8
            ).order_by('-confidence')[:10]

            response_data = {
                'threat_categories': list(threat_categories),
                'threat_trends': list(threat_trends),
                'high_confidence_threats': ThreatSerializer(high_confidence_threats, many=True).data
            }

            return Response(response_data)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(ensure_csrf_cookie, name='dispatch')
class GetCSRFToken(View):
    def get(self, request):
        return JsonResponse({'detail': 'CSRF cookie set'})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_network_activity_logs(request):
    """
    Get network activity logs with filtering and pagination
    """
    try:
        # Get query parameters
        search = request.query_params.get('search', '')
        event_type = request.query_params.get('event_type', '')
        severity = request.query_params.get('severity', '')
        start_date = request.query_params.get('start_date', '')
        end_date = request.query_params.get('end_date', '')
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 10))

        # Base queryset
        queryset = NetworkFlow.objects.all()

        # Apply filters
        if search:
            queryset = queryset.filter(
                Q(src_ip__icontains=search) |
                Q(dst_ip__icontains=search) |
                Q(threat_details__icontains=search)
            )

        if event_type:
            queryset = queryset.filter(threat_details__contains={'predicted_label': event_type})

        if severity:
            queryset = queryset.filter(threat_level=severity)

        if start_date:
            start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
            queryset = queryset.filter(created_at__gte=start_datetime)

        if end_date:
            end_datetime = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            queryset = queryset.filter(created_at__lt=end_datetime)

        # Order by created_at descending
        queryset = queryset.order_by('-created_at')

        # Calculate pagination
        total_count = queryset.count()
        start_index = (page - 1) * page_size
        end_index = start_index + page_size

        # Get paginated data
        paginated_queryset = queryset[start_index:end_index]

        # Prepare response data
        logs = []
        for flow in paginated_queryset:
            # Get related alerts
            alerts = Alert.objects.filter(flow=flow)
            alert_details = []
            for alert in alerts:
                alert_details.append({
                    'description': alert.description,
                    'severity': alert.severity,
                    'threat_type': alert.threat_type
                })

            log_entry = {
                'id': flow.id,
                'date': flow.created_at.strftime('%Y-%m-%d'),
                'time': flow.created_at.strftime('%I:%M %p'),
                'event': flow.threat_details.get('predicted_label', 'Unknown Event'),
                'severity': flow.threat_level,
                'source_ip': flow.src_ip,
                'destination_ip': flow.dst_ip,
                'protocol': flow.protocol,
                'details': flow.threat_details.get('protocol_analysis', {}),
                'alerts': alert_details,
                'flow_metrics': flow.threat_details.get('flow_metrics', {})
            }
            logs.append(log_entry)

        response_data = {
            'logs': logs,
            'pagination': {
                'total_count': total_count,
                'page': page,
                'page_size': page_size,
                'total_pages': (total_count + page_size - 1) // page_size
            }
        }

        return Response(response_data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def export_network_activity_logs(request):
    try:
        # Get query parameters
        search = request.GET.get('search', '')
        event_type = request.GET.get('event_type', '')
        severity = request.GET.get('severity', '')

        # Get the queryset
        queryset = NetworkFlow.objects.all().order_by('-start_time')

        # Apply filters
        if search:
            queryset = queryset.filter(
                Q(src_ip__icontains=search) |
                Q(dst_ip__icontains=search) |
                Q(protocol__icontains=search) |
                Q(threat_level__icontains=search)
            )
        if event_type:
            queryset = queryset.filter(threat_level=event_type)
        if severity:
            queryset = queryset.filter(threat_level=severity)

        # Create the HttpResponse object with CSV header
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="network-logs-{datetime.now().strftime("%Y-%m-%d")}.csv"'

        # Create CSV writer
        writer = csv.writer(response)
        
        # Write header
        writer.writerow([
            'Timestamp',
            'Source IP',
            'Destination IP',
            'Protocol',
            'Threat Level',
            'Flow Duration',
            'Total Packets',
            'Total Bytes',
            'Details'
        ])

        for flow in queryset:
            writer.writerow([
                flow.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                flow.src_ip,
                flow.dst_ip,
                flow.protocol,
                flow.threat_level,
                flow.duration,
                flow.packet_count,
                flow.total_bytes,
                flow.threat_details
            ])

        return response

    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def export_reports(request):
    try:
        # Get selected report IDs from request
        report_ids = request.data.get('reportIds', [])
        
        if not report_ids:
            return HttpResponse(
                json.dumps({'error': 'No reports selected for export'}),
                status=400,
                content_type='application/json'
            )
        
        # Get reports from database
        reports = Report.objects.filter(id__in=report_ids)
        
        if not reports.exists():
            return HttpResponse(
                json.dumps({'error': 'No reports found'}),
                status=404,
                content_type='application/json'
            )
        
        # Format reports data
        export_data = []
        for report in reports:
            # Handle content field which might be a string or a dictionary
            content = report.content
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except json.JSONDecodeError:
                    content = {'raw_content': content}
            
            report_data = {
                'id': report.id,
                'threat_type': report.alert.threat_type if report.alert else 'Unknown',
                'target_device': report.threat.target_device if report.threat else 'Unknown',
                'attack_source': report.threat.source_ip if report.threat else 'Unknown',
                'threat_status': report.report_status,
                'severity_level': report.alert.severity if report.alert else 'Unknown',
                'created_at': report.created_at.isoformat(),
                'content': content.get('raw_content', '') if isinstance(content, dict) else str(content),
                'user': report.user.username if report.user else 'Unknown'
            }
            export_data.append(report_data)
        
        # Create response with JSON data
        response = HttpResponse(
            json.dumps(export_data, indent=2),
            content_type='application/json'
        )
        response['Content-Disposition'] = 'attachment; filename="reports_export.json"'
        
        return response
        
    except Exception as e:
        return HttpResponse(
            json.dumps({'error': str(e)}),
            status=500,
            content_type='application/json'
        )


class ReportDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            report = Report.objects.get(id=report_id)
            serializer = ReportSerializer(report)
            return Response(serializer.data)
        except Report.DoesNotExist:
            return Response(
                {'error': 'Report not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request, report_id):
        try:
            report = Report.objects.get(id=report_id)
            serializer = ReportSerializer(report, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Report.DoesNotExist:
            return Response(
                {'error': 'Report not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    def delete(self, request, report_id):
        try:
            report = Report.objects.get(id=report_id)
            report.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Report.DoesNotExist:
            return Response(
                {'error': 'Report not found'},
                status=status.HTTP_404_NOT_FOUND
            )

