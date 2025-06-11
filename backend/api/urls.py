from django.urls import path
from .views import (
    CheckSystemHealthView,
    CreateProfilesView,
    LoginAPIView,
    SignupAPIView,
    ForgetPasswordAPIView,
    ResetPasswordAPIView,
    ProtectedAPIView,
    SystemManagementView,
    AddAgentView,
    UpdateProfileImageView,
    CustomLogoutView,
    MarkNotificationAsReadView,
    MarkAllNotificationsAsReadView,
    EventDetailsView,
    ReportsView,
    UserManagementView,
    SettingsView,
    AlertAPIView,
    ThreatAPIView,
    SuspiciousIPAPIView,
    HelpSupportView,
    ActivityView,
    NotificationView,
    ChangePasswordAPIView,
    UpdateProfileAPIView,
    VerifyEmailAPIView,
    ExportReportAPIView,
    BackupSystemAPIView,
    RestoreBackupAPIView,
    SecurityIntegrationsAPIView,
    NetworkAnalysisView,
    ThreatAnalysisView,
    GetCSRFToken,
    get_network_activity_logs,
    export_network_activity_logs,
    ReportDetailView,
    export_reports,
)
from .report_views import delete_reports
from .settings_views import (
    UserSettingsView,
    SystemSettingsView,
    SecuritySettingsView,
    NotificationSettingsView,
)
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .dashboard_views import DashboardView, DataAnalysisView
from .user_views import UserListView, UserDetailView, PermissionGroupListView, PermissionGroupDetailView

urlpatterns = [
    # Authentication paths
    path('create_profiles/', CreateProfilesView.as_view(), name='create_profiles'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('signup/', SignupAPIView.as_view(), name='signup'),
    path('forget_password/', ForgetPasswordAPIView.as_view(), name='forget_password'),
    path('reset_password/<str:uidb64>/<str:token>/', ResetPasswordAPIView.as_view(), name='reset_password'),
    path('logout/', CustomLogoutView.as_view(), name='api_logout'),
    
    # New authentication paths
    path('change_password/', ChangePasswordAPIView.as_view(), name='api_change_password'),
    path('verify_email/<str:token>/', VerifyEmailAPIView.as_view(), name='verify_email'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Protected paths
    path('protected/', ProtectedAPIView.as_view(), name='protected'),
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path('data-analysis/', DataAnalysisView.as_view(), name='data_analysis'),
    path('network-analysis/', NetworkAnalysisView.as_view(), name='network_analysis'),
    path('alerts/', AlertAPIView.as_view(), name='alerts'),
    path('alerts/<int:pk>/', AlertAPIView.as_view(), name='alert_detail'),
    path('threats/', ThreatAPIView.as_view(), name='threats'),
    path('threats/<int:pk>/', ThreatAPIView.as_view(), name='threat_detail'),
    path('suspicious-ips/', SuspiciousIPAPIView.as_view(), name='suspicious_ips'),
    path('suspicious-ips/<int:pk>/', SuspiciousIPAPIView.as_view(), name='suspicious_ip_detail'),
    path('reports/', ReportsView.as_view(), name='reports'),
    path('reports/<int:report_id>/', ReportDetailView.as_view(), name='report-detail'),
    path('reports/export/', export_reports, name='export-reports'),
    path('reports/delete/', delete_reports, name='delete-reports'),
    
    # Settings paths
    path('settings/user/', UserSettingsView.as_view(), name='user_settings'),
    path('settings/system/', SystemSettingsView.as_view(), name='system_settings'),
    path('settings/security/', SecuritySettingsView.as_view(), name='security_settings'),
    path('settings/notifications/', NotificationSettingsView.as_view(), name='notification_settings'),
    
    # User Management paths
    path('users/', UserListView.as_view(), name='user-list'),
    path('users/<int:user_id>/', UserDetailView.as_view(), name='user-detail'),
    path('permission-groups/', PermissionGroupListView.as_view(), name='permission-group-list'),
    path('permission-groups/<int:group_id>/', PermissionGroupDetailView.as_view(), name='permission-group-detail'),
    
    path('notifications/', NotificationView.as_view(), name='notifications'),
    path('notifications/<int:notification_id>/read/', MarkNotificationAsReadView.as_view(), name='mark_notification_read'),
    path('notifications/mark-all-read/', MarkAllNotificationsAsReadView.as_view(), name='mark_all_notifications_read'),
    path('events/', EventDetailsView.as_view(), name='events'),
    path('help-support/', HelpSupportView.as_view(), name='help_support'),
    path('activity/', ActivityView.as_view(), name='activity'),
    path('update-profile/', UpdateProfileAPIView.as_view(), name='update_profile'),
    path('update-profile-image/', UpdateProfileImageView.as_view(), name='update_profile_image'),
    path('export-report/<int:report_id>/', ExportReportAPIView.as_view(), name='export_report'),
    path('backup/', BackupSystemAPIView.as_view(), name='backup'),
    path('restore/<int:backup_id>/', RestoreBackupAPIView.as_view(), name='restore'),
    path('security-integrations/', SecurityIntegrationsAPIView.as_view(), name='security_integrations'),
    path('threat-analysis/', ThreatAnalysisView.as_view(), name='threat_analysis'),
    path('get-csrf-token/', GetCSRFToken.as_view(), name='get_csrf_token'),
    path('event-details/', EventDetailsView.as_view(), name='event-details'),
    path('network-activity-logs/', get_network_activity_logs, name='network-activity-logs'),
    path('network-activity-logs/export/', export_network_activity_logs, name='export-network-activity-logs'),
]
