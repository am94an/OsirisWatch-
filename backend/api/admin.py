from django.contrib import admin
from .models import Threat, NetworkFlow, SuspiciousIP, UserLogin, Agent, AttackType, Alert, Notification, Report, System_Settings

class AlertAdmin(admin.ModelAdmin):
    list_display = ('id', 'threat_type', 'severity', 'status', 'created_at')
    list_filter = ('severity', 'status', 'threat_type')
    search_fields = ('threat_type', 'description')
    date_hierarchy = 'created_at'

class ThreatAdmin(admin.ModelAdmin):
    list_display = ('id', 'category', 'confidence', 'created_at')
    list_filter = ('category', 'confidence')
    search_fields = ('category', 'description')
    date_hierarchy = 'created_at'

class NetworkFlowAdmin(admin.ModelAdmin):
    list_display = ('id', 'src_ip', 'dst_ip', 'protocol', 'threat_level', 'created_at')
    list_filter = ('protocol', 'threat_level')
    search_fields = ('src_ip', 'dst_ip')
    date_hierarchy = 'created_at'

class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = ('id', 'ip_address', 'date')
    list_filter = ('date',)
    search_fields = ('ip_address', 'reason')
    date_hierarchy = 'date'

class UserLoginAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'timestamp')
    list_filter = ('timestamp',)
    search_fields = ('user__username',)
    date_hierarchy = 'timestamp'

class AgentAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')
    search_fields = ('name', 'description')

class AttackTypeAdmin(admin.ModelAdmin):
    list_display = ('id', 'type')
    search_fields = ('type', 'description')

class NotificationAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'notification_type', 'is_read', 'sent_at')
    list_filter = ('notification_type', 'is_read', 'sent_at')
    search_fields = ('user__username', 'message')
    date_hierarchy = 'sent_at'

class ReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'report_status', 'created_at')
    list_filter = ('report_status', 'created_at')
    search_fields = ('user__username', 'content')
    date_hierarchy = 'created_at'

class SystemSettingsAdmin(admin.ModelAdmin):
    list_display = ('id', 'system_name', 'version', 'maintenance_mode')
    list_filter = ('maintenance_mode',)

# Register models with custom admin classes
admin.site.register(Alert, AlertAdmin)
admin.site.register(Threat, ThreatAdmin)
admin.site.register(NetworkFlow, NetworkFlowAdmin)
admin.site.register(SuspiciousIP, SuspiciousIPAdmin)
admin.site.register(UserLogin, UserLoginAdmin)
admin.site.register(Agent, AgentAdmin)
admin.site.register(AttackType, AttackTypeAdmin)
admin.site.register(Notification, NotificationAdmin)
admin.site.register(Report, ReportAdmin)
admin.site.register(System_Settings, SystemSettingsAdmin)
