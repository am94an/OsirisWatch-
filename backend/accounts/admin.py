from django.contrib import admin
from predictions.models import NetworkSession
from .models import *

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'permission_group')
    list_filter = ('role', 'permission_group')
    search_fields = ('user__username', 'user__email')

class PermissionGroupAdmin(admin.ModelAdmin):
    list_display = ('name', 'description')
    search_fields = ('name', 'description')
    fieldsets = (
        ('معلومات أساسية', {
            'fields': ('name', 'description')
        }),
        ('صلاحيات لوحة القيادة', {
            'fields': ('can_view_dashboard',)
        }),
        ('صلاحيات المستخدمين', {
            'fields': ('can_view_users', 'can_add_users', 'can_edit_users', 'can_delete_users')
        }),
        ('صلاحيات التقارير', {
            'fields': ('can_view_reports', 'can_add_reports', 'can_edit_reports', 'can_delete_reports')
        }),
        ('صلاحيات التهديدات', {
            'fields': ('can_view_threats', 'can_add_threats', 'can_edit_threats', 'can_delete_threats')
        }),
        ('صلاحيات الإشعارات', {
            'fields': ('can_view_notifications', 'can_manage_notifications')
        }),
    )

admin.site.register(UserProfile, UserProfileAdmin)
admin.site.register(PermissionGroup, PermissionGroupAdmin)
admin.site.register(NetworkFlow)
admin.site.register(Alert)
admin.site.register(Threat)
admin.site.register(Log)
admin.site.register(Notification)
admin.site.register(Report)
admin.site.register(NetworkSession)
admin.site.register(SuspiciousIP)
admin.site.register(UserLogin)
admin.site.register(AttackType)
admin.site.register(Agent)
