from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User

class NetworkFlow(models.Model):
    THREAT_LEVEL_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High')
    ]

    flow_id = models.CharField(max_length=255, unique=True)
    src_ip = models.GenericIPAddressField()
    src_port = models.IntegerField()
    dst_ip = models.GenericIPAddressField()
    dst_port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField(null=True, blank=True)
    packet_count = models.IntegerField()
    total_bytes = models.BigIntegerField()
    duration = models.FloatField(null=True, blank=True)
    avg_packet_size = models.FloatField(null=True, blank=True)
    std_packet_size = models.FloatField(null=True, blank=True)
    min_packet_size = models.IntegerField(null=True, blank=True)
    max_packet_size = models.IntegerField(null=True, blank=True)
    bytes_per_second = models.FloatField(null=True, blank=True)
    packets_per_second = models.FloatField(null=True, blank=True)
    threat_level = models.CharField(max_length=10, choices=THREAT_LEVEL_CHOICES, default='low')
    threat_details = models.JSONField(default=list)
    anomalies = models.JSONField(default=list)
    protocol_analysis = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['src_ip', 'dst_ip']),
            models.Index(fields=['threat_level']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.flow_id} - {self.threat_level}"

    @classmethod
    def create_or_update(cls, flow_id, **kwargs):
        """
        Create a new network flow or update an existing one if flow_id already exists
        """
        try:
            # Try to get existing flow
            flow = cls.objects.get(flow_id=flow_id)
            # Update fields
            for key, value in kwargs.items():
                setattr(flow, key, value)
            flow.save()
            return flow
        except cls.DoesNotExist:
            # Create new flow if it doesn't exist
            return cls.objects.create(flow_id=flow_id, **kwargs)

class Alert(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ]

    STATUS_CHOICES = [
        ('new', 'New'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive')
    ]

    flow = models.ForeignKey(NetworkFlow, on_delete=models.CASCADE, related_name='alerts')
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    description = models.TextField()
    threat_type = models.CharField(max_length=100)
    source = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"Alert {self.id} - {self.threat_type}"

class Threat(models.Model):
    CATEGORY_CHOICES = [
        ('scan', 'Port Scan'),
        ('dos', 'Denial of Service'),
        ('brute_force', 'Brute Force'),
        ('malware', 'Malware'),
        ('suspicious', 'Suspicious Activity'),
        ('other', 'Other')
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('resolved', 'Resolved'),
        ('investigating', 'Investigating'),
        ('false_positive', 'False Positive')
    ]

    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ]

    flow = models.ForeignKey(NetworkFlow, on_delete=models.CASCADE, related_name='flow_threats')
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    threat_type = models.CharField(max_length=100, null=True, blank=True)
    target_device = models.CharField(max_length=100, null=True, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='high')
    description = models.TextField()
    confidence = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['category']),
            models.Index(fields=['confidence']),
            models.Index(fields=['created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['severity']),
        ]

    def __str__(self):
        return f"Threat {self.id} - {self.category}"

class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField()
    date = models.DateField()
    reason = models.TextField(null=True, blank=True)
    alert = models.ForeignKey('Alert', on_delete=models.SET_NULL, null=True, blank=True, related_name='suspicious_ips')  # New field
    threat = models.ForeignKey('Threat', on_delete=models.SET_NULL, null=True, blank=True, related_name='suspicious_ips')  # New field

    def __str__(self):
        return f"Suspicious IP {self.ip_address} - Date: {self.date}"

class UserLogin(models.Model):
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE, related_name='api_userlogins')
    timestamp = models.DateTimeField(auto_now_add=True)
    # Fields we'll add after migrations
    # ip_address = models.GenericIPAddressField(null=True, blank=True)
    # device_info = models.TextField(null=True, blank=True)
    # login_status = models.BooleanField(default=True)  # True for successful, False for failed

    def __str__(self):
        return f"User {self.user.username} logged in at {self.timestamp}"

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_notifications')
    alert = models.ForeignKey('Alert', on_delete=models.CASCADE, related_name='api_alert_notifications', null=True, blank=True)
    threat = models.ForeignKey('Threat', on_delete=models.CASCADE, related_name='api_threat_notifications', null=True, blank=True)
    message = models.TextField()
    notification_type = models.CharField(
        max_length=20,
        choices=[('email', 'Email'), ('sms', 'SMS'), ('push', 'Push Notification')],
        null=True,
        blank=True
    )
    is_read = models.BooleanField(default=False)
    sent_at = models.DateTimeField(auto_now_add=True)
    priority = models.CharField(
        max_length=20,
        choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')],
        default='medium'
    )

    def __str__(self):
        return f"Notification {self.id} for {self.user.username} - Type: {self.notification_type}"

    class Meta:
        ordering = ['-sent_at']

class Report(models.Model):
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE, related_name='api_reports')
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='api_alert_reports')
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE, related_name='api_threat_reports', null=True, blank=True)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    report_status = models.CharField(
        max_length=20,
        choices=[('open', 'Open'), ('closed', 'Closed'), ('review', 'In Review')]
    )

    def __str__(self):
        return f"Report {self.id} by {self.user.username} - Status: {self.report_status}"

class AttackType(models.Model):
    type = models.CharField(max_length=50)
    description = models.TextField(null=True, blank=True)
    alerts = models.ManyToManyField('Alert', related_name='attack_types', blank=True)
    threats = models.ManyToManyField('Threat', related_name='attack_types', blank=True)

    def __str__(self):
        return f"Attack Type: {self.type}"

class Agent(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    user = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='api_agents')
    is_active = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)
    network_flows = models.ManyToManyField('NetworkFlow', related_name='agents', blank=True)

    def __str__(self):
        return f"Agent: {self.name}"

class System_Settings(models.Model):
    system_name = models.CharField(max_length=100, default="Osiris Network Analysis System")
    version = models.CharField(max_length=20, default="1.0.0")
    maintenance_mode = models.BooleanField(default=False)
    max_login_attempts = models.IntegerField(default=5)
    notification_settings = models.JSONField(default=dict)
    
    def __str__(self):
        return self.system_name

class PermissionGroup(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    
    # Dashboard permissions
    can_view_dashboard = models.BooleanField(default=False)
    
    # Report permissions
    can_view_reports = models.BooleanField(default=False)
    can_edit_reports = models.BooleanField(default=False)
    can_delete_reports = models.BooleanField(default=False)
    
    # User management permissions
    can_view_users = models.BooleanField(default=False)
    can_edit_users = models.BooleanField(default=False)
    can_delete_users = models.BooleanField(default=False)
    
    # Settings permissions
    can_view_notifications = models.BooleanField(default=False)
    can_manage_notifications = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Permission Group'
        verbose_name_plural = 'Permission Groups'

@receiver(post_save, sender=Alert)
def create_alert_notification(sender, instance, created, **kwargs):
    if created:
        # Create notification for all users with appropriate permissions
        from django.contrib.auth.models import User
        from .models import Notification
        
        users = User.objects.filter(
            userprofile__role__in=['Admin', 'Analyst']
        )
        
        for user in users:
            Notification.objects.create(
                user=user,
                alert=instance,
                message=f"New {instance.severity} severity alert: {instance.description}",
                notification_type='push'
            )

@receiver(post_save, sender=Threat)
def create_threat_notification(sender, instance, created, **kwargs):
    if created:
        try:
            # Get users with Admin or Analyst role
            users = User.objects.filter(
                userprofile__role__in=['Admin', 'Analyst']
            ).select_related('userprofile')
            
            for user in users:
                Notification.objects.create(
                    user=user,
                    message=f"New threat detected: {instance.category}",
                    notification_type='push',
                    threat=instance
                )
                
                # Try to get the associated alert
                alert = instance.flow.alerts.first()
                
                if alert:
                    # Create a detailed report for each admin/analyst user
                    Report.objects.create(
                        user=user,
                        alert=alert,  # Use the found alert
                        threat=instance,
                        content=f"""Threat Report:
Threat Type: {instance.threat_type or instance.category}
Target Device: {instance.target_device or 'Unknown'}
Attack Source IP: {instance.source_ip or 'Unknown'}
Threat Status: {instance.status}
Severity Level: {instance.severity}
Category: {instance.category}
Description: {instance.description}
Confidence: {instance.confidence}
Created At: {instance.created_at}
Flow ID: {instance.flow.flow_id}
Protocol: {instance.flow.protocol}
Source Port: {instance.flow.src_port}
Destination Port: {instance.flow.dst_port}
Total Packets: {instance.flow.packet_count}
Total Bytes: {instance.flow.total_bytes}""",
                        report_status='open'
                    )
                else:
                    print(f"Warning: No alert found for threat {instance.id}. Report not created for user {user.username}.")
        except Exception as e:
            print(f"Error creating threat notification and report: {str(e)}")
