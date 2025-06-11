from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class PermissionGroup(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    
    # الصلاحيات للوحة القيادة
    can_view_dashboard = models.BooleanField(default=False)
    
    # صلاحيات إدارة المستخدمين
    can_view_users = models.BooleanField(default=False)
    can_add_users = models.BooleanField(default=False)
    can_edit_users = models.BooleanField(default=False)
    can_delete_users = models.BooleanField(default=False)
    
    # صلاحيات التقارير
    can_view_reports = models.BooleanField(default=False)
    can_add_reports = models.BooleanField(default=False)
    can_edit_reports = models.BooleanField(default=False)
    can_delete_reports = models.BooleanField(default=False)
    
    # صلاحيات التهديدات
    can_view_threats = models.BooleanField(default=False)
    can_add_threats = models.BooleanField(default=False)
    can_edit_threats = models.BooleanField(default=False)
    can_delete_threats = models.BooleanField(default=False)
    
    # صلاحيات الإشعارات
    can_view_notifications = models.BooleanField(default=False)
    can_manage_notifications = models.BooleanField(default=False)
    
    def __str__(self):
        return self.name

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(
        max_length=50,
        choices=[('User', 'User'), ('Admin', 'Admin'), ('Analyst', 'Analyst')],
        default='User'
    )
    permission_group = models.ForeignKey(PermissionGroup, on_delete=models.SET_NULL, null=True, blank=True)
    profile_image = models.ImageField(upload_to="profile_images/", default="profile_images/default.jpg")
    # Fields we're adding now
    bio = models.TextField(blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    is_email_verified = models.BooleanField(default=False)
    last_password_change = models.DateTimeField(auto_now_add=True)
    # Notification preferences
    notify_on_threats = models.BooleanField(default=True)
    notify_on_alerts = models.BooleanField(default=True)
    notify_on_reports = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"

# Create signals to automatically create/update user profile when a user is created/updated
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Signal to create a UserProfile whenever a User is created
    """
    if created:
        UserProfile.objects.get_or_create(user=instance)
        print(f"Created profile for user: {instance.username}")

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Signal to save UserProfile whenever a User is saved
    """
    try:
        # Check if profile exists, if not create it
        if not hasattr(instance, 'userprofile'):
            UserProfile.objects.create(user=instance)
            print(f"Created missing profile for existing user: {instance.username}")
        else:
            instance.userprofile.save()
            print(f"Updated profile for user: {instance.username}")
    except Exception as e:
        print(f"Error updating profile for {instance.username}: {str(e)}")
        # Create profile if it doesn't exist for any reason
        UserProfile.objects.get_or_create(user=instance)

class NetworkFlow(models.Model):
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.IntegerField()
    destination_port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    timestamp = models.DateTimeField()
    duration = models.DurationField()
    packet_count = models.IntegerField()
    byte_count = models.IntegerField()
    label = models.CharField(
        max_length=20,
        choices=[('normal', 'Normal'), ('anomalous', 'Anomalous')]
    )
    level = models.CharField(
        max_length=10,
        choices=[('high', 'High'), ('low', 'Low')],
        null=True,
        blank=True
    )
    agent = models.ForeignKey('Agent', on_delete=models.SET_NULL, null=True, blank=True, related_name='network_flows')

    def __str__(self):
        return f"Flow {self.id} from {self.source_ip} to {self.destination_ip}"

class Agent(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='account_agents')
    is_active = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Agent: {self.name}"

class AttackType(models.Model):
    type = models.CharField(max_length=50)
    description = models.TextField(null=True, blank=True)
    severity_level = models.CharField(
        max_length=20,
        choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')],
        default='medium'
    )

    def __str__(self):
        return f"Attack Type: {self.type}"

class Alert(models.Model):
    flow = models.ForeignKey(NetworkFlow, on_delete=models.CASCADE, related_name='alerts')
    alert_type = models.CharField(max_length=50)
    severity = models.CharField(max_length=20)
    description = models.TextField()
    alert_time = models.DateTimeField()
    attack_type = models.ForeignKey('AttackType', on_delete=models.SET_NULL, null=True, blank=True, related_name='alerts')
    is_processed = models.BooleanField(default=False)

    def __str__(self):
        return f"Alert {self.id}: {self.alert_type} - Severity: {self.severity}"

class Threat(models.Model):
    alert = models.OneToOneField(Alert, on_delete=models.CASCADE, related_name='threat')
    threat_name = models.CharField(max_length=50)
    threat_level = models.CharField(max_length=20)
    threat_source = models.CharField(max_length=50)
    response_action = models.TextField()
    date = models.DateField(auto_now_add=True)
    attack_type = models.ForeignKey('AttackType', on_delete=models.SET_NULL, null=True, blank=True, related_name='threats')
    is_resolved = models.BooleanField(default=False)
    resolution_details = models.TextField(blank=True, null=True)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_threats')
    resolved_at = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        # Automatically block the source IP if the threat level is high
        if self.threat_level == 'high' and self.alert:
            SuspiciousIP.objects.create(
                ip_address=self.alert.flow.source_ip,
                date=self.date,
                reason=f"Automatically blocked due to {self.threat_name} threat.",
                alert=self.alert,
                threat=self
            )
        # Automatically create a report when a threat is detected
        if not self.pk:  # Only on creation
            if self.alert.flow.agent and self.alert.flow.agent.user:
                Report.objects.create(
                    user=self.alert.flow.agent.user,
                    alert=self.alert,
                    threat=self,
                    content=f"Automatically generated report for {self.threat_name} threat.",
                    report_status='open'
                )
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Threat {self.id}: {self.threat_name} - Level: {self.threat_level}"

class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField()
    date = models.DateField()
    reason = models.TextField(null=True, blank=True)
    alert = models.ForeignKey('Alert', on_delete=models.SET_NULL, null=True, blank=True, related_name='suspicious_ips')
    threat = models.ForeignKey('Threat', on_delete=models.SET_NULL, null=True, blank=True, related_name='suspicious_ips')
    block_status = models.BooleanField(default=True)
    reviewed = models.BooleanField(default=False)
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_ips')

    def __str__(self):
        return f"Suspicious IP {self.ip_address} - Date: {self.date}"

class UserLogin(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_logins')
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_info = models.TextField(null=True, blank=True)
    login_status = models.BooleanField(default=True)  # True for successful, False for failed
    
    def __str__(self):
        return f"User {self.user.username} logged in at {self.timestamp}"

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    alert = models.ForeignKey('Alert', on_delete=models.CASCADE, related_name='alert_notifications', null=True, blank=True)
    threat = models.ForeignKey('Threat', on_delete=models.CASCADE, related_name='threat_notifications', null=True, blank=True)
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
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='alert_reports')
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE, related_name='threat_reports', null=True, blank=True)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    report_status = models.CharField(
        max_length=20,
        choices=[('open', 'Open'), ('closed', 'Closed'), ('review', 'In Review')]
    )
    report_format = models.CharField(
        max_length=10,
        choices=[('text', 'Text'), ('pdf', 'PDF'), ('csv', 'CSV')],
        default='text'
    )
    report_file = models.FileField(upload_to='reports/', null=True, blank=True)

    def __str__(self):
        return f"Report {self.id} by {self.user.username} - Status: {self.report_status}"

class System_Settings(models.Model):
    system_name = models.CharField(max_length=255)
    version = models.CharField(max_length=50)
    maintenance_mode = models.BooleanField(default=False)
    max_login_attempts = models.IntegerField(default=5)
    notification_settings = models.JSONField(default=dict)
    backup_settings = models.JSONField(default=dict)
    security_policy = models.TextField(blank=True, null=True)
    last_backup = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.system_name

class Log(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='logs')
    action = models.CharField(max_length=255)
    action_time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    module = models.CharField(max_length=100, null=True, blank=True)
    details = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"Log {self.id} - {self.user.username}: {self.action}"

class EmailVerification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_verifications')
    token = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    verified = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Email verification for {self.user.email}"

class BackupRecord(models.Model):
    backup_file = models.FileField(upload_to='backups/')
    backup_date = models.DateTimeField(auto_now_add=True)
    backup_size = models.BigIntegerField()
    backup_type = models.CharField(
        max_length=20,
        choices=[('full', 'Full'), ('incremental', 'Incremental'), ('differential', 'Differential')],
        default='full'
    )
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='backups')
    
    def __str__(self):
        return f"Backup from {self.backup_date}"
