# Generated by Django 5.1.5 on 2025-04-22 02:45

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0009_alert_attack_type_networkflow_agent_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='notifications',
        ),
        migrations.AddField(
            model_name='agent',
            name='is_active',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='agent',
            name='last_activity',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AddField(
            model_name='agent',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='agents', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='alert',
            name='is_processed',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='attacktype',
            name='severity_level',
            field=models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], default='medium', max_length=20),
        ),
        migrations.AddField(
            model_name='log',
            name='details',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='log',
            name='ip_address',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='log',
            name='module',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='notification',
            name='priority',
            field=models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], default='medium', max_length=20),
        ),
        migrations.AddField(
            model_name='report',
            name='report_file',
            field=models.FileField(blank=True, null=True, upload_to='reports/'),
        ),
        migrations.AddField(
            model_name='report',
            name='report_format',
            field=models.CharField(choices=[('text', 'Text'), ('pdf', 'PDF'), ('csv', 'CSV')], default='text', max_length=10),
        ),
        migrations.AddField(
            model_name='suspiciousip',
            name='block_status',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='suspiciousip',
            name='reviewed',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='suspiciousip',
            name='reviewed_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='reviewed_ips', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='system_settings',
            name='backup_settings',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='system_settings',
            name='last_backup',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='system_settings',
            name='security_policy',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='threat',
            name='is_resolved',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='threat',
            name='resolution_details',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='threat',
            name='resolved_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='threat',
            name='resolved_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='resolved_threats', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='userlogin',
            name='device_info',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userlogin',
            name='ip_address',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userlogin',
            name='login_status',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='bio',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='is_email_verified',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='last_password_change',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='userprofile',
            name='phone_number',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
        migrations.AlterField(
            model_name='notification',
            name='alert',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='alert_notifications', to='accounts.alert'),
        ),
        migrations.AlterField(
            model_name='notification',
            name='threat',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='threat_notifications', to='accounts.threat'),
        ),
        migrations.AlterField(
            model_name='notification',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notifications', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='report',
            name='alert',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='alert_reports', to='accounts.alert'),
        ),
        migrations.AlterField(
            model_name='report',
            name='threat',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='threat_reports', to='accounts.threat'),
        ),
        migrations.AlterField(
            model_name='report',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reports', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='userlogin',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_logins', to=settings.AUTH_USER_MODEL),
        ),
        migrations.CreateModel(
            name='BackupRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('backup_file', models.FileField(upload_to='backups/')),
                ('backup_date', models.DateTimeField(auto_now_add=True)),
                ('backup_size', models.BigIntegerField()),
                ('backup_type', models.CharField(choices=[('full', 'Full'), ('incremental', 'Incremental'), ('differential', 'Differential')], default='full', max_length=20)),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='backups', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='EmailVerification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField()),
                ('verified', models.BooleanField(default=False)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='email_verifications', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
