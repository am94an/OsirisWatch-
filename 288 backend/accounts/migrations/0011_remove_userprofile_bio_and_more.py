# Generated by Django 5.1.5 on 2025-04-22 02:49

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0010_remove_userprofile_notifications_agent_is_active_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='bio',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='is_email_verified',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='last_password_change',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='phone_number',
        ),
    ]
