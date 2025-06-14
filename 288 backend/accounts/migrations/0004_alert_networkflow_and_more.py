# Generated by Django 5.1.2 on 2024-10-25 18:00

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_alter_notification_user'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('alert_type', models.CharField(max_length=50)),
                ('severity', models.CharField(max_length=20)),
                ('description', models.TextField()),
                ('alert_time', models.DateTimeField()),
            ],
        ),
        migrations.CreateModel(
            name='NetworkFlow',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source_ip', models.GenericIPAddressField()),
                ('destination_ip', models.GenericIPAddressField()),
                ('source_port', models.IntegerField()),
                ('destination_port', models.IntegerField()),
                ('protocol', models.CharField(max_length=10)),
                ('timestamp', models.DateTimeField()),
                ('duration', models.DurationField()),
                ('packet_count', models.IntegerField()),
                ('byte_count', models.IntegerField()),
                ('label', models.CharField(choices=[('normal', 'Normal'), ('anomalous', 'Anomalous')], max_length=20)),
            ],
        ),
        migrations.RenameField(
            model_name='notification',
            old_name='created_at',
            new_name='sent_at',
        ),
        migrations.AddField(
            model_name='notification',
            name='notification_type',
            field=models.CharField(blank=True, choices=[('email', 'Email'), ('sms', 'SMS'), ('push', 'Push Notification')], max_length=20, null=True),
        ),
        migrations.AlterField(
            model_name='notification',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notifications', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='notification',
            name='alert',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='notifications', to='accounts.alert'),
        ),
        migrations.CreateModel(
            name='Log',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(max_length=255)),
                ('action_time', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='logs', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='alert',
            name='flow',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='alerts', to='accounts.networkflow'),
        ),
        migrations.CreateModel(
            name='Threat',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('threat_name', models.CharField(max_length=50)),
                ('threat_level', models.CharField(max_length=20)),
                ('threat_source', models.CharField(max_length=50)),
                ('response_action', models.TextField()),
                ('alert', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='threat', to='accounts.alert')),
            ],
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('content', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('report_status', models.CharField(choices=[('open', 'Open'), ('closed', 'Closed'), ('review', 'In Review')], max_length=20)),
                ('alert', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reports', to='accounts.alert')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reports', to=settings.AUTH_USER_MODEL)),
                ('threat', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='reports', to='accounts.threat')),
            ],
        ),
    ]
