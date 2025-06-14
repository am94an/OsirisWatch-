# Generated by Django 5.1.4 on 2025-01-26 03:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('predictions', '0005_rename_label_networksession_label_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='networksession',
            name='dst_ip',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='networksession',
            name='dst_port',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='networksession',
            name='flow_end_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='networksession',
            name='flow_id',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='networksession',
            name='flow_start_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='networksession',
            name='protocol_name',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='networksession',
            name='src_ip',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='networksession',
            name='src_port',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='networksession',
            name='total_bytes',
            field=models.BigIntegerField(blank=True, null=True),
        ),
    ]
