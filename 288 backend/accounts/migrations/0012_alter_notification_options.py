# Generated by Django 5.1.5 on 2025-04-22 03:05

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0011_remove_userprofile_bio_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='notification',
            options={'ordering': ['-sent_at']},
        ),
    ]
