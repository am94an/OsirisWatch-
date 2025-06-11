from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import NetworkSession
from api.models import Alert, Threat, SuspiciousIP

@receiver(post_save, sender=NetworkSession)
def update_related_tables(sender, instance, created, **kwargs):
    if created and instance.network_flow:
        alert, created_alert = Alert.objects.get_or_create(
            flow=instance.network_flow,
            defaults={
                "alert_type": "New Session Alert",
                "severity": "medium",
                "description": "Automatically generated alert for new network session.",
                "alert_time": instance.created_at
            }
        )
        
        if created_alert:
            Threat.objects.create(
                alert=alert,
                threat_name="New Session Threat",
                threat_level="low",
                threat_source="System",
                response_action="Monitor",
                attack_type=None
            )
        
        if instance.label == 'high':
            SuspiciousIP.objects.create(
                ip_address=instance.src_ip,
                date=instance.created_at.date(),
                reason="Automatically added due to high-level threat in network session.",
                alert=alert,
                threat=alert.threat
            )