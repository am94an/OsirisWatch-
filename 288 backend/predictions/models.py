from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from api.models import Alert, Threat, SuspiciousIP
import pandas as pd
import os
import json

class NetworkSession(models.Model):
    protocol = models.IntegerField(default=0)
    flow_duration = models.FloatField(default=0)
    total_fwd_packets = models.IntegerField(default=0)
    total_bwd_packets = models.IntegerField(default=0)
    fwd_packets_length_total = models.FloatField(default=0)
    bwd_packets_length_total = models.FloatField(default=0)
    fwd_packet_length_max = models.FloatField(default=0)
    fwd_packet_length_min = models.FloatField(default=0)
    fwd_packet_length_mean = models.FloatField(default=0)
    fwd_packet_length_std = models.FloatField(default=0)
    bwd_packet_length_max = models.FloatField(default=0)
    bwd_packet_length_min = models.FloatField(default=0)
    bwd_packet_length_mean = models.FloatField(default=0)
    bwd_packet_length_std = models.FloatField(default=0)
    flow_bytes_per_s = models.FloatField(default=0)
    flow_packets_per_s = models.FloatField(default=0)
    flow_iat_mean = models.FloatField(default=0)
    flow_iat_std = models.FloatField(default=0)
    flow_iat_max = models.FloatField(default=0)
    flow_iat_min = models.FloatField(default=0)
    fwd_iat_total = models.FloatField(default=0)
    fwd_iat_mean = models.FloatField(default=0)
    fwd_iat_std = models.FloatField(default=0)
    fwd_iat_max = models.FloatField(default=0)
    fwd_iat_min = models.FloatField(default=0)
    bwd_iat_total = models.FloatField(default=0)
    bwd_iat_mean = models.FloatField(default=0)
    bwd_iat_std = models.FloatField(default=0)
    bwd_iat_max = models.FloatField(default=0)
    bwd_iat_min = models.FloatField(default=0)
    fwd_psh_flags = models.IntegerField(default=0)
    bwd_psh_flags = models.IntegerField(default=0)
    fwd_urg_flags = models.IntegerField(default=0)
    bwd_urg_flags = models.IntegerField(default=0)
    fwd_header_length = models.FloatField(default=0)
    bwd_header_length = models.FloatField(default=0)
    fwd_packets_per_s = models.FloatField(default=0)
    bwd_packets_per_s = models.FloatField(default=0)
    packet_length_min = models.FloatField(default=0)
    packet_length_max = models.FloatField(default=0)
    packet_length_mean = models.FloatField(default=0)
    packet_length_std = models.FloatField(default=0)
    packet_length_variance = models.FloatField(default=0)
    fin_flag_count = models.IntegerField(default=0)
    syn_flag_count = models.IntegerField(default=0)
    rst_flag_count = models.IntegerField(default=0)
    psh_flag_count = models.IntegerField(default=0)
    ack_flag_count = models.IntegerField(default=0)
    urg_flag_count = models.IntegerField(default=0)
    cwe_flag_count = models.IntegerField(default=0)
    ece_flag_count = models.IntegerField(default=0)
    down_up_ratio = models.FloatField(default=0)
    avg_packet_size = models.FloatField(default=0)
    avg_fwd_segment_size = models.FloatField(default=0)
    avg_bwd_segment_size = models.FloatField(default=0)
    fwd_avg_bytes_bulk = models.FloatField(default=0)
    fwd_avg_packets_bulk = models.FloatField(default=0)
    fwd_avg_bulk_rate = models.FloatField(default=0)
    bwd_avg_bytes_bulk = models.FloatField(default=0)
    bwd_avg_packets_bulk = models.FloatField(default=0)
    bwd_avg_bulk_rate = models.FloatField(default=0)
    subflow_fwd_packets = models.IntegerField(default=0)
    subflow_fwd_bytes = models.FloatField(default=0)
    subflow_bwd_packets = models.IntegerField(default=0)
    subflow_bwd_bytes = models.FloatField(default=0)
    init_fwd_win_bytes = models.FloatField(default=0)
    init_bwd_win_bytes = models.FloatField(default=0)
    fwd_act_data_packets = models.IntegerField(default=0)
    fwd_seg_size_min = models.FloatField(default=0)
    active_mean = models.FloatField(default=0)
    active_std = models.FloatField(default=0)
    active_max = models.FloatField(default=0)
    active_min = models.FloatField(default=0)
    idle_mean = models.FloatField(default=0)
    idle_std = models.FloatField(default=0)
    idle_max = models.FloatField(default=0)
    idle_min = models.FloatField(default=0)
    flow_id = models.CharField(max_length=100, null=True, blank=True)
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    src_port = models.IntegerField(null=True, blank=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)
    protocol_name = models.CharField(max_length=50, null=True, blank=True)
    flow_start_time = models.DateTimeField(null=True, blank=True)
    flow_end_time = models.DateTimeField(null=True, blank=True)
    total_bytes = models.BigIntegerField(null=True, blank=True)
    network_flow = models.ForeignKey('api.NetworkFlow', on_delete=models.SET_NULL, null=True, blank=True, related_name='sessions')

    label = models.CharField(max_length=20, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Session {self.id} - Protocol: {self.protocol} - {self.label}"

    def prepare_data(self):
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        SAVE_FOLDER = os.path.join(BASE_DIR, 'saved_model')
        feature_names_file_path = os.path.join(SAVE_FOLDER, 'feature_names.json')
        with open(feature_names_file_path, 'r') as f:
            feature_names = json.load(f)

        feature_to_field = {
            'Protocol': 'protocol',
            'Flow Duration': 'flow_duration',
            'Total Fwd Packets': 'total_fwd_packets',
            'Total Backward Packets': 'total_bwd_packets',
            'Fwd Packets Length Total': 'fwd_packets_length_total',
            'Bwd Packets Length Total': 'bwd_packets_length_total',
            'Fwd Packet Length Max': 'fwd_packet_length_max',
            'Fwd Packet Length Min': 'fwd_packet_length_min',
            'Fwd Packet Length Mean': 'fwd_packet_length_mean',
            'Fwd Packet Length Std': 'fwd_packet_length_std',
            'Bwd Packet Length Max': 'bwd_packet_length_max',
            'Bwd Packet Length Min': 'bwd_packet_length_min',
            'Bwd Packet Length Mean': 'bwd_packet_length_mean',
            'Bwd Packet Length Std': 'bwd_packet_length_std',
            'Flow Bytes/s': 'flow_bytes_per_s',
            'Flow Packets/s': 'flow_packets_per_s',
            'Flow IAT Mean': 'flow_iat_mean',
            'Flow IAT Std': 'flow_iat_std',
            'Flow IAT Max': 'flow_iat_max',
            'Flow IAT Min': 'flow_iat_min',
            'Fwd IAT Total': 'fwd_iat_total',
            'Fwd IAT Mean': 'fwd_iat_mean',
            'Fwd IAT Std': 'fwd_iat_std',
            'Fwd IAT Max': 'fwd_iat_max',
            'Fwd IAT Min': 'fwd_iat_min',
            'Bwd IAT Total': 'bwd_iat_total',
            'Bwd IAT Mean': 'bwd_iat_mean',
            'Bwd IAT Std': 'bwd_iat_std',
            'Bwd IAT Max': 'bwd_iat_max',
            'Bwd IAT Min': 'bwd_iat_min',
            'Fwd PSH Flags': 'fwd_psh_flags',
            'Bwd PSH Flags': 'bwd_psh_flags',
            'Fwd URG Flags': 'fwd_urg_flags',
            'Bwd URG Flags': 'bwd_urg_flags',
            'Fwd Header Length': 'fwd_header_length',
            'Bwd Header Length': 'bwd_header_length',
            'Fwd Packets/s': 'fwd_packets_per_s',
            'Bwd Packets/s': 'bwd_packets_per_s',
            'Packet Length Min': 'packet_length_min',
            'Packet Length Max': 'packet_length_max',
            'Packet Length Mean': 'packet_length_mean',
            'Packet Length Std': 'packet_length_std',
            'Packet Length Variance': 'packet_length_variance',
            'FIN Flag Count': 'fin_flag_count',
            'SYN Flag Count': 'syn_flag_count',
            'RST Flag Count': 'rst_flag_count',
            'PSH Flag Count': 'psh_flag_count',
            'ACK Flag Count': 'ack_flag_count',
            'URG Flag Count': 'urg_flag_count',
            'CWE Flag Count': 'cwe_flag_count',
            'ECE Flag Count': 'ece_flag_count',
            'Down/Up Ratio': 'down_up_ratio',
            'Avg Packet Size': 'avg_packet_size',
            'Avg Fwd Segment Size': 'avg_fwd_segment_size',
            'Avg Bwd Segment Size': 'avg_bwd_segment_size',
            'Fwd Avg Bytes/Bulk': 'fwd_avg_bytes_bulk',
            'Fwd Avg Packets/Bulk': 'fwd_avg_packets_bulk',
            'Fwd Avg Bulk Rate': 'fwd_avg_bulk_rate',
            'Bwd Avg Bytes/Bulk': 'bwd_avg_bytes_bulk',
            'Bwd Avg Packets/Bulk': 'bwd_avg_packets_bulk',
            'Bwd Avg Bulk Rate': 'bwd_avg_bulk_rate',
            'Subflow Fwd Packets': 'subflow_fwd_packets',
            'Subflow Fwd Bytes': 'subflow_fwd_bytes',
            'Subflow Bwd Packets': 'subflow_bwd_packets',
            'Subflow Bwd Bytes': 'subflow_bwd_bytes',
            'Init Fwd Win Bytes': 'init_fwd_win_bytes',
            'Init Bwd Win Bytes': 'init_bwd_win_bytes',
            'Fwd Act Data Packets': 'fwd_act_data_packets',
            'Fwd Seg Size Min': 'fwd_seg_size_min',
            'Active Mean': 'active_mean',
            'Active Std': 'active_std',
            'Active Max': 'active_max',
            'Active Min': 'active_min',
            'Idle Mean': 'idle_mean',
            'Idle Std': 'idle_std',
            'Idle Max': 'idle_max',
            'Idle Min': 'idle_min'
        }

        data_dict = {feature: [getattr(self, feature_to_field.get(feature))] for feature in feature_names}
        return pd.DataFrame(data_dict)

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