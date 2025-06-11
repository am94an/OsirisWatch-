import json
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.middleware import BaseMiddleware
from channels.auth import AuthMiddlewareStack
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from .models import NetworkSession
from .predict import predict_attack 
from channels.db import database_sync_to_async
from api.permissions import IsAdminOrAnalyst
from accounts.models import UserProfile

User = get_user_model()

class NetworkSessionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if not self.scope["user"].is_authenticated:
            await self.close()
            return
            
        # التحقق من الصلاحيات
        try:
            user_profile = await database_sync_to_async(UserProfile.objects.get)(user=self.scope["user"])
            if user_profile.role not in ['Admin', 'Analyst']:
                await self.close()
                return
        except:
            await self.close()
            return
            
        self.room_group_name = 'network_sessions_group'
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        
        protocol = data['Protocol']
        flow_duration = data['Flow Duration']
        total_fwd_packets = data['Total Fwd Packets']
        total_bwd_packets = data['Total Backward Packets']
        fwd_packets_length_total = data['Fwd Packets Length Total']
        bwd_packets_length_total = data['Bwd Packets Length Total']
        fwd_packet_length_max = data['Fwd Packet Length Max']
        fwd_packet_length_min = data['Fwd Packet Length Min']
        fwd_packet_length_mean = data['Fwd Packet Length Mean']
        fwd_packet_length_std = data['Fwd Packet Length Std']
        bwd_packet_length_max = data['Bwd Packet Length Max']
        bwd_packet_length_min = data['Bwd Packet Length Min']
        bwd_packet_length_mean = data['Bwd Packet Length Mean']
        bwd_packet_length_std = data['Bwd Packet Length Std']
        flow_bytes_per_second = data['Flow Bytes/s']
        flow_packets_per_second = data['Flow Packets/s']
        flow_iat_mean = data['Flow IAT Mean']
        flow_iat_std = data['Flow IAT Std']
        flow_iat_max = data['Flow IAT Max']
        flow_iat_min = data['Flow IAT Min']
        fwd_iat_total = data['Fwd IAT Total']
        fwd_iat_mean = data['Fwd IAT Mean']
        fwd_iat_std = data['Fwd IAT Std']
        fwd_iat_max = data['Fwd IAT Max']
        fwd_iat_min = data['Fwd IAT Min']
        bwd_iat_total = data['Bwd IAT Total']
        bwd_iat_mean = data['Bwd IAT Mean']
        bwd_iat_std = data['Bwd IAT Std']
        bwd_iat_max = data['Bwd IAT Max']
        bwd_iat_min = data['Bwd IAT Min']
        fwd_psh_flags = data['Fwd PSH Flags']
        bwd_psh_flags = data['Bwd PSH Flags']
        fwd_urg_flags = data['Fwd URG Flags']
        bwd_urg_flags = data['Bwd URG Flags']
        fwd_header_length = data['Fwd Header Length']
        bwd_header_length = data['Bwd Header Length']
        fwd_packets_per_second = data['Fwd Packets/s']
        bwd_packets_per_second = data['Bwd Packets/s']
        packet_length_min = data['Packet Length Min']
        packet_length_max = data['Packet Length Max']
        packet_length_mean = data['Packet Length Mean']
        packet_length_std = data['Packet Length Std']
        packet_length_variance = data['Packet Length Variance']
        fin_flag_count = data['FIN Flag Count']
        syn_flag_count = data['SYN Flag Count']
        rst_flag_count = data['RST Flag Count']
        psh_flag_count = data['PSH Flag Count']
        ack_flag_count = data['ACK Flag Count']
        urg_flag_count = data['URG Flag Count']
        cwe_flag_count = data['CWE Flag Count']
        ece_flag_count = data['ECE Flag Count']
        down_up_ratio = data['Down/Up Ratio']
        avg_packet_size = data['Avg Packet Size']
        avg_fwd_segment_size = data['Avg Fwd Segment Size']
        avg_bwd_segment_size = data['Avg Bwd Segment Size']
        fwd_avg_bytes_bulk = data['Fwd Avg Bytes/Bulk']
        fwd_avg_packets_bulk = data['Fwd Avg Packets/Bulk']
        fwd_avg_bulk_rate = data['Fwd Avg Bulk Rate']
        bwd_avg_bytes_bulk = data['Bwd Avg Bytes/Bulk']
        bwd_avg_packets_bulk = data['Bwd Avg Packets/Bulk']
        bwd_avg_bulk_rate = data['Bwd Avg Bulk Rate']
        subflow_fwd_packets = data['Subflow Fwd Packets']
        subflow_fwd_bytes = data['Subflow Fwd Bytes']
        subflow_bwd_packets = data['Subflow Bwd Packets']
        subflow_bwd_bytes = data['Subflow Bwd Bytes']
        init_fwd_win_bytes = data['Init Fwd Win Bytes']
        init_bwd_win_bytes = data['Init Bwd Win Bytes']
        fwd_act_data_packets = data['Fwd Act Data Packets']
        fwd_seg_size_min = data['Fwd Seg Size Min']
        active_mean = data['Active Mean']
        active_std = data['Active Std']
        active_max = data['Active Max']
        active_min = data['Active Min']
        idle_mean = data['Idle Mean']
        idle_std = data['Idle Std']
        idle_max = data['Idle Max']
        idle_min = data['Idle Min']
        label = data['Label']

        session = await database_sync_to_async(self.save_session)(
            protocol, flow_duration, total_fwd_packets, total_bwd_packets, fwd_packets_length_total,
            bwd_packets_length_total, fwd_packet_length_max, fwd_packet_length_min, fwd_packet_length_mean,
            fwd_packet_length_std, bwd_packet_length_max, bwd_packet_length_min, bwd_packet_length_mean,
            bwd_packet_length_std, flow_bytes_per_second, flow_packets_per_second, flow_iat_mean, flow_iat_std,
            flow_iat_max, flow_iat_min, fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
            bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min, fwd_psh_flags, bwd_psh_flags,
            fwd_urg_flags, bwd_urg_flags, fwd_header_length, bwd_header_length, fwd_packets_per_second,
            bwd_packets_per_second, packet_length_min, packet_length_max, packet_length_mean, packet_length_std,
            packet_length_variance, fin_flag_count, syn_flag_count, rst_flag_count, psh_flag_count, ack_flag_count,
            urg_flag_count, cwe_flag_count, ece_flag_count, down_up_ratio, avg_packet_size, avg_fwd_segment_size,
            avg_bwd_segment_size, fwd_avg_bytes_bulk, fwd_avg_packets_bulk, fwd_avg_bulk_rate, bwd_avg_bytes_bulk,
            bwd_avg_packets_bulk, bwd_avg_bulk_rate, subflow_fwd_packets, subflow_fwd_bytes, subflow_bwd_packets,
            subflow_bwd_bytes, init_fwd_win_bytes, init_bwd_win_bytes, fwd_act_data_packets, fwd_seg_size_min,
            active_mean, active_std, active_max, active_min, idle_mean, idle_std, idle_max, idle_min, label)

        prediction = await database_sync_to_async(predict_attack)(session)

        await self.send(text_data=json.dumps({
            'message': f'The prediction for this session is: {prediction}'
        }))

    def save_session(self, protocol, flow_duration, total_fwd_packets, total_bwd_packets, fwd_packets_length_total,
                     bwd_packets_length_total, fwd_packet_length_max, fwd_packet_length_min, fwd_packet_length_mean,
                     fwd_packet_length_std, bwd_packet_length_max, bwd_packet_length_min, bwd_packet_length_mean,
                     bwd_packet_length_std, flow_bytes_per_second, flow_packets_per_second, flow_iat_mean, flow_iat_std,
                     flow_iat_max, flow_iat_min, fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
                     bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min, fwd_psh_flags, bwd_psh_flags,
                     fwd_urg_flags, bwd_urg_flags, fwd_header_length, bwd_header_length, fwd_packets_per_second,
                     bwd_packets_per_second, packet_length_min, packet_length_max, packet_length_mean, packet_length_std,
                     packet_length_variance, fin_flag_count, syn_flag_count, rst_flag_count, psh_flag_count, ack_flag_count,
                     urg_flag_count, cwe_flag_count, ece_flag_count, down_up_ratio, avg_packet_size, avg_fwd_segment_size,
                     avg_bwd_segment_size, fwd_avg_bytes_bulk, fwd_avg_packets_bulk, fwd_avg_bulk_rate, bwd_avg_bytes_bulk,
                     bwd_avg_packets_bulk, bwd_avg_bulk_rate, subflow_fwd_packets, subflow_fwd_bytes, subflow_bwd_packets,
                     subflow_bwd_bytes, init_fwd_win_bytes, init_bwd_win_bytes, fwd_act_data_packets, fwd_seg_size_min,
                     active_mean, active_std, active_max, active_min, idle_mean, idle_std, idle_max, idle_min, label):
        session = NetworkSession.objects.create(
            protocol=protocol, flow_duration=flow_duration, total_fwd_packets=total_fwd_packets,
            total_bwd_packets=total_bwd_packets, fwd_packets_length_total=fwd_packets_length_total,
            bwd_packets_length_total=bwd_packets_length_total, fwd_packet_length_max=fwd_packet_length_max,
            fwd_packet_length_min=fwd_packet_length_min, fwd_packet_length_mean=fwd_packet_length_mean,
            fwd_packet_length_std=fwd_packet_length_std, bwd_packet_length_max=bwd_packet_length_max,
            bwd_packet_length_min=bwd_packet_length_min, bwd_packet_length_mean=bwd_packet_length_mean,
            bwd_packet_length_std=bwd_packet_length_std, flow_bytes_per_second=flow_bytes_per_second,
            flow_packets_per_second=flow_packets_per_second, flow_iat_mean=flow_iat_mean, flow_iat_std=flow_iat_std,
            flow_iat_max=flow_iat_max, flow_iat_min=flow_iat_min, fwd_iat_total=fwd_iat_total, fwd_iat_mean=fwd_iat_mean,
            fwd_iat_std=fwd_iat_std, fwd_iat_max=fwd_iat_max, fwd_iat_min=fwd_iat_min, bwd_iat_total=bwd_iat_total,
            bwd_iat_mean=bwd_iat_mean, bwd_iat_std=bwd_iat_std, bwd_iat_max=bwd_iat_max, bwd_iat_min=bwd_iat_min,
            fwd_psh_flags=fwd_psh_flags, bwd_psh_flags=bwd_psh_flags, fwd_urg_flags=fwd_urg_flags, bwd_urg_flags=bwd_urg_flags,
            fwd_header_length=fwd_header_length, bwd_header_length=bwd_header_length,
            fwd_packets_per_second=fwd_packets_per_second, bwd_packets_per_second=bwd_packets_per_second,
            packet_length_min=packet_length_min, packet_length_max=packet_length_max, packet_length_mean=packet_length_mean,
            packet_length_std=packet_length_std, packet_length_variance=packet_length_variance, fin_flag_count=fin_flag_count,
            syn_flag_count=syn_flag_count, rst_flag_count=rst_flag_count, psh_flag_count=psh_flag_count,
            ack_flag_count=ack_flag_count, urg_flag_count=urg_flag_count, cwe_flag_count=cwe_flag_count,
            ece_flag_count=ece_flag_count, down_up_ratio=down_up_ratio, avg_packet_size=avg_packet_size,
            avg_fwd_segment_size=avg_fwd_segment_size, avg_bwd_segment_size=avg_bwd_segment_size,
            fwd_avg_bytes_bulk=fwd_avg_bytes_bulk, fwd_avg_packets_bulk=fwd_avg_packets_bulk, fwd_avg_bulk_rate=fwd_avg_bulk_rate,
            bwd_avg_bytes_bulk=bwd_avg_bytes_bulk, bwd_avg_packets_bulk=bwd_avg_packets_bulk, bwd_avg_bulk_rate=bwd_avg_bulk_rate,
            subflow_fwd_packets=subflow_fwd_packets, subflow_fwd_bytes=subflow_fwd_bytes, subflow_bwd_packets=subflow_bwd_packets,
            subflow_bwd_bytes=subflow_bwd_bytes, init_fwd_win_bytes=init_fwd_win_bytes, init_bwd_win_bytes=init_bwd_win_bytes,
            fwd_act_data_packets=fwd_act_data_packets, fwd_seg_size_min=fwd_seg_size_min, active_mean=active_mean,
            active_std=active_std, active_max=active_max, active_min=active_min, idle_mean=idle_mean, idle_std=idle_std,
            idle_max=idle_max, idle_min=idle_min, label=label
        )
        return session

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if not self.scope["user"].is_authenticated:
            await self.close()
            return

        self.room_group_name = f'notifications_{self.scope["user"].id}'
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        pass

    async def notification_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'notification',
            'message': event['message'],
            'notification': event['notification']
        }))
