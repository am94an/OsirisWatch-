# processor/flow.py
import time
import datetime 
from .feature_extractor import FeatureExtractor
from utils.logger import setup_logger

class Flow:
    def __init__(self, flow_id, src_ip, src_port, dst_ip, dst_port, protocol):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.packets = []
        self.features = {}
        self.logger = setup_logger()
        self.last_packet_time = time.time()
        self.start_time = self.last_packet_time
        
        # إضافة متغيرات للتحليل السريع
        self.packet_count = 0
        self.total_bytes = 0
        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.urgent_count = 0
        self.last_analysis_time = self.start_time
        self.analysis_interval = 1.0  # تحليل كل ثانية
        self.min_packets_for_analysis = 5  # الحد الأدنى للحزم للتحليل الأولي

    def add_packet(self, pkt):
        current_time = time.time()
        self.packets.append(pkt)
        self.last_packet_time = current_time
        self.packet_count += 1
        self.total_bytes += len(pkt)

        # تحليل سريع للحزمة الحالية
        if pkt.haslayer('TCP'):
            tcp_layer = pkt['TCP']
            flags = tcp_layer.flags
            self.syn_count += int(flags & 0x02 != 0)
            self.ack_count += int(flags & 0x10 != 0)
            self.rst_count += int(flags & 0x04 != 0)
            self.urgent_count += int(flags & 0x20 != 0)

        # تحليل سريع كل فترة
        if (current_time - self.last_analysis_time >= self.analysis_interval and 
            self.packet_count >= self.min_packets_for_analysis):
            self.quick_analysis()
            self.last_analysis_time = current_time

    def quick_analysis(self):
        """تحليل سريع للكشف عن الهجمات المحتملة"""
        current_time = time.time()
        duration = current_time - self.start_time
        
        # حساب معدلات سريعة
        packets_per_second = self.packet_count / duration if duration > 0 else 0
        bytes_per_second = self.total_bytes / duration if duration > 0 else 0
        
        # تحليل سريع للهجمات المحتملة
        attack_indicators = {
            'syn_flood': self.syn_count > 10 and self.syn_count / self.packet_count > 0.7,
            'high_traffic': packets_per_second > 1000 or bytes_per_second > 1000000,
            'port_scan': self.packet_count > 20 and self.syn_count > 15,
            'dos_attempt': self.rst_count > 5 and self.rst_count / self.packet_count > 0.3
        }
        
        # إذا تم اكتشاف مؤشرات هجوم، قم بإرسال تنبيه فوري
        if any(attack_indicators.values()):
            self.send_urgent_alert(attack_indicators)

    def send_urgent_alert(self, attack_indicators):
        """إرسال تنبيه عاجل للهجمات المحتملة"""
        alert_data = {
            'flow_id': self.flow_id,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'protocol': self.protocol,
            'attack_indicators': attack_indicators,
            'packet_count': self.packet_count,
            'total_bytes': self.total_bytes,
            'duration': self.last_packet_time - self.start_time
        }
        # إرسال التنبيه عبر WebSocket
        self.send_websocket_alert(alert_data)

    def calculate_features(self):
        flow_stats = FeatureExtractor.extract_features(self)

        flow_stats.update({
            'flow_id': self.flow_id,
            'src_ip': self.src_ip,
            'src_port': self.src_port,
            'dst_ip': self.dst_ip,
            'dst_port': self.dst_port,
            'protocol_name': self.protocol
        })

        times = [pkt.time for pkt in self.packets]
        if times:
            flow_start_time = datetime.datetime.utcfromtimestamp(min(times)).isoformat() + 'Z'
            flow_end_time = datetime.datetime.utcfromtimestamp(max(times)).isoformat() + 'Z'
            flow_stats['flow_start_time'] = flow_start_time
            flow_stats['flow_end_time'] = flow_end_time
        else:
            flow_stats['flow_start_time'] = None
            flow_stats['flow_end_time'] = None

        lengths = [len(pkt) for pkt in self.packets]
        flow_stats['total_bytes'] = sum(lengths)

        # إضافة الميزات السريعة المحسوبة مسبقاً
        flow_stats.update({
            'quick_analysis': {
                'packets_per_second': self.packet_count / (self.last_packet_time - self.start_time),
                'bytes_per_second': self.total_bytes / (self.last_packet_time - self.start_time),
                'syn_ratio': self.syn_count / self.packet_count if self.packet_count > 0 else 0,
                'ack_ratio': self.ack_count / self.packet_count if self.packet_count > 0 else 0
            }
        })

        self.features = flow_stats
        self.logger.info(f"Features calculated for flow {self.flow_id}")
        return flow_stats