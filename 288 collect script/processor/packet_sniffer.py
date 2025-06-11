# processor/packet_sniffer.py

from scapy.all import sniff
from collections import defaultdict
from .flow import Flow
from utils.logger import setup_logger
from utils.auth import auth_manager
from config import SNIF_FILTER, API_URL
import time
import requests
from .feature_extractor import FeatureExtractor
import json
import websockets
import asyncio

class PacketSniffer:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PacketSniffer, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance

    def __init__(self):
        if self.initialized:
            return
        self.flows = {}
        self.logger = setup_logger()
        self.flow_timeout = 120  # seconds
        self.max_flow_duration = 3600  # 1 hour
        self.max_flow_packets = 1000
        self.initialized = True
        self.feature_extractor = FeatureExtractor()
        self.api_url = API_URL + 'create_network_flow/'
        
        # Fast analysis thresholds
        self.alert_thresholds = {
            'packets_per_second': 1000,
            'bytes_per_second': 1000000,
            'syn_ratio': 0.7,
            'rst_ratio': 0.3
        }
        
        # WebSocket setup
        self.ws_url = "ws://localhost:8000/ws/network_sessions/"
        self.ws = None
        self.ws_connected = False

    async def connect_websocket(self):
        """Connect to WebSocket server"""
        try:
            self.ws = await websockets.connect(self.ws_url)
            self.ws_connected = True
            self.logger.info("Connected to WebSocket server")
        except Exception as e:
            self.logger.error(f"Failed to connect to WebSocket server: {str(e)}")
            self.ws_connected = False

    async def send_websocket_alert(self, alert_data):
        """Send alert via WebSocket"""
        if not self.ws_connected:
            await self.connect_websocket()
        
        if self.ws_connected:
            try:
                await self.ws.send(json.dumps(alert_data))
                self.logger.info(f"Alert sent: {alert_data['flow_id']}")
            except Exception as e:
                self.logger.error(f"Failed to send alert: {str(e)}")
                self.ws_connected = False

    def process_packet(self, pkt):
        try:
            if pkt.haslayer('IP'):
                ip_layer = pkt['IP']
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                if pkt.haslayer('TCP'):
                    layer = pkt['TCP']
                    src_port = layer.sport
                    dst_port = layer.dport
                    protocol = 'TCP'
                elif pkt.haslayer('UDP'):
                    layer = pkt['UDP']
                    src_port = layer.sport
                    dst_port = layer.dport
                    protocol = 'UDP'
                else:
                    return

                flow_id = f"{src_ip}-{src_port}-{dst_ip}-{dst_port}-{protocol}"
                
                if flow_id not in self.flows:
                    self.flows[flow_id] = Flow(flow_id, src_ip, src_port, dst_ip, dst_port, protocol)
                    self.logger.info(f"New flow created: {flow_id}")
                
                flow = self.flows[flow_id]
                flow.add_packet(pkt)
                
                if self.is_flow_finished(flow, pkt):
                    self.finalize_flow(flow)
                    del self.flows[flow_id]
                    self.logger.info(f"Flow {flow_id} has been processed and removed.")

        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")

    def is_flow_finished(self, flow, pkt):
        """Check if flow should be terminated"""
        current_time = time.time()
        
        if flow.packet_count >= 5:
            if self.check_attack_indicators(flow):
                return True
        
        if current_time - flow.last_packet_time > self.flow_timeout:
            return True
        if current_time - flow.start_time > self.max_flow_duration:
            return True
        if flow.packet_count >= self.max_flow_packets:
            return True
            
        return False

    def check_attack_indicators(self, flow):
        """Check for potential attack indicators"""
        duration = flow.last_packet_time - flow.start_time
        if duration == 0:
            return False
            
        packets_per_second = flow.packet_count / duration
        bytes_per_second = flow.total_bytes / duration
        
        if (packets_per_second > self.alert_thresholds['packets_per_second'] or
            bytes_per_second > self.alert_thresholds['bytes_per_second'] or
            flow.syn_count / flow.packet_count > self.alert_thresholds['syn_ratio'] or
            flow.rst_count / flow.packet_count > self.alert_thresholds['rst_ratio']):
            return True
            
        return False

    def finalize_flow(self, flow):
        """Finalize flow and send data"""
        try:
            flow.calculate_features()
            self.send_network_flow_data(flow)
            self.logger.info(f"Flow {flow.flow_id} has been finalized and sent.")
        except Exception as e:
            self.logger.error(f"Error finalizing flow: {str(e)}")

    def send_network_flow_data(self, flow):
        """Send flow data to server"""
        try:
            headers = {
                'Content-Type': 'application/json',
                **auth_manager.get_auth_headers()
            }
            
            response = requests.post(
                self.api_url,
                json=flow.features,
                headers=headers
            )
            
            if response.status_code == 200:
                self.logger.info(f"Successfully sent flow data to predictions API")
            elif response.status_code == 401:
                auth_manager.refresh_tokens()
                headers = {
                    'Content-Type': 'application/json',
                    **auth_manager.get_auth_headers()
                }
                response = requests.post(
                    self.api_url,
                    json=flow.features,
                    headers=headers
                )
                if response.status_code == 200:
                    self.logger.info(f"Successfully sent flow data after token refresh")
                else:
                    self.logger.error(f"Failed to send flow data after token refresh. Status code: {response.status_code}")
            else:
                self.logger.error(f"Failed to send flow data. Status code: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error sending data to API: {str(e)}")

    def start_sniffing(self):
        """Start packet capture"""
        self.logger.info("Starting packet sniffing...")
        asyncio.run(self.connect_websocket())
        sniff(filter=SNIF_FILTER, prn=self.process_packet, store=0)