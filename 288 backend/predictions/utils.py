import time
from collections import defaultdict
from .models import NetworkSession
import pyshark
import numpy as np
import logging
import requests
from django.conf import settings
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

PROTOCOL_MAP = {
    'TCP': 6,
    'UDP': 17,
}

# Cache for storing IP check results
ip_cache = {}
CACHE_DURATION = timedelta(hours=24)  # Cache results for 24 hours

def get_cached_ip_result(ip_address):
    """
    Get cached result for an IP address if it exists and is not expired
    """
    if ip_address in ip_cache:
        cache_entry = ip_cache[ip_address]
        if datetime.now() - cache_entry['timestamp'] < CACHE_DURATION:
            return cache_entry['data']
    return None

def update_ip_cache(ip_address, data):
    """
    Update cache with new IP check result
    """
    ip_cache[ip_address] = {
        'data': data,
        'timestamp': datetime.now()
    }

def compute_statistics(values):
    if not values:
        return {'mean': 0, 'std': 0, 'min': 0, 'max': 0}
    return {
        'mean': np.mean(values),
        'std': np.std(values),
        'min': min(values),
        'max': max(values),
    }

def process_packet(packet, flows):
    try:
        src_ip = getattr(packet.ip, 'src', '')
        dst_ip = getattr(packet.ip, 'dst', '')
        protocol_name = getattr(packet, 'transport_layer', '')
        protocol = PROTOCOL_MAP.get(protocol_name, 0)
        src_port = int(getattr(packet[packet.transport_layer], 'srcport', 0)) if protocol_name else 0
        dst_port = int(getattr(packet[packet.transport_layer], 'dstport', 0)) if protocol_name else 0

        flow_key = (src_ip, dst_ip, protocol, src_port, dst_port)

        if flow_key not in flows:
            flows[flow_key] = {
                'timestamps': [],
                'fwd_lengths': [],
                'bwd_lengths': [],
                'protocol': protocol,
                'start_time': None,
                'end_time': None,
                'last_seen': time.time(),
                'fwd_flags': [],
                'bwd_flags': [],
                'fwd_iat': [],
                'bwd_iat': [],
                'packet_lengths': [],
            }

        flow = flows[flow_key]
        timestamp = float(packet.sniff_timestamp)
        packet_length = float(getattr(packet, 'length', 0))

        if src_ip < dst_ip:
            flow['fwd_lengths'].append(packet_length)
            if flow['timestamps']:
                flow['fwd_iat'].append(timestamp - flow['timestamps'][-1])
            if hasattr(packet, 'tcp'):
                flow['fwd_flags'].append(packet.tcp.flags)
        else:
            flow['bwd_lengths'].append(packet_length)
            if flow['timestamps']:
                flow['bwd_iat'].append(timestamp - flow['timestamps'][-1])
            if hasattr(packet, 'tcp'):
                flow['bwd_flags'].append(packet.tcp.flags)

        flow['packet_lengths'].append(packet_length)
        flow['timestamps'].append(timestamp)
        flow['start_time'] = min(flow['timestamps'])
        flow['end_time'] = max(flow['timestamps'])
        flow['last_seen'] = time.time()

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def finalize_and_store_flows(flows, timeout=10):
    current_time = time.time()
    completed_flows = []

    for flow_key, data in list(flows.items()):
        if current_time - data['last_seen'] > timeout:
            try:
                fwd_stats = compute_statistics(data['fwd_lengths'])
                bwd_stats = compute_statistics(data['bwd_lengths'])
                flow_duration = data['end_time'] - data['start_time'] if data['start_time'] and data['end_time'] else 0
                flow_iat = np.diff(data['timestamps'])
                iat_stats = compute_statistics(flow_iat)

                NetworkSession.objects.create(
                    protocol=data['protocol'],
                    flow_duration=flow_duration,
                    total_fwd_packets=len(data['fwd_lengths']),
                    total_bwd_packets=len(data['bwd_lengths']),
                    total_packets=len(data['packet_lengths']),
                    total_length=sum(data['packet_lengths']),
                    fwd_packet_length_mean=fwd_stats['mean'],
                    bwd_packet_length_mean=bwd_stats['mean'],
                    flow_iat_mean=iat_stats['mean'],
                )
                completed_flows.append(flow_key)
            except Exception as e:
                logging.error(f"Error storing flow: {e}")

    for flow_key in completed_flows:
        del flows[flow_key]

def continuous_capture(interface='eth0', packet_batch_size=100, timeout=10):
    flows = defaultdict(dict)
    while True:
        try:
            logging.info(f"Starting packet capture on interface {interface}...")
            capture = pyshark.LiveCapture(interface=interface)
            packets = capture.sniff_continuously(packet_count=packet_batch_size)

            for packet in packets:
                process_packet(packet, flows)

            finalize_and_store_flows(flows, timeout)
            logging.info("Batch processed and stored. Continuing...")

        except KeyboardInterrupt:
            logging.info("Stopping continuous capture...")
            break
        except Exception as e:
            logging.error(f"Error during capture: {e}. Retrying in 5 seconds...")
            time.sleep(5)

def check_ip_abuseipdb(ip_address):
    """
    Check an IP address against AbuseIPDB API with caching
    Returns a dictionary containing the check results
    """
    try:
        # Check cache first
        cached_result = get_cached_ip_result(ip_address)
        if cached_result is not None:
            logging.info(f"Using cached result for IP: {ip_address}")
            return cached_result

        api_key = getattr(settings, 'ABUSEIPDB_API_KEY', None)
        if not api_key:
            logging.warning("AbuseIPDB API key not configured")
            return None

        url = f'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Key': api_key,
            'Accept': 'application/json',
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90
        }

        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        
        data = response.json()
        result = {
            'abuse_confidence_score': data.get('data', {}).get('abuseConfidenceScore', 0),
            'total_reports': data.get('data', {}).get('totalReports', 0),
            'last_reported_at': data.get('data', {}).get('lastReportedAt'),
            'country_code': data.get('data', {}).get('countryCode'),
            'domain': data.get('data', {}).get('domain'),
            'is_whitelisted': data.get('data', {}).get('isWhitelisted', False)
        }

        # Update cache with new result
        update_ip_cache(ip_address, result)
        return result

    except Exception as e:
        logging.error(f"Error checking IP with AbuseIPDB: {e}")
        return None
