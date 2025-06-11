# processor/feature_extractor.py

import numpy as np
from scapy.layers.inet import IP, TCP, UDP

class FeatureExtractor:
    @staticmethod
    def extract_features(flow):
        flow_stats = {}
        packets = flow.packets
        src_ip = flow.src_ip
        protocol = flow.protocol

        # تعيين البروتوكول كرقم
        protocol_number = 6 if protocol == 'TCP' else 17 if protocol == 'UDP' else 0
        flow_stats['protocol'] = protocol_number

        times = []
        lengths = []
        lengths_fwd = []
        lengths_bwd = []
        directions = []
        iat_list = []
        fwd_iat_list = []
        bwd_iat_list = []
        prev_time = None
        prev_fwd_time = None
        prev_bwd_time = None
        total_fwd_packets = 0
        total_bwd_packets = 0
        fwd_flags = {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'CWR': 0, 'ECE': 0}
        bwd_flags = {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'CWR': 0, 'ECE': 0}
        active_times = []
        idle_times = []
        last_activity_time = None

        for idx, pkt in enumerate(packets):
            pkt_time = pkt.time
            times.append(pkt_time)
            pkt_length = len(pkt)
            lengths.append(pkt_length)
            ip_layer = pkt[IP]
            direction = 'fwd' if ip_layer.src == src_ip else 'bwd'
            directions.append(direction)
            if direction == 'fwd':
                lengths_fwd.append(pkt_length)
                total_fwd_packets += 1
                if protocol == 'TCP' and pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    flags = tcp_layer.flags
                    fwd_flags['FIN'] += int(flags & 0x01 != 0)
                    fwd_flags['SYN'] += int(flags & 0x02 != 0)
                    fwd_flags['RST'] += int(flags & 0x04 != 0)
                    fwd_flags['PSH'] += int(flags & 0x08 != 0)
                    fwd_flags['ACK'] += int(flags & 0x10 != 0)
                    fwd_flags['URG'] += int(flags & 0x20 != 0)
                    fwd_flags['ECE'] += int(flags & 0x40 != 0)
                    fwd_flags['CWR'] += int(flags & 0x80 != 0)
            else:
                lengths_bwd.append(pkt_length)
                total_bwd_packets += 1
                if protocol == 'TCP' and pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    flags = tcp_layer.flags
                    bwd_flags['FIN'] += int(flags & 0x01 != 0)
                    bwd_flags['SYN'] += int(flags & 0x02 != 0)
                    bwd_flags['RST'] += int(flags & 0x04 != 0)
                    bwd_flags['PSH'] += int(flags & 0x08 != 0)
                    bwd_flags['ACK'] += int(flags & 0x10 != 0)
                    bwd_flags['URG'] += int(flags & 0x20 != 0)
                    bwd_flags['ECE'] += int(flags & 0x40 != 0)
                    bwd_flags['CWR'] += int(flags & 0x80 != 0)
            if prev_time is not None:
                iat = (pkt_time - prev_time) * 1e6
                iat_list.append(iat)
            if direction == 'fwd':
                if prev_fwd_time is not None:
                    fwd_iat = (pkt_time - prev_fwd_time) * 1e6
                    fwd_iat_list.append(fwd_iat)
                prev_fwd_time = pkt_time
            else:
                if prev_bwd_time is not None:
                    bwd_iat = (pkt_time - prev_bwd_time) * 1e6
                    bwd_iat_list.append(bwd_iat)
                prev_bwd_time = pkt_time
            prev_time = pkt_time
            if last_activity_time is not None:
                idle_time = (pkt_time - last_activity_time) * 1e6
                if idle_time > 0:
                    idle_times.append(idle_time)
            last_activity_time = pkt_time

        if len(times) > 1:
            flow_duration = (max(times) - min(times)) * 1e6
        else:
            flow_duration = 0
        flow_stats['flow_duration'] = flow_duration
        flow_stats['total_fwd_packets'] = total_fwd_packets
        flow_stats['total_bwd_packets'] = total_bwd_packets
        total_packets = total_fwd_packets + total_bwd_packets
        flow_stats['total_packets'] = total_packets
        total_length = sum(lengths_fwd) + sum(lengths_bwd)
        flow_stats['total_length'] = total_length
        flow_stats['fwd_packets_length_total'] = sum(lengths_fwd)
        flow_stats['bwd_packets_length_total'] = sum(lengths_bwd)

        if lengths_fwd:
            flow_stats['fwd_packet_length_max'] = max(lengths_fwd)
            flow_stats['fwd_packet_length_min'] = min(lengths_fwd)
            flow_stats['fwd_packet_length_mean'] = np.mean(lengths_fwd)
            flow_stats['fwd_packet_length_std'] = np.std(lengths_fwd)
        else:
            flow_stats['fwd_packet_length_max'] = 0
            flow_stats['fwd_packet_length_min'] = 0
            flow_stats['fwd_packet_length_mean'] = 0
            flow_stats['fwd_packet_length_std'] = 0

        if lengths_bwd:
            flow_stats['bwd_packet_length_max'] = max(lengths_bwd)
            flow_stats['bwd_packet_length_min'] = min(lengths_bwd)
            flow_stats['bwd_packet_length_mean'] = np.mean(lengths_bwd)
            flow_stats['bwd_packet_length_std'] = np.std(lengths_bwd)
        else:
            flow_stats['bwd_packet_length_max'] = 0
            flow_stats['bwd_packet_length_min'] = 0
            flow_stats['bwd_packet_length_mean'] = 0
            flow_stats['bwd_packet_length_std'] = 0

        if lengths:
            flow_stats['packet_length_max'] = max(lengths)
            flow_stats['packet_length_min'] = min(lengths)
            flow_stats['packet_length_mean'] = np.mean(lengths)
            flow_stats['packet_length_std'] = np.std(lengths)
            flow_stats['packet_length_variance'] = np.var(lengths)
        else:
            flow_stats['packet_length_max'] = 0
            flow_stats['packet_length_min'] = 0
            flow_stats['packet_length_mean'] = 0
            flow_stats['packet_length_std'] = 0
            flow_stats['packet_length_variance'] = 0

        if flow_duration > 0:
            flow_stats['flow_bytes_per_s'] = total_length / (flow_duration / 1e6)
            flow_stats['flow_packets_per_s'] = total_packets / (flow_duration / 1e6)
            flow_stats['fwd_packets_per_s'] = total_fwd_packets / (flow_duration / 1e6)
            flow_stats['bwd_packets_per_s'] = total_bwd_packets / (flow_duration / 1e6)
        else:
            flow_stats['flow_bytes_per_s'] = 0
            flow_stats['flow_packets_per_s'] = 0
            flow_stats['fwd_packets_per_s'] = 0
            flow_stats['bwd_packets_per_s'] = 0

        if iat_list:
            flow_stats['flow_iat_mean'] = np.mean(iat_list)
            flow_stats['flow_iat_std'] = np.std(iat_list)
            flow_stats['flow_iat_max'] = max(iat_list)
            flow_stats['flow_iat_min'] = min(iat_list)
        else:
            flow_stats['flow_iat_mean'] = 0
            flow_stats['flow_iat_std'] = 0
            flow_stats['flow_iat_max'] = 0
            flow_stats['flow_iat_min'] = 0

        if fwd_iat_list:
            flow_stats['fwd_iat_total'] = sum(fwd_iat_list)
            flow_stats['fwd_iat_mean'] = np.mean(fwd_iat_list)
            flow_stats['fwd_iat_std'] = np.std(fwd_iat_list)
            flow_stats['fwd_iat_max'] = max(fwd_iat_list)
            flow_stats['fwd_iat_min'] = min(fwd_iat_list)
        else:
            flow_stats['fwd_iat_total'] = 0
            flow_stats['fwd_iat_mean'] = 0
            flow_stats['fwd_iat_std'] = 0
            flow_stats['fwd_iat_max'] = 0
            flow_stats['fwd_iat_min'] = 0

        if bwd_iat_list:
            flow_stats['bwd_iat_total'] = sum(bwd_iat_list)
            flow_stats['bwd_iat_mean'] = np.mean(bwd_iat_list)
            flow_stats['bwd_iat_std'] = np.std(bwd_iat_list)
            flow_stats['bwd_iat_max'] = max(bwd_iat_list)
            flow_stats['bwd_iat_min'] = min(bwd_iat_list)
        else:
            flow_stats['bwd_iat_total'] = 0
            flow_stats['bwd_iat_mean'] = 0
            flow_stats['bwd_iat_std'] = 0
            flow_stats['bwd_iat_max'] = 0
            flow_stats['bwd_iat_min'] = 0

        flow_stats['fin_flag_count'] = fwd_flags['FIN'] + bwd_flags['FIN']
        flow_stats['syn_flag_count'] = fwd_flags['SYN'] + bwd_flags['SYN']
        flow_stats['rst_flag_count'] = fwd_flags['RST'] + bwd_flags['RST']
        flow_stats['psh_flag_count'] = fwd_flags['PSH'] + bwd_flags['PSH']
        flow_stats['ack_flag_count'] = fwd_flags['ACK'] + bwd_flags['ACK']
        flow_stats['urg_flag_count'] = fwd_flags['URG'] + bwd_flags['URG']
        flow_stats['cwe_flag_count'] = fwd_flags['CWR'] + bwd_flags['CWR']
        flow_stats['ece_flag_count'] = fwd_flags['ECE'] + bwd_flags['ECE']

        if total_bwd_packets > 0:
            flow_stats['down_up_ratio'] = total_fwd_packets / total_bwd_packets
        else:
            flow_stats['down_up_ratio'] = 0

        if total_packets > 0:
            flow_stats['avg_packet_size'] = total_length / total_packets
        else:
            flow_stats['avg_packet_size'] = 0

        if total_fwd_packets > 0:
            flow_stats['avg_fwd_segment_size'] = sum(lengths_fwd) / total_fwd_packets
        else:
            flow_stats['avg_fwd_segment_size'] = 0

        if total_bwd_packets > 0:
            flow_stats['avg_bwd_segment_size'] = sum(lengths_bwd) / total_bwd_packets
        else:
            flow_stats['avg_bwd_segment_size'] = 0

        fwd_header_lengths = []
        bwd_header_lengths = []
        for pkt in packets:
            ip_layer = pkt[IP]
            direction = 'fwd' if ip_layer.src == src_ip else 'bwd'
            if protocol == 'TCP' and pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                header_length = tcp_layer.dataofs * 4
            elif protocol == 'UDP' and pkt.haslayer(UDP):
                header_length = 8
            else:
                header_length = 0
            if direction == 'fwd':
                fwd_header_lengths.append(header_length)
            else:
                bwd_header_lengths.append(header_length)

        flow_stats['fwd_header_length'] = sum(fwd_header_lengths)
        flow_stats['bwd_header_length'] = sum(bwd_header_lengths)

        init_win_bytes_fwd = None
        init_win_bytes_bwd = None
        for pkt in packets:
            ip_layer = pkt[IP]
            if protocol == 'TCP' and pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                window_size = tcp_layer.window
                if ip_layer.src == src_ip and init_win_bytes_fwd is None:
                    init_win_bytes_fwd = window_size
                elif ip_layer.dst == src_ip and init_win_bytes_bwd is None:
                    init_win_bytes_bwd = window_size
                if init_win_bytes_fwd is not None and init_win_bytes_bwd is not None:
                    break

        flow_stats['init_fwd_win_bytes'] = init_win_bytes_fwd if init_win_bytes_fwd is not None else 0
        flow_stats['init_bwd_win_bytes'] = init_win_bytes_bwd if init_win_bytes_bwd is not None else 0

        act_data_pkt_fwd = 0
        for pkt in packets:
            ip_layer = pkt[IP]
            if protocol == 'TCP' and pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                if ip_layer.src == src_ip and len(tcp_layer.payload) > 0:
                    act_data_pkt_fwd += 1

        flow_stats['fwd_act_data_packets'] = act_data_pkt_fwd

        min_seg_size_fwd = None
        for pkt in packets:
            ip_layer = pkt[IP]
            if protocol == 'TCP' and pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                segment_size = tcp_layer.dataofs * 4
                if ip_layer.src == src_ip:
                    if min_seg_size_fwd is None or segment_size < min_seg_size_fwd:
                        min_seg_size_fwd = segment_size

        flow_stats['fwd_seg_size_min'] = min_seg_size_fwd if min_seg_size_fwd is not None else 0

        if active_times:
            flow_stats['active_mean'] = np.mean(active_times)
            flow_stats['active_std'] = np.std(active_times)
            flow_stats['active_max'] = max(active_times)
            flow_stats['active_min'] = min(active_times)
        else:
            flow_stats['active_mean'] = 0
            flow_stats['active_std'] = 0
            flow_stats['active_max'] = 0
            flow_stats['active_min'] = 0

        if idle_times:
            flow_stats['idle_mean'] = np.mean(idle_times)
            flow_stats['idle_std'] = np.std(idle_times)
            flow_stats['idle_max'] = max(idle_times)
            flow_stats['idle_min'] = min(idle_times)
        else:
            flow_stats['idle_mean'] = 0
            flow_stats['idle_std'] = 0
            flow_stats['idle_max'] = 0
            flow_stats['idle_min'] = 0

        # قيم افتراضية للصفر
        flow_stats['fwd_psh_flags'] = fwd_flags['PSH']
        flow_stats['bwd_psh_flags'] = bwd_flags['PSH']
        flow_stats['fwd_urg_flags'] = fwd_flags['URG']
        flow_stats['bwd_urg_flags'] = bwd_flags['URG']
        flow_stats['fwd_avg_bytes_bulk'] = 0
        flow_stats['fwd_avg_packets_bulk'] = 0
        flow_stats['fwd_avg_bulk_rate'] = 0
        flow_stats['bwd_avg_bytes_bulk'] = 0
        flow_stats['bwd_avg_packets_bulk'] = 0
        flow_stats['bwd_avg_bulk_rate'] = 0
        flow_stats['subflow_fwd_packets'] = total_fwd_packets
        flow_stats['subflow_fwd_bytes'] = sum(lengths_fwd)
        flow_stats['subflow_bwd_packets'] = total_bwd_packets
        flow_stats['subflow_bwd_bytes'] = sum(lengths_bwd)

        return flow_stats