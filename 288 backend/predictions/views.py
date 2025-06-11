from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view, permission_classes
from api.permissions import IsAdminOrAnalyst, CanManageUsers
from .models import NetworkSession
from .serializers import NetworkSessionSerializer
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from api.models import NetworkFlow, Alert, Threat, AttackType, Agent, Report, SuspiciousIP
from django.utils import timezone
import json
from django.views.decorators.csrf import csrf_exempt
from . import model_utils
from .utils import check_ip_abuseipdb

class NetworkSessionCreateView(CreateAPIView):
    queryset = NetworkSession.objects.all()
    serializer_class = NetworkSessionSerializer
    permission_classes = [IsAuthenticated, IsAdminOrAnalyst]

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminOrAnalyst])
def network_session_list(request):
    sessions = NetworkSession.objects.all()
    data = [{"id": session.id, "protocol": session.protocol, "label": session.label} for session in sessions]
    return JsonResponse(data, safe=False)

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminOrAnalyst])
def network_session_detail(request, pk):
    session = get_object_or_404(NetworkSession, pk=pk)
    data = {
        "id": session.id,
        "protocol": session.protocol,
        "label": session.label,
        "network_flow": session.network_flow.id if session.network_flow else None
    }
    return JsonResponse(data)

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminOrAnalyst])
def create_network_flow(request):
    if request.method == "POST":
        data = json.loads(request.body)
        
        flow_duration = data.get("flow_duration", 0)
        flow_duration_timedelta = timezone.timedelta(microseconds=flow_duration)

        protocol_name = data.get("protocol_name")
        protocol_number = 6 if protocol_name == 'TCP' else 17 if protocol_name == 'UDP' else 0

        session = NetworkSession.objects.create(
            protocol=protocol_number,
            flow_duration=flow_duration,
            total_fwd_packets=data.get("total_fwd_packets", 0),
            total_bwd_packets=data.get("total_bwd_packets", 0),
            fwd_packets_length_total=data.get("fwd_packets_length_total", 0),
            bwd_packets_length_total=data.get("bwd_packets_length_total", 0),
            fwd_packet_length_max=data.get("fwd_packet_length_max", 0),
            fwd_packet_length_min=data.get("fwd_packet_length_min", 0),
            fwd_packet_length_mean=data.get("fwd_packet_length_mean", 0),
            fwd_packet_length_std=data.get("fwd_packet_length_std", 0),
            bwd_packet_length_max=data.get("bwd_packet_length_max", 0),
            bwd_packet_length_min=data.get("bwd_packet_length_min", 0),
            bwd_packet_length_mean=data.get("bwd_packet_length_mean", 0),
            bwd_packet_length_std=data.get("bwd_packet_length_std", 0),
            flow_bytes_per_s=data.get("flow_bytes_per_s", 0),
            flow_packets_per_s=data.get("flow_packets_per_s", 0),
            flow_iat_mean=data.get("flow_iat_mean", 0),
            flow_iat_std=data.get("flow_iat_std", 0),
            flow_iat_max=data.get("flow_iat_max", 0),
            flow_iat_min=data.get("flow_iat_min", 0),
            fwd_iat_total=data.get("fwd_iat_total", 0),
            fwd_iat_mean=data.get("fwd_iat_mean", 0),
            fwd_iat_std=data.get("fwd_iat_std", 0),
            fwd_iat_max=data.get("fwd_iat_max", 0),
            fwd_iat_min=data.get("fwd_iat_min", 0),
            bwd_iat_total=data.get("bwd_iat_total", 0),
            bwd_iat_mean=data.get("bwd_iat_mean", 0),
            bwd_iat_std=data.get("bwd_iat_std", 0),
            bwd_iat_max=data.get("bwd_iat_max", 0),
            bwd_iat_min=data.get("bwd_iat_min", 0),
            fwd_psh_flags=data.get("fwd_psh_flags", 0),
            bwd_psh_flags=data.get("bwd_psh_flags", 0),
            fwd_urg_flags=data.get("fwd_urg_flags", 0),
            bwd_urg_flags=data.get("bwd_urg_flags", 0),
            fwd_header_length=data.get("fwd_header_length", 0),
            bwd_header_length=data.get("bwd_header_length", 0),
            fwd_packets_per_s=data.get("fwd_packets_per_s", 0),
            bwd_packets_per_s=data.get("bwd_packets_per_s", 0),
            packet_length_min=data.get("packet_length_min", 0),
            packet_length_max=data.get("packet_length_max", 0),
            packet_length_mean=data.get("packet_length_mean", 0),
            packet_length_std=data.get("packet_length_std", 0),
            packet_length_variance=data.get("packet_length_variance", 0),
            fin_flag_count=data.get("fin_flag_count", 0),
            syn_flag_count=data.get("syn_flag_count", 0),
            rst_flag_count=data.get("rst_flag_count", 0),
            psh_flag_count=data.get("psh_flag_count", 0),
            ack_flag_count=data.get("ack_flag_count", 0),
            urg_flag_count=data.get("urg_flag_count", 0),
            cwe_flag_count=data.get("cwe_flag_count", 0),
            ece_flag_count=data.get("ece_flag_count", 0),
            down_up_ratio=data.get("down_up_ratio", 0),
            avg_packet_size=data.get("avg_packet_size", 0),
            avg_fwd_segment_size=data.get("avg_fwd_segment_size", 0),
            avg_bwd_segment_size=data.get("avg_bwd_segment_size", 0),
            fwd_avg_bytes_bulk=data.get("fwd_avg_bytes_bulk", 0),
            fwd_avg_packets_bulk=data.get("fwd_avg_packets_bulk", 0),
            fwd_avg_bulk_rate=data.get("fwd_avg_bulk_rate", 0),
            bwd_avg_bytes_bulk=data.get("bwd_avg_bytes_bulk", 0),
            bwd_avg_packets_bulk=data.get("bwd_avg_packets_bulk", 0),
            bwd_avg_bulk_rate=data.get("bwd_avg_bulk_rate", 0),
            subflow_fwd_packets=data.get("subflow_fwd_packets", 0),
            subflow_fwd_bytes=data.get("subflow_fwd_bytes", 0),
            subflow_bwd_packets=data.get("subflow_bwd_packets", 0),
            subflow_bwd_bytes=data.get("subflow_bwd_bytes", 0),
            init_fwd_win_bytes=data.get("init_fwd_win_bytes", 0),
            init_bwd_win_bytes=data.get("init_bwd_win_bytes", 0),
            fwd_act_data_packets=data.get("fwd_act_data_packets", 0),
            fwd_seg_size_min=data.get("fwd_seg_size_min", 0),
            active_mean=data.get("active_mean", 0),
            active_std=data.get("active_std", 0),
            active_max=data.get("active_max", 0),
            active_min=data.get("active_min", 0),
            idle_mean=data.get("idle_mean", 0),
            idle_std=data.get("idle_std", 0),
            idle_max=data.get("idle_max", 0),
            idle_min=data.get("idle_min", 0),
            flow_id=data.get("flow_id"),
            src_ip=data.get("src_ip"),
            src_port=data.get("src_port"),
            dst_ip=data.get("dst_ip"),
            dst_port=data.get("dst_port"),
            protocol_name=data.get("protocol_name"),
            flow_start_time=data.get("flow_start_time"),
            flow_end_time=data.get("flow_end_time"),
            total_bytes=data.get("total_bytes")
        )

        data_for_prediction = session.prepare_data()
        predicted_labels = model_utils.predict(data_for_prediction)
        predicted_label = predicted_labels[0]

        session.label = predicted_label
        session.save()

        threat_level = 'high' if predicted_label != 'Benign' else 'low'
        
        # Check source and destination IPs with AbuseIPDB
        abuseipdb_results = {}
        if session.src_ip:
            result = check_ip_abuseipdb(session.src_ip)
            abuseipdb_results['src_ip'] = result if result is not None else {}
        if session.dst_ip:
            result = check_ip_abuseipdb(session.dst_ip)
            abuseipdb_results['dst_ip'] = result if result is not None else {}

        # Adjust threat level based on AbuseIPDB results
        if abuseipdb_results.get('src_ip', {}).get('abuse_confidence_score', 0) > 50 or \
           abuseipdb_results.get('dst_ip', {}).get('abuse_confidence_score', 0) > 50:
            threat_level = 'high'
        
        protocol_analysis = {
            'flow_duration': session.flow_duration,
            'packet_size_stats': {
                'mean': session.packet_length_mean,
                'std': session.packet_length_std,
                'min': session.packet_length_min,
                'max': session.packet_length_max
            },
            'iat_stats': {
                'mean': session.flow_iat_mean,
                'std': session.flow_iat_std,
                'min': session.flow_iat_min,
                'max': session.flow_iat_max
            },
            'tcp_flags': {
                'fin': session.fin_flag_count,
                'syn': session.syn_flag_count,
                'rst': session.rst_flag_count,
                'psh': session.psh_flag_count,
                'ack': session.ack_flag_count,
                'urg': session.urg_flag_count
            },
            'abuseipdb_results': abuseipdb_results
        }

        network_flow = NetworkFlow.create_or_update(
            flow_id=session.flow_id,
            src_ip=session.src_ip,
            src_port=session.src_port,
            dst_ip=session.dst_ip,
            dst_port=session.dst_port,
            protocol=session.protocol_name,
            start_time=session.flow_start_time,
            end_time=session.flow_end_time,
            packet_count=session.total_fwd_packets + session.total_bwd_packets,
            total_bytes=session.total_bytes,
            duration=session.flow_duration,
            avg_packet_size=session.avg_packet_size,
            std_packet_size=session.packet_length_std,
            min_packet_size=session.packet_length_min,
            max_packet_size=session.packet_length_max,
            bytes_per_second=session.flow_bytes_per_s,
            packets_per_second=session.flow_packets_per_s,
            threat_level=threat_level,
            threat_details={
                'predicted_label': predicted_label,
                'protocol_analysis': protocol_analysis,
                'flow_metrics': {
                    'fwd_packets': session.total_fwd_packets,
                    'bwd_packets': session.total_bwd_packets,
                    'fwd_bytes': session.fwd_packets_length_total,
                    'bwd_bytes': session.bwd_packets_length_total
                }
            },
            anomalies=[],
            protocol_analysis=protocol_analysis
        )

        session.network_flow = network_flow
        session.save()

        agent_name = data.get("agent_name")
        if agent_name:
            agent, created = Agent.objects.get_or_create(
                name=agent_name,
                defaults={
                    'is_active': True,
                    'last_activity': timezone.now()
                }
            )
            agent.network_flows.add(network_flow)
            agent.last_activity = timezone.now()
            agent.save()

        if predicted_label != 'Benign':
            severity = 'high'
            if predicted_label in ['DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest', 'DoS slowloris']:
                severity = 'critical'
            elif predicted_label in ['Brute Force', 'Patator']:
                severity = 'high'
            else:
                severity = 'medium'

            alert = Alert.objects.create(
                flow=network_flow,
                severity=severity,
                status='new',
                description=f'Detected {predicted_label} attack in network flow {network_flow.flow_id}',
                threat_type=predicted_label,
                source=session.src_ip or 'Unknown Source'
            )

            # Create threat with all required fields
            threat = Threat.objects.create(
                flow=network_flow,
                category='dos' if 'DoS' in predicted_label else 'brute_force' if predicted_label in ['Brute Force', 'Patator'] else 'suspicious',
                threat_type=predicted_label,
                target_device=session.dst_ip or 'No Target Device',
                source_ip=session.src_ip or 'Unknown Source',
                status='active',
                severity=severity,
                description=f'Detected {predicted_label} attack from {session.src_ip or "Unknown Source"} to {session.dst_ip or "Unknown Target"}',
                confidence=0.95  # High confidence for ML predictions
            )

            # Create suspicious IP entry if source IP is known
            if session.src_ip:
                SuspiciousIP.objects.create(
                    ip_address=session.src_ip,
                    date=timezone.now().date(),
                    reason=f'Detected {predicted_label} attack',
                    alert=alert,
                    threat=threat
            )

            attack_type, created = AttackType.objects.get_or_create(
                type=predicted_label,
                defaults={'description': f'Attack type: {predicted_label}'}
            )
            attack_type.alerts.add(alert)
            attack_type.threats.add(threat)

            if request.user.is_authenticated:
                report = Report.objects.create(
                    user=request.user,
                    alert=alert,
                    threat=threat,
                    content=f"""Attack Report:
Attack Type: {predicted_label}
Target Device: {session.dst_ip or 'Unknown'}
Attack Source IP: {session.src_ip or 'Unknown'}
Threat Status: Active
Severity Level: {severity}
Category: {threat.category}
Description: Detected {predicted_label} attack from {session.src_ip or 'Unknown Source'} to {session.dst_ip or 'Unknown Target'}
Confidence: 0.95
Created At: {timezone.now()}
Flow ID: {network_flow.flow_id}
Protocol: {session.protocol_name}
Source Port: {session.src_port}
Destination Port: {session.dst_port}
Total Packets: {session.total_fwd_packets + session.total_bwd_packets}
Total Bytes: {session.total_bytes}

Technical Details:
- Protocol: {session.protocol_name}
- Port: {session.dst_port}
- Packet Count: {session.total_fwd_packets + session.total_bwd_packets}
- Total Bytes: {session.total_bytes}
- Duration: {session.flow_duration}

Analysis Results:
- Detection Method: Machine Learning Model
- Confidence Score: 0.95
- False Positive Probability: 0.05

Impact Assessment:
- Impact Level: {severity}
- Affected Systems: Target system at {session.dst_ip}:{session.dst_port}
- Potential Damage: Potential {predicted_label} attack impact

Response Actions:
- Recommended Actions: Monitor traffic from {session.src_ip} and consider blocking if necessary
- Prevention Measures: Implement rate limiting and traffic filtering

Evidence:
- Flow Metrics:
  * Forward Packets: {session.total_fwd_packets}
  * Backward Packets: {session.total_bwd_packets}
  * Forward Bytes: {session.fwd_packets_length_total}
  * Backward Bytes: {session.bwd_packets_length_total}
- Protocol Analysis: {protocol_analysis}
- TCP Flags:
  * FIN: {session.fin_flag_count}
  * SYN: {session.syn_flag_count}
  * RST: {session.rst_flag_count}
  * PSH: {session.psh_flag_count}
  * ACK: {session.ack_flag_count}
  * URG: {session.urg_flag_count}""",
                    report_status='open'
                )

        return JsonResponse({
            'status': 'success',
            'flow_id': network_flow.flow_id,
            'prediction': predicted_label,
            'threat_level': threat_level,
            'agent': agent_name if agent_name else None,
            'attack_type': predicted_label if predicted_label != 'Benign' else None
        })

@api_view(['POST'])
@permission_classes([IsAuthenticated, CanManageUsers])
def create_attack_type(request):
    if request.method == "POST":
        data = json.loads(request.body)
        attack_type = AttackType.objects.create(
            name=data.get("name"),
            description=data.get("description", "")
        )
        return JsonResponse({
            "id": attack_type.id,
            "name": attack_type.name,
            "description": attack_type.description
        }, status=201)

@api_view(['POST'])
@permission_classes([IsAuthenticated, CanManageUsers])
def create_agent(request):
    if request.method == "POST":
        data = json.loads(request.body)
        agent = Agent.objects.create(
            name=data.get("name"),
            ip_address=data.get("ip_address"),
            status=data.get("status", "active")
        )
        return JsonResponse({
            "id": agent.id,
            "name": agent.name,
            "ip_address": agent.ip_address,
            "status": agent.status
        }, status=201)

@api_view(['POST'])
@permission_classes([IsAuthenticated, CanManageUsers])
def create_alert(request):
    if request.method == "POST":
        data = json.loads(request.body)
        alert = Alert.objects.create(
            flow_id=data.get("flow_id"),
            severity=data.get("severity", "low"),
            status=data.get("status", "new"),
            description=data.get("description", ""),
            threat_type=data.get("threat_type", "unknown"),
            source=data.get("source", "system")
        )
        return JsonResponse({
            "id": alert.id,
            "flow_id": alert.flow_id,
            "severity": alert.severity,
            "status": alert.status,
            "description": alert.description,
            "threat_type": alert.threat_type,
            "source": alert.source
        }, status=201)