from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.db.models import Sum, Count, Avg
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from django.db import models

from .models import (
    NetworkFlow, Threat, Alert, SuspiciousIP, 
    UserLogin, Agent, AttackType
)
from .mixins import IncludeUserDataMixin, CalculateChangeMixin

CACHE_TTL = getattr(settings, 'CACHE_TTL', 300)

class DashboardView(IncludeUserDataMixin, CalculateChangeMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_data = self.get_user_data(user)

        # تحقق من صلاحيات المستخدم
        try:
            is_admin = user.userprofile.role == 'Admin'
            is_analyst = user.userprofile.role == 'Analyst'
            
            # إذا لم يكن المستخدم مسؤولًا أو محللًا، ارجع رسالة خطأ مناسبة
            if not (is_admin or is_analyst):
                return Response({
                    "error": "You do not have permission to access the dashboard.",
                    "user_data": user_data
                }, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            return Response({
                "error": f"Error checking user permissions: {str(e)}",
                "user_data": user_data
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # إنشاء مفتاح للذاكرة المؤقتة خاص بالمستخدم الحالي
        cache_key = f"dashboard_data_user_{user.id}"
        dashboard_data = cache.get(cache_key)

        # إذا لم يتم العثور على بيانات في الذاكرة المؤقتة، قم بحسابها
        if not dashboard_data:
            today = datetime.now().date()
            yesterday = today - timedelta(days=1)
            last_week = today - timedelta(weeks=1)
            last_hour = timezone.now() - timedelta(hours=1)

            try:
                # تحديد ما إذا كان المستخدم مسؤولاً أم محلل
                is_admin = user.userprofile.role == 'Admin'
                
                # إذا كان محلل، احصل على قائمة الأجهزة التي يشرف عليها
                if not is_admin:
                    # الحصول على الأجهزة المرتبطة بالمحلل
                    user_agents = Agent.objects.filter(user=user)
                    if not user_agents.exists():
                        return Response({
                            "threats_detected": {"count": 0, "change": 0, "trend": "stable"},
                            "network_traffic": {"count": 0, "change": 0, "trend": "stable"},
                            "suspicious_ips": {"count": 0, "change": 0, "trend": "stable"},
                            "user_logins": {"count": 0, "change": 0, "trend": "stable"},
                            "traffic_trends": {"high": [], "low": [], "timestamps": []},
                            "top_agents": [],
                            "type_of_attack": [],
                            'user_data': user_data,
                            "message": "No agents assigned to your account. Please contact an administrator to assign agents to you."
                        }, status=status.HTTP_200_OK)
                
                # استعلامات مختلفة بناءً على دور المستخدم
                if is_admin:
                    flows_today = NetworkFlow.objects.filter(start_time__date=today)
                    flows_yesterday = NetworkFlow.objects.filter(start_time__date=yesterday)
                    threats_today_query = Threat.objects.filter(flow__in=flows_today)
                    threats_yesterday_query = Threat.objects.filter(flow__in=flows_yesterday)
                    suspicious_ips_today_query = SuspiciousIP.objects.filter(date=today, threat__flow__in=flows_today)
                    suspicious_ips_yesterday_query = SuspiciousIP.objects.filter(date=yesterday, threat__flow__in=flows_yesterday)
                    logins_today_query = UserLogin.objects.filter(timestamp__date=today)
                    logins_yesterday_query = UserLogin.objects.filter(timestamp__date=yesterday)
                else:
                    flows_today = NetworkFlow.objects.filter(start_time__date=today, agents__in=user_agents)
                    flows_yesterday = NetworkFlow.objects.filter(start_time__date=yesterday, agents__in=user_agents)
                    
                    threats_today_query = Threat.objects.filter(flow__in=flows_today)
                    threats_yesterday_query = Threat.objects.filter(flow__in=flows_yesterday)
                    
                    suspicious_ips_today_query = SuspiciousIP.objects.filter(date=today, threat__flow__in=flows_today)
                    suspicious_ips_yesterday_query = SuspiciousIP.objects.filter(date=yesterday, threat__flow__in=flows_yesterday)
                
                # حساب الإحصائيات
                threats_today = threats_today_query.count()
                threats_yesterday = threats_yesterday_query.count()
                threats_change, threats_trend = self.calculate_change(threats_today, threats_yesterday)

                # حركة الشبكة - مجموع حزم البيانات
                traffic_today = flows_today.aggregate(Sum('packet_count'))['packet_count__sum'] or 0
                traffic_yesterday = flows_yesterday.aggregate(Sum('packet_count'))['packet_count__sum'] or 0
                traffic_change, traffic_trend = self.calculate_change(traffic_today, traffic_yesterday)

                # عناوين IP المشبوهة
                suspicious_ips_today = suspicious_ips_today_query.count()
                suspicious_ips_yesterday = suspicious_ips_yesterday_query.count()
                suspicious_ips_change, suspicious_ips_trend = self.calculate_change(suspicious_ips_today, suspicious_ips_yesterday)

                # تسجيلات الدخول
                logins_today = logins_today_query.count()
                logins_yesterday = logins_yesterday_query.count()
                logins_change, logins_trend = self.calculate_change(logins_today, logins_yesterday)

                # مفتاح ذاكرة مؤقتة منفصل لاتجاهات حركة المرور
                traffic_trends_key = f"traffic_trends_{user.id}_{today.isoformat()}"
                traffic_trends = cache.get(traffic_trends_key)
                
                if not traffic_trends:
                    now = timezone.now()
                    hourly_timestamps = []
                    
                    # تقسيم الساعة إلى فترات أصغر (كل 5 دقائق)
                    for i in range(12):
                        for j in range(12):  # 12 فترات في الساعة
                            timestamp = now - timedelta(hours=i, minutes=j*5)
                            hourly_timestamps.append(timestamp)
                    
                    hourly_timestamps.sort()
                    
                    high_traffic_data = []
                    low_traffic_data = []
                    formatted_timestamps = []
                    
                    for i in range(0, len(hourly_timestamps), 12):  # تجميع كل 12 فترة (ساعة)
                        period_timestamps = hourly_timestamps[i:i+12]
                        start_time = period_timestamps[0]
                        end_time = period_timestamps[-1]
                        
                        # حساب متوسط حركة المرور في هذه الفترة
                        if is_admin:
                            high_traffic = NetworkFlow.objects.filter(
                                start_time__gte=start_time,
                                start_time__lte=end_time,
                                threat_level='high'
                            ).aggregate(
                                avg_packets=Avg('packet_count'),
                                total_packets=Sum('packet_count')
                            )
                            
                            low_traffic = NetworkFlow.objects.filter(
                                start_time__gte=start_time,
                                start_time__lte=end_time,
                                threat_level='low'
                            ).aggregate(
                                avg_packets=Avg('packet_count'),
                                total_packets=Sum('packet_count')
                            )
                        else:
                            high_traffic = NetworkFlow.objects.filter(
                                start_time__gte=start_time,
                                start_time__lte=end_time,
                                threat_level='high',
                                agents__in=user_agents
                            ).aggregate(
                                avg_packets=Avg('packet_count'),
                                total_packets=Sum('packet_count')
                            )
                            
                            low_traffic = NetworkFlow.objects.filter(
                                start_time__gte=start_time,
                                start_time__lte=end_time,
                                threat_level='low',
                                agents__in=user_agents
                            ).aggregate(
                                avg_packets=Avg('packet_count'),
                                total_packets=Sum('packet_count')
                            )
                        
                        # استخدام المتوسط بدلاً من المجموع
                        high_traffic_value = high_traffic['avg_packets'] or 0
                        low_traffic_value = low_traffic['avg_packets'] or 0
                        
                        # تطبيق معادلة تجانس
                        if i > 0:
                            high_traffic_value = (high_traffic_value + high_traffic_data[-1]) / 2
                            low_traffic_value = (low_traffic_value + low_traffic_data[-1]) / 2
                        
                        high_traffic_data.append(high_traffic_value)
                        low_traffic_data.append(low_traffic_value)
                        formatted_timestamps.append(start_time.isoformat())
                    
                    traffic_trends = {
                        "high": high_traffic_data,
                        "low": low_traffic_data,
                        "timestamps": formatted_timestamps,
                    }
                    
                    cache.set(traffic_trends_key, traffic_trends, 60 * 60)

                # مفتاح ذاكرة مؤقتة للوكلاء
                top_agents_key = f"top_agents_{user.id}_{today.isoformat()}"
                top_agents_data = cache.get(top_agents_key)
                
                if not top_agents_data:
                    # أهم الوكلاء - مخطط دائري
                    if is_admin:
                        top_agents = Agent.objects.annotate(flow_count=Count('network_flows'))
                    else:
                        top_agents = user_agents.annotate(flow_count=Count('network_flows'))
                    
                    # حساب النسب المئوية لكل وكيل
                    total_agent_flows = sum(agent.flow_count for agent in top_agents) or 1  # تجنب القسمة على صفر
                    
                    top_agents_data = []
                    for agent in top_agents:
                        percentage = round((agent.flow_count / total_agent_flows) * 100)
                        top_agents_data.append({
                            "name": agent.name,
                            "percentage": percentage
                        })
                    
                    # ترتيب حسب النسبة المئوية وأخذ أعلى 5
                    top_agents_data = sorted(top_agents_data, key=lambda x: x['percentage'], reverse=True)[:5]
                    
                    # تخزين مؤقت لمدة ساعة
                    cache.set(top_agents_key, top_agents_data, 60 * 60)

                # مفتاح ذاكرة مؤقتة لأنواع الهجمات
                attack_types_key = f"attack_types_{user.id}_{today.isoformat()}"
                attack_types_data = cache.get(attack_types_key)
                
                if not attack_types_data:
                    # نوع مخطط الهجوم - مخطط دائري
                    if is_admin:
                        attack_types = AttackType.objects.annotate(
                            alert_count=Count('alerts'),
                            threat_count=Count('threats')
                        )
                    else:
                        # الحصول على أنواع الهجمات المرتبطة بالتنبيهات والتهديدات للأجهزة التي يشرف عليها المستخدم
                        alerts_ids = Alert.objects.filter(flow__agent__in=user_agents).values_list('id', flat=True)
                        threats_ids = Threat.objects.filter(alert_id__in=alerts_ids).values_list('id', flat=True)
                        
                        attack_types = AttackType.objects.filter(
                            models.Q(alerts__in=alerts_ids) | models.Q(threats__in=threats_ids)
                        ).annotate(
                            alert_count=Count('alerts', filter=models.Q(alerts__in=alerts_ids)),
                            threat_count=Count('threats', filter=models.Q(threats__in=threats_ids))
                        ).distinct()
                    
                    # حساب النسب المئوية لكل نوع هجوم
                    total_attack_counts = sum(at.alert_count + at.threat_count for at in attack_types) or 1
                    
                    attack_types_data = []
                    for attack_type in attack_types:
                        total_count = attack_type.alert_count + attack_type.threat_count
                        percentage = round((total_count / total_attack_counts) * 100)
                        attack_types_data.append({
                            "type": attack_type.type,
                            "percentage": percentage
                        })
                    
                    # ترتيب حسب النسبة المئوية وأخذ أعلى 5
                    attack_types_data = sorted(attack_types_data, key=lambda x: x['percentage'], reverse=True)[:5]
                    
                    # تخزين مؤقت لمدة ساعة
                    cache.set(attack_types_key, attack_types_data, 60 * 60)

                # بناء الاستجابة
                dashboard_data = {
                    "threats_detected": {"count": threats_today, "change": threats_change, "trend": threats_trend},
                    "network_traffic": {"count": traffic_today, "change": traffic_change, "trend": traffic_trend},
                    "suspicious_ips": {"count": suspicious_ips_today, "change": suspicious_ips_change, "trend": suspicious_ips_trend},
                    "user_logins": {"count": logins_today, "change": logins_change, "trend": logins_trend},
                    "traffic_trends": traffic_trends,
                    "top_agents": top_agents_data,
                    "type_of_attack": attack_types_data,
                    'user_data': user_data,
                }
                
                # تخزين بيانات لوحة التحكم الكاملة في ذاكرة التخزين المؤقت
                cache.set(cache_key, dashboard_data, CACHE_TTL)

            except Exception as e:
                return Response({"error": f"An error occurred: {str(e)}", "user_data": user_data}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # إرجاع البيانات المخزنة مؤقتًا أو المحسوبة
        return Response(dashboard_data, status=status.HTTP_200_OK)

class DataAnalysisView(IncludeUserDataMixin, CalculateChangeMixin, APIView):
    permission_classes = [IsAuthenticated]

    def calculate_risk_level(self, threats, flow_count, total_bytes, total_packets):

        risk_score = 0
        
        for threat in threats:
            threat_weight = threat["confidence"]
            
            if threat["category"] == "dos":
                threat_weight *= 1.5
            elif threat["category"] == "brute_force":
                threat_weight *= 1.3
            elif threat["category"] == "malware":
                threat_weight *= 1.4
            elif threat["category"] == "scan":
                threat_weight *= 1.2
            
            risk_score += threat_weight
        
        # حساب درجة المخاطرة من حجم البيانات
        if total_bytes > 1000000000:  # أكثر من 1GB
            risk_score += 2
        elif total_bytes > 100000000:  # أكثر من 100MB
            risk_score += 1.5
        elif total_bytes > 10000000:   # أكثر من 10MB
            risk_score += 1
        
        # حساب درجة المخاطرة من عدد الحزم
        if total_packets > 10000:
            risk_score += 1.5
        elif total_packets > 1000:
            risk_score += 1
        
        # حساب درجة المخاطرة من عدد التدفقات
        if flow_count > 100:
            risk_score += 2
        elif flow_count > 50:
            risk_score += 1.5
        elif flow_count > 10:
            risk_score += 1
        
        # تحديد مستوى المخاطرة النهائي
        if risk_score >= 8:
            return "critical"
        elif risk_score >= 6:
            return "high"
        elif risk_score >= 4:
            return "medium"
        else:
            return "low"

    def get(self, request):
        user = request.user
        user_data = self.get_user_data(user)
        
        # إنشاء مفتاح للذاكرة المؤقتة خاص بالمستخدم والتاريخ
        today = datetime.now().date()
        cache_key = f"data_analysis_user_{user.id}_{today.isoformat()}"
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return Response(cached_data, status=200)
            
        try:
            today = datetime.now().date()
            last_week = today - timedelta(weeks=1)

            # تحديد ما إذا كان المستخدم مسؤولاً أم محلل
            is_admin = user.userprofile.role == 'Admin'
            
            if not is_admin:
                user_agents = Agent.objects.filter(user=user)
                if not user_agents.exists():
                    return Response({
                        "data_analysis": {
                            "threat_trends": {"categories": [], "series": []},
                            "network_traffic": {"name": "Applications", "children": []},
                            "alarming_hosts": [],
                            "attack_vectors": [],
                            "top_threats": {"categories": [], "data": []},
                            "suspicious_ips": {"recent": []}
                        },
                        "user_data": user_data
                    }, status=200)
                
                flows = NetworkFlow.objects.filter(agent__in=user_agents)
                threats = Threat.objects.filter(flow__in=flows)
            else:
                flows = NetworkFlow.objects.all()
                threats = Threat.objects.all()

            # 1. Threat Trends - تحليل اتجاهات التهديدات
            threat_trends = {
                "categories": [],
                "series": [
                    {"name": "High Confidence", "data": []},
                    {"name": "Medium Confidence", "data": []},
                    {"name": "Low Confidence", "data": []}
                ]
            }
            
            for i in range(7):
                day = today - timedelta(days=i)
                high_confidence = threats.filter(
                    created_at__date=day,
                    confidence__gte=0.8
                ).count()
                medium_confidence = threats.filter(
                    created_at__date=day,
                    confidence__gte=0.5,
                    confidence__lt=0.8
                ).count()
                low_confidence = threats.filter(
                    created_at__date=day,
                    confidence__lt=0.5
                ).count()
                
                threat_trends["categories"].insert(0, day.strftime("%a"))
                threat_trends["series"][0]["data"].insert(0, high_confidence)
                threat_trends["series"][1]["data"].insert(0, medium_confidence)
                threat_trends["series"][2]["data"].insert(0, low_confidence)

            # 2. Network Traffic Analysis - تحليل حركة الشبكة
            network_traffic = {
                "tcp": {
                    "http": 0,
                    "https": 0,
                    "ftp": 0
                },
                "udp": {
                    "dns": 0,
                    "dhcp": 0,
                    "snmp": 0
                }
            }
            
            # تجميع حركة المرور حسب البروتوكول
            protocol_stats = flows.values('protocol').annotate(
                total_bytes=Sum('total_bytes'),
                packet_count=Sum('packet_count')
            )
            
            for stat in protocol_stats:
                protocol = stat['protocol'].lower()
                value = stat['total_bytes'] or 0
                
                # Map protocols to their categories
                if 'tcp' in protocol:
                    if 'http' in protocol:
                        network_traffic['tcp']['http'] += value
                    elif 'https' in protocol:
                        network_traffic['tcp']['https'] += value
                    elif 'ftp' in protocol:
                        network_traffic['tcp']['ftp'] += value
                    else:
                        # Default TCP traffic
                        network_traffic['tcp']['http'] += value
                elif 'udp' in protocol:
                    if 'dns' in protocol:
                        network_traffic['udp']['dns'] += value
                    elif 'dhcp' in protocol:
                        network_traffic['udp']['dhcp'] += value
                    elif 'snmp' in protocol:
                        network_traffic['udp']['snmp'] += value
                    else:
                        # Default UDP traffic
                        network_traffic['udp']['dns'] += value

            # 3. Alarming Hosts - المضيفين المثيرين للقلق
            alarming_hosts = {}
            high_threat_flows = flows.filter(threat_level='high')
            
            for flow in high_threat_flows:
                related_threats = threats.filter(flow=flow)
                host_ip = flow.src_ip
                
                if host_ip not in alarming_hosts:
                    alarming_hosts[host_ip] = {
                        "host": host_ip,
                        "threat_level": flow.threat_level,
                        "incidents": 0,
                        "last_seen": flow.end_time.isoformat() if flow.end_time else flow.start_time.isoformat(),
                        "status": "active" if flow.end_time and flow.end_time > timezone.now() - timedelta(hours=1) else "investigating",
                        "threats": [],
                        "flow_count": 0,
                        "total_bytes": 0,
                        "total_packets": 0,
                        "risk_level": "low",
                        "risk_score": 0
                    }
                
                # تحديث البيانات المجمعة
                alarming_hosts[host_ip]["incidents"] += related_threats.count()
                alarming_hosts[host_ip]["flow_count"] += 1
                alarming_hosts[host_ip]["total_bytes"] += flow.total_bytes
                alarming_hosts[host_ip]["total_packets"] += flow.packet_count
                
                # تحديث آخر ظهور
                if flow.end_time and flow.end_time > datetime.fromisoformat(alarming_hosts[host_ip]["last_seen"].replace('Z', '+00:00')):
                    alarming_hosts[host_ip]["last_seen"] = flow.end_time.isoformat()
                    alarming_hosts[host_ip]["status"] = "active" if flow.end_time > timezone.now() - timedelta(hours=1) else "investigating"
                
                # إضافة التهديدات الجديدة
                for threat in related_threats:
                    if not any(t["category"] == threat.category and t["confidence"] == threat.confidence 
                             for t in alarming_hosts[host_ip]["threats"]):
                        alarming_hosts[host_ip]["threats"].append({
                            "category": threat.category,
                            "confidence": threat.confidence,
                            "description": threat.description
                        })
                
                # حساب مستوى المخاطرة
                alarming_hosts[host_ip]["risk_level"] = self.calculate_risk_level(
                    alarming_hosts[host_ip]["threats"],
                    alarming_hosts[host_ip]["flow_count"],
                    alarming_hosts[host_ip]["total_bytes"],
                    alarming_hosts[host_ip]["total_packets"]
                )
            
            # تحويل القاموس إلى قائمة
            alarming_hosts = list(alarming_hosts.values())
            # ترتيب حسب مستوى المخاطرة أولاً، ثم عدد الحوادث
            alarming_hosts.sort(key=lambda x: (
                {"critical": 4, "high": 3, "medium": 2, "low": 1}[x["risk_level"]],
                x["incidents"]
            ), reverse=True)

            # 4. Attack Vectors - ناقلات الهجوم
            attack_vectors = []
            attack_stats = threats.values('category').annotate(
                count=Count('id'),
                avg_confidence=Avg('confidence')
            ).order_by('-count')[:5]
            
            for stat in attack_stats:
                attack_vectors.append({
                    "name": stat['category'],
                    "value": stat['count'],
                    "details": {
                        "type": stat['category'],
                        "count": stat['count'],
                        "confidence": round(stat['avg_confidence'], 2)
                    }
                })

            # 5. Top Threats - أهم التهديدات
            top_threats = {
                "categories": [],
                "data": []
            }
            
            threat_categories = threats.values('category').annotate(
                count=Count('id'),
                avg_confidence=Avg('confidence')
            ).order_by('-count')[:5]
            
            for category in threat_categories:
                top_threats["categories"].append(category['category'])
                top_threats["data"].append({
                    "count": category['count'],
                    "confidence": round(category['avg_confidence'], 2)
                })

            # 6. Suspicious IPs - عناوين IP المشبوهة
            suspicious_ips = {
                "recent": {}
            }
            
            recent_suspicious = SuspiciousIP.objects.filter(
                date__gte=last_week
            ).order_by('-date')
            
            for ip in recent_suspicious:
                if ip.ip_address not in suspicious_ips["recent"]:
                    related_threats = []
                    if ip.threat:
                        related_threats = [{
                            "category": ip.threat.category,
                            "confidence": ip.threat.confidence,
                            "description": ip.threat.description
                        }]
                    
                    # حساب مستوى المخاطرة
                    risk_level = self.calculate_risk_level(
                        related_threats,
                        1,  # flow_count
                        ip.threat.flow.total_bytes if ip.threat and ip.threat.flow else 0,
                        ip.threat.flow.packet_count if ip.threat and ip.threat.flow else 0
                    )
                    
                    suspicious_ips["recent"][ip.ip_address] = {
                        "ip": ip.ip_address,
                        "threat_level": "high" if ip.threat and ip.threat.confidence > 0.8 else "medium",
                        "risk_level": risk_level,
                        "incidents": len(related_threats),
                        "last_seen": ip.date.isoformat(),
                        "threats": related_threats,
                        "reasons": [ip.reason] if ip.reason else [],
                        "dates": [ip.date.isoformat()]
                    }
                else:
                    # تحديث البيانات المجمعة
                    if ip.reason and ip.reason not in suspicious_ips["recent"][ip.ip_address]["reasons"]:
                        suspicious_ips["recent"][ip.ip_address]["reasons"].append(ip.reason)
                    if ip.date.isoformat() not in suspicious_ips["recent"][ip.ip_address]["dates"]:
                        suspicious_ips["recent"][ip.ip_address]["dates"].append(ip.date.isoformat())
                        suspicious_ips["recent"][ip.ip_address]["last_seen"] = ip.date.isoformat()
                    
                    if ip.threat:
                        threat_data = {
                            "category": ip.threat.category,
                            "confidence": ip.threat.confidence,
                            "description": ip.threat.description
                        }
                        if not any(t["category"] == threat_data["category"] and t["confidence"] == threat_data["confidence"] 
                                 for t in suspicious_ips["recent"][ip.ip_address]["threats"]):
                            suspicious_ips["recent"][ip.ip_address]["threats"].append(threat_data)
                            suspicious_ips["recent"][ip.ip_address]["incidents"] += 1
                    
                    # تحديث مستوى المخاطرة
                    suspicious_ips["recent"][ip.ip_address]["risk_level"] = self.calculate_risk_level(
                        suspicious_ips["recent"][ip.ip_address]["threats"],
                        len(suspicious_ips["recent"][ip.ip_address]["dates"]),
                        sum(t.flow.total_bytes for t in threats.filter(flow__src_ip=ip.ip_address)) if ip.threat else 0,
                        sum(t.flow.packet_count for t in threats.filter(flow__src_ip=ip.ip_address)) if ip.threat else 0
                    )
            
            # تحويل القاموس إلى قائمة وترتيبها
            suspicious_ips["recent"] = list(suspicious_ips["recent"].values())
            # ترتيب حسب مستوى المخاطرة أولاً، ثم عدد الحوادث
            suspicious_ips["recent"].sort(key=lambda x: (
                {"critical": 4, "high": 3, "medium": 2, "low": 1}[x["risk_level"]],
                x["incidents"]
            ), reverse=True)
            # أخذ أول 5 عناصر فقط
            suspicious_ips["recent"] = suspicious_ips["recent"][:5]

            # تجميع البيانات النهائية
            response_data = {
                "data_analysis": {
                    "threat_trends": threat_trends,
                    "network_traffic": network_traffic,
                    "alarming_hosts": alarming_hosts,
                    "attack_vectors": attack_vectors,
                    "top_threats": top_threats,
                    "suspicious_ips": suspicious_ips
                },
                "user_data": user_data
            }
            
            # تخزين مؤقت للبيانات
            cache.set(cache_key, response_data, 30 * 60)  # 30 دقيقة

            return Response(response_data)
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)