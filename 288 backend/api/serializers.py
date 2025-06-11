from rest_framework import serializers
from django.contrib.auth.models import User
from accounts.models import UserProfile, Notification
from .models import (
    Threat, NetworkFlow, SuspiciousIP, UserLogin, 
    Agent, AttackType, Alert, Report, System_Settings
)

# Authentication serializers
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128, write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            # Check if user exists
            if not User.objects.filter(username=username).exists():
                print(f"User {username} does not exist")
                raise serializers.ValidationError("User does not exist.")
            return data
        else:
            print("Missing username or password")
            raise serializers.ValidationError("Username and password are required.")

class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'confirm_password']

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')  
        user = User(
            username=validated_data['username'],
            email=validated_data['email']
        )
        user.set_password(validated_data['password']) 
        user.save()
        return user

class ForgetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is not registered.")
        return value

class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

# User related serializers
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_active', 'date_joined']

class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = ['user', 'role', 'profile_image']

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = [
            'id', 
            'message', 
            'notification_type', 
            'is_read', 
            'sent_at',
            'alert',
            'threat',
            'user',
            'priority'
        ]

    def to_representation(self, instance):
        print(f"=== Serializing notification {instance.id} ===")
        print(f"Instance data:")
        print(f"  - Message: {instance.message}")
        print(f"  - Type: {instance.notification_type}")
        print(f"  - Is Read: {instance.is_read}")
        print(f"  - Sent At: {instance.sent_at}")
        print(f"  - Alert: {instance.alert}")
        print(f"  - Threat: {instance.threat}")
        print(f"  - User: {instance.user}")
        print(f"  - Priority: {instance.priority}")
        
        data = super().to_representation(instance)
        print(f"Serialized data: {data}")
        return data

# Security data serializers
class AgentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Agent
        fields = ['id', 'name', 'description']

class AttackTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackType
        fields = ['id', 'type', 'description']

class NetworkFlowSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkFlow
        fields = [
            'flow_id', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
            'protocol', 'start_time', 'end_time', 'packet_count',
            'total_bytes', 'duration', 'avg_packet_size', 'std_packet_size',
            'min_packet_size', 'max_packet_size', 'bytes_per_second',
            'packets_per_second', 'threat_level', 'threats', 'anomalies',
            'protocol_analysis'
        ]

class AlertSerializer(serializers.ModelSerializer):
    flow = NetworkFlowSerializer(read_only=True)
    
    class Meta:
        model = Alert
        fields = [
            'id', 'flow', 'severity', 'status', 'description',
            'threat_type', 'source', 'created_at', 'updated_at',
            'assigned_to'
        ]

class ThreatSerializer(serializers.ModelSerializer):
    flow = NetworkFlowSerializer(read_only=True)
    
    class Meta:
        model = Threat
        fields = [
            'id', 'flow', 'category', 'description',
            'confidence', 'created_at', 'updated_at'
        ]

class NetworkAnalysisSerializer(serializers.Serializer):
    time_range = serializers.CharField()
    total_flows = serializers.IntegerField()
    total_bytes = serializers.IntegerField()
    threat_distribution = serializers.ListField()
    top_sources = serializers.ListField()
    protocol_distribution = serializers.ListField()
    recent_alerts = AlertSerializer(many=True)

class ThreatAnalysisSerializer(serializers.Serializer):
    threat_categories = serializers.ListField()
    threat_trends = serializers.ListField()
    high_confidence_threats = ThreatSerializer(many=True)

class SuspiciousIPSerializer(serializers.ModelSerializer):
    alert = AlertSerializer(read_only=True)
    alert_id = serializers.PrimaryKeyRelatedField(
        queryset=Alert.objects.all(), 
        source='alert', 
        write_only=True,
        required=False
    )
    threat = ThreatSerializer(read_only=True)
    threat_id = serializers.PrimaryKeyRelatedField(
        queryset=Threat.objects.all(), 
        source='threat', 
        write_only=True,
        required=False
    )
    
    class Meta:
        model = SuspiciousIP
        fields = [
            'id', 'ip_address', 'date', 'reason',
            'alert', 'alert_id', 'threat', 'threat_id'
        ]

class UserLoginSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = UserLogin
        fields = ['id', 'user', 'timestamp']

class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = [
            'id', 'user', 'alert', 'threat', 'content',
            'created_at', 'report_status'
        ]
        read_only_fields = ['id', 'created_at']

class SystemSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = System_Settings
        fields = [
            'id', 'system_name', 'version', 'maintenance_mode',
            'max_login_attempts', 'notification_settings'
        ]

