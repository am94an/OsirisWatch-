from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .models import (
    Threat, NetworkFlow, SuspiciousIP, UserLogin, 
    Agent, AttackType, Alert, Notification, Report, System_Settings
)
from accounts.models import UserProfile
from datetime import datetime, timedelta
from django.utils import timezone

class AuthenticationTests(APITestCase):
    def setUp(self):
        self.signup_url = reverse('signup')
        self.login_url = reverse('login')
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpassword123',
            'confirm_password': 'testpassword123'
        }

    def test_signup(self):
        response = self.client.post(self.signup_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username='testuser').exists())
        
    def test_login(self):
        # Create a user first
        user = User.objects.create_user(
            username='testuser', 
            email='test@example.com', 
            password='testpassword123'
        )
        UserProfile.objects.create(user=user, role='User')
        
        # Try to login
        login_data = {
            'username': 'testuser',
            'password': 'testpassword123'
        }
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

class DashboardTests(APITestCase):
    def setUp(self):
        # Create a user
        self.user = User.objects.create_user(
            username='testuser', 
            email='test@example.com', 
            password='testpassword123'
        )
        UserProfile.objects.create(user=self.user, role='Admin')
        
        # Authenticate
        self.client = APIClient()
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        # Create sample data
        self.agent = Agent.objects.create(name='Test Agent')
        self.attack_type = AttackType.objects.create(type='SQL Injection')
        
        # Create network flow
        self.flow = NetworkFlow.objects.create(
            source_ip='192.168.1.1',
            destination_ip='192.168.1.2',
            source_port=1234,
            destination_port=80,
            protocol='TCP',
            timestamp=timezone.now(),
            duration=timedelta(seconds=10),
            packet_count=100,
            byte_count=1000,
            label='normal',
            level='low',
            agent=self.agent
        )
        
        # Create alert
        self.alert = Alert.objects.create(
            flow=self.flow,
            alert_type='Connection Attempt',
            severity='medium',
            description='Suspicious connection attempt detected',
            alert_time=timezone.now(),
            attack_type=self.attack_type
        )
        
        # Create threat
        self.threat = Threat.objects.create(
            alert=self.alert,
            threat_name='Potential SQL Injection',
            threat_level='high',
            threat_source='External',
            response_action='Block IP',
            attack_type=self.attack_type
        )
        
        # URL
        self.dashboard_url = reverse('dashboard')
        self.data_analysis_url = reverse('data-analysis')

    def test_dashboard_access(self):
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('dashboard', response.data)
        
    def test_data_analysis_access(self):
        response = self.client.get(self.data_analysis_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('data_analysis', response.data)

class NetworkFlowAPITests(APITestCase):
    def setUp(self):
        # Create and authenticate user
        self.user = User.objects.create_user(
            username='testuser', email='test@example.com', password='testpassword123'
        )
        UserProfile.objects.create(user=self.user, role='Admin')
        self.client = APIClient()
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        # URLs
        self.network_flows_url = reverse('network_flows')
        
        # Create sample data
        self.agent = Agent.objects.create(name='Test Agent')

    def test_create_network_flow(self):
        data = {
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'source_port': 1234,
            'destination_port': 80,
            'protocol': 'TCP',
            'packet_count': 100,
            'byte_count': 1000,
            'label': 'normal',
            'level': 'low',
            'agent_id': self.agent.id
        }
        
        response = self.client.post(self.network_flows_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(NetworkFlow.objects.count(), 1)
        
    def test_list_network_flows(self):
        # Create some flows first
        NetworkFlow.objects.create(
            source_ip='192.168.1.1',
            destination_ip='192.168.1.2',
            source_port=1234,
            destination_port=80,
            protocol='TCP',
            timestamp=timezone.now(),
            duration=timedelta(seconds=10),
            packet_count=100,
            byte_count=1000,
            label='normal',
            level='low'
        )
        
        response = self.client.get(self.network_flows_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

class AlertAPITests(APITestCase):
    def setUp(self):
        # Create and authenticate user
        self.user = User.objects.create_user(
            username='testuser', email='test@example.com', password='testpassword123'
        )
        UserProfile.objects.create(user=self.user, role='Admin')
        self.client = APIClient()
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        # URLs
        self.alerts_url = reverse('alerts')
        
        # Create sample data
        self.flow = NetworkFlow.objects.create(
            source_ip='192.168.1.1',
            destination_ip='192.168.1.2',
            source_port=1234,
            destination_port=80,
            protocol='TCP',
            timestamp=timezone.now(),
            duration=timedelta(seconds=10),
            packet_count=100,
            byte_count=1000,
            label='normal',
            level='low'
        )
        
        self.attack_type = AttackType.objects.create(type='SQL Injection')

    def test_create_alert(self):
        data = {
            'flow_id': self.flow.id,
            'alert_type': 'Suspicious Activity',
            'severity': 'high',
            'description': 'Potential malicious activity detected',
            'attack_type_id': self.attack_type.id
        }
        
        response = self.client.post(self.alerts_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Alert.objects.count(), 1)
        
    def test_list_alerts(self):
        # Create an alert first
        Alert.objects.create(
            flow=self.flow,
            alert_type='Connection Attempt',
            severity='medium',
            description='Suspicious connection attempt detected',
            alert_time=timezone.now(),
            attack_type=self.attack_type
        )
        
        response = self.client.get(self.alerts_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
