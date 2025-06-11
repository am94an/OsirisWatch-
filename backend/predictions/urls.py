from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import create_network_flow, NetworkSessionCreateView, network_session_list, network_session_detail, create_attack_type, create_agent, create_alert

urlpatterns = [
    # Authentication endpoints (already in api/urls.py)
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Protected endpoints
    path('create_network_flow/', create_network_flow, name='create_network_flow'),
    path('network_sessions/', network_session_list, name='network_session_list'),
    path('network_sessions/<int:pk>/', network_session_detail, name='network_session_detail'),
    path('network_sessions/create/', NetworkSessionCreateView.as_view(), name='network_session_create'),
    path('create_attack_type/', create_attack_type, name='create_attack_type'),
    path('create_agent/', create_agent, name='create_agent'),
    path('create_alert/', create_alert, name='create_alert'),
]