from django.urls import path, re_path
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from .consumers import PredictConsumer
from . import consumers

websocket_urlpatterns = [
    path('ws/predict/', PredictConsumer.as_asgi()),
    re_path(r'ws/network_sessions/$', consumers.NetworkSessionConsumer.as_asgi()),
    re_path(r'ws/notifications/$', consumers.NotificationConsumer.as_asgi()),
]

application = ProtocolTypeRouter({
    'websocket': AuthMiddlewareStack(
        URLRouter(
            websocket_urlpatterns
        )
    ),
})
