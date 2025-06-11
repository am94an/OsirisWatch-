import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import get_user_model
from .models import Notification

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # التحقق من المصادقة
        if isinstance(self.scope["user"], AnonymousUser):
            await self.close()
            return

        # الانضمام إلى مجموعة المستخدم
        self.user = self.scope["user"]
        self.room_group_name = f"user_{self.user.id}_notifications"
        
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        
        await self.accept()

    async def disconnect(self, close_code):
        # مغادرة مجموعة المستخدم
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        # معالجة الرسائل الواردة
        try:
            text_data_json = json.loads(text_data)
            message = text_data_json.get('message', '')
            
            # إرسال رسالة تأكيد
            await self.send(text_data=json.dumps({
                'type': 'echo',
                'message': message
            }))
        except json.JSONDecodeError:
            pass

    async def notification_message(self, event):
        # إرسال التنبيه إلى المستخدم
        await self.send(text_data=json.dumps({
            'type': 'notification',
            'message': event['message'],
            'notification': event['notification']
        })) 