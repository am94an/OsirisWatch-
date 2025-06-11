# predictions/serializers.py

from rest_framework import serializers
from .models import NetworkSession

class NetworkSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkSession
        fields = '__all__'