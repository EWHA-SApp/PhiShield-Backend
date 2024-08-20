# api/serializers.py

from rest_framework import serializers
from .models import Email

class EmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Email
        fields = ['title', 'sender', 'body', 'whole_data','is_phishing', 'file']