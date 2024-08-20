# api/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import EmailSerializer
from .models import Email

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

class PhishingCheckView(APIView):
    @swagger_auto_schema(
        operation_description="Check if the email content is phishing",
        request_body=EmailSerializer,
        responses={200: openapi.Response('result', EmailSerializer)}
    )
    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        if serializer.is_valid():
            email_data = serializer.validated_data

            # 간단한 피싱 판별 로직 (가상의 예시)
            email_body = email_data['body']
            is_phishing = self.is_phishing(email_body)

            # Email 객체 생성 및 저장
            email_instance = Email(
                title=email_data.get('title'),
                sender=email_data.get('sender'),
                body=email_body,
                is_phishing=is_phishing
            )
            email_instance.save()

            # 결과를 반환
            return Response({'is_phishing': is_phishing}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def is_phishing(self, text):
        # 간단한 텍스트 기반 피싱 판별 (예시)
        # 실제로는 훈련된 머신러닝/딥러닝 모델을 사용해야 함
        phishing_keywords = ['urgent', 'click', 'login', 'verify']
        return any(keyword in text.lower() for keyword in phishing_keywords)
