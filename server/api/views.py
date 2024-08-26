# api/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import EmailSerializer
from .models import Email

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from python_files.phishing_detection import create_report

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

            title=email_data.get('title')
            sender=email_data.get('sender')
            body=email_data.get('body')
            whole_data=email_data.get('whole_data')
            file=email_data.get('file')
            report, result=create_report(sender, title, body, whole_data, file)

            # Email 객체 생성 및 저장
            email_instance = Email(
                title=title,
                sender=sender,
                body=body,
                whole_data=whole_data,
                file=file,
                is_phishing=result,
                report=report
            )
            email_instance.save()

            # 결과 반환
            return Response({'report': report, 'is_phishing': result}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def is_phishing(psender, ptitle, pcontent, pwhole, pfile_ex):
        # models/phishing_check.py 파일에 있는 함수로 데이터 전달
        return create_report(psender, ptitle, pcontent, pwhole, pfile_ex)