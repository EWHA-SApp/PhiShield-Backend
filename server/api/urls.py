from django.urls import path, include
from api.views import PhishingCheckView
from rest_framework.routers import DefaultRouter

app_name = 'api'

router = DefaultRouter()


urlpatterns = [
    path('', include(router.urls)),
    path('phishing-check', PhishingCheckView.as_view(), name='phishing-check'),
]
