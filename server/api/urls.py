from django.urls import path
from api.views import PhishingCheckView


urlpatterns = [
    path('phishing-check/', PhishingCheckView.as_view(), name='phishing-check'),
]
