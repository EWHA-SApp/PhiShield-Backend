from django.db import models

# Create your models here.

class Email(models.Model):
    title = models.CharField(max_length=500, null=True)
    sender = models.EmailField(null=True)
    body = models.TextField(null=True)
    whole_data = models.TextField(null=True)
    is_phishing = models.BooleanField(null=True)
    file = models.FileField(null=True, blank=True, upload_to='uploads/')
    report = models.TextField(null=True, blank=True)