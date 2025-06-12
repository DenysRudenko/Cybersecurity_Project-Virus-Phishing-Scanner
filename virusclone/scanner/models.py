from django.db import models
from django.contrib.auth.models import User

class Scan(models.Model):
    SCAN_TYPE_CHOICES = [
        ('URL', 'URL'),
        ('File', 'File'),
        ('Email', 'Email'),
    ]

    RESULT_CHOICES = [
        ('Clean', 'Clean'),
        ('Malware', 'Malware'),
        ('Phishing', 'Phishing'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    type = models.CharField(max_length=10, choices=SCAN_TYPE_CHOICES)
    item = models.CharField(max_length=255)
    result = models.CharField(max_length=20, choices=RESULT_CHOICES)

    def __str__(self):
        return f"{self.timestamp} - {self.item}"
