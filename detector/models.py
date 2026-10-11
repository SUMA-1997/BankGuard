from django.db import models
from django.contrib.auth.models import User


class EmailAnalysis(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="email_analyses",
        null=True,
        blank=True
    )

    email_text = models.TextField()
    risk_score = models.IntegerField()
    risk_level = models.CharField(max_length=20)
    reasons = models.TextField(blank=True)
    recommendation = models.TextField(blank=True)
    analyzed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.risk_level} - {self.risk_score}"
