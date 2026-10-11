from django.contrib import admin
from .models import EmailAnalysis


@admin.register(EmailAnalysis)
class EmailAnalysisAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "risk_score",
        "risk_level",
        "analyzed_at",
    )

    list_filter = (
        "risk_level",
        "analyzed_at",
    )

    search_fields = (
        "email_text",
        "risk_level",
        "recommendation",
    )

    ordering = (
        "-analyzed_at",
    )

    readonly_fields = (
        "analyzed_at",
    )

    fieldsets = (
        (
            "Analysis Information",
            {
                "fields": (
                    "email_text",
                    "risk_score",
                    "risk_level",
                    "reasons",
                    "recommendation",
                    "analyzed_at",
                )
            },
        ),
    )