from django.contrib import admin
from .models import EmailAnalysis


# BankGuard Admin Branding
admin.site.site_header = "BankGuard | Email Security Administration"
admin.site.site_title = "BankGuard Admin"
admin.site.index_title = "Welcome to BankGuard Project"


@admin.register(EmailAnalysis)
class EmailAnalysisAdmin(admin.ModelAdmin):

    # Columns displayed in the admin list page
    list_display = (
        "id",
        "user",
        "risk_score",
        "risk_level",
        "analyzed_at",
    )

    # Filters
    list_filter = (
        "risk_level",
        "analyzed_at",
    )

    # Search fields (email content is not searchable)
    search_fields = (
        "risk_level",
        "recommendation",
        "reasons",
        "user__username",
        "user__email",
    )

    # Show latest analyses first
    ordering = (
        "-analyzed_at",
    )

    # Read-only analysis results
    readonly_fields = (
        "id",
        "user",
        "risk_score",
        "risk_level",
        "reasons",
        "recommendation",
        "analyzed_at",
    )

    # Email content is intentionally excluded
    exclude = (
        "email_text",
    )

    # Organize the record detail page
    fieldsets = (
        (
            "Analysis Information",
            {
                "fields": (
                    "id",
                    "user",
                    "risk_score",
                    "risk_level",
                    "reasons",
                    "recommendation",
                    "analyzed_at",
                )
            },
        ),
    )

    # Prevent adding analysis records manually
    def has_add_permission(self, request):
        return False