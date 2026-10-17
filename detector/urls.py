
from django.urls import path, reverse_lazy
from django.contrib.auth import views as auth_views

from . import views


urlpatterns = [

    # ==================================================
    # HOME / EMAIL PHISHING ANALYSIS
    # ==================================================

    path(
        "",
        views.home,
        name="home",
    ),

    # ==================================================
    # DETECTOR
    # ==================================================

    path(
        "detector/",
        views.home,
        name="detector",
    ),

    # ==================================================
    # USER REGISTRATION
    # Username + Email + Password
    # ==================================================

    path(
        "register/",
        views.register_view,
        name="register",
    ),

    # ==================================================
    # LOGIN USING EMAIL ADDRESS AND PASSWORD
    # ==================================================

    path(
        "login/",
        views.login_view,
        name="login",
    ),

    # ==================================================
    # LOGOUT
    # ==================================================

    path(
        "logout/",
        views.logout_view,
        name="logout",
    ),

    # ==================================================
    # FORGOT PASSWORD
    # ENTER REGISTERED EMAIL ADDRESS
    # ==================================================

    path(
        "password-reset/",
        auth_views.PasswordResetView.as_view(
            template_name="detector/password_reset.html",

            email_template_name=(
                "detector/registration/password_reset_email.html"
            ),

            subject_template_name=(
                "detector/registration/password_reset_subject.txt"
            ),

            success_url=reverse_lazy("password_reset_done"),
        ),
        name="password_reset",
    ),

    # ==================================================
    # PASSWORD RESET EMAIL SENT
    # ==================================================

    path(
        "password-reset/done/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="detector/password_reset_done.html",
        ),
        name="password_reset_done",
    ),

    # ==================================================
    # SET NEW PASSWORD
    # ==================================================

    path(
        "reset/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="detector/password_reset_confirm.html",

            success_url=reverse_lazy("password_reset_complete"),
        ),
        name="password_reset_confirm",
    ),

    # ==================================================
    # PASSWORD RESET COMPLETED
    # ==================================================

    path(
        "reset/done/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="detector/password_reset_complete.html",
        ),
        name="password_reset_complete",
    ),

    # ==================================================
    # USER-SPECIFIC ANALYSIS HISTORY
    # ==================================================

    path(
        "history/",
        views.history,
        name="history",
    ),

    # ==================================================
    # USER-SPECIFIC DASHBOARD
    # ==================================================

    path(
        "dashboard/",
        views.dashboard,
        name="dashboard",
    ),

]
