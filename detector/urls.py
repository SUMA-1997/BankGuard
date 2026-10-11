
from django.urls import path
from . import views

urlpatterns = [

    # Home / Email Analysis
    path("", views.home, name="home"),

    # Detector
    path("detector/", views.home, name="detector"),

    # Registration
    path("register/", views.register_view, name="register"),

    # Login
    path("login/", views.login_view, name="login"),

    # Logout
    path("logout/", views.logout_view, name="logout"),

    # Analysis History
    path("history/", views.history, name="history"),

    # Dashboard
    path("dashboard/", views.dashboard, name="dashboard"),

]