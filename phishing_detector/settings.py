
"""
Django settings for phishing_detector project.
BankGuard - Email Phishing Detection System
"""

from pathlib import Path


# ==================================================
# BASE DIRECTORY
# ==================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# ==================================================
# SECURITY SETTINGS
# ==================================================

SECRET_KEY = 'django-insecure-y509iv410uthfj@*+69m2t_b*px*$0h)tip^%#ace!5%o09os1'

DEBUG = True

ALLOWED_HOSTS = []


# ==================================================
# APPLICATION DEFINITION
# ==================================================

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # BankGuard Application
    'detector',
]


# ==================================================
# MIDDLEWARE
# ==================================================

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]


# ==================================================
# URL CONFIGURATION
# ==================================================

ROOT_URLCONF = 'phishing_detector.urls'


# ==================================================
# TEMPLATE CONFIGURATION
# ==================================================

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',

        # Uses templates inside installed Django apps
        'DIRS': [BASE_DIR / 'templates'],

        'APP_DIRS': True,

        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


# ==================================================
# WSGI CONFIGURATION
# ==================================================

WSGI_APPLICATION = 'phishing_detector.wsgi.application'


# ==================================================
# DATABASE CONFIGURATION
# Preserve existing SQLite database
# ==================================================

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# ==================================================
# PASSWORD VALIDATION
# ==================================================

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': (
            'django.contrib.auth.password_validation.'
            'UserAttributeSimilarityValidator'
        ),
    },
    {
        'NAME': (
            'django.contrib.auth.password_validation.'
            'MinimumLengthValidator'
        ),
    },
    {
        'NAME': (
            'django.contrib.auth.password_validation.'
            'CommonPasswordValidator'
        ),
    },
    {
        'NAME': (
            'django.contrib.auth.password_validation.'
            'NumericPasswordValidator'
        ),
    },
]


# ==================================================
# INTERNATIONALIZATION
# ==================================================

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_TZ = True


# ==================================================
# STATIC FILES
# ==================================================

STATIC_URL = 'static/'


# ==================================================
# AUTHENTICATION AND LOGIN REDIRECTS
# ==================================================

LOGIN_URL = 'login'

LOGIN_REDIRECT_URL = 'home'

LOGOUT_REDIRECT_URL = 'login'


# ==================================================
# EMAIL CONFIGURATION
# Development: print reset email in terminal
# ==================================================

EMAIL_BACKEND = (
    'django.core.mail.backends.console.EmailBackend'
)

DEFAULT_FROM_EMAIL = 'BankGuard Support <noreply@bankguard.local>'


# ==================================================
# PASSWORD RESET CONFIGURATION
# ==================================================

PASSWORD_RESET_TIMEOUT = 3600  # Reset link valid for 1 hour


# ==================================================
# DEFAULT PRIMARY KEY
# ==================================================

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
