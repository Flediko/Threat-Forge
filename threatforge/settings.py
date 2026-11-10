"""
Django settings for ThreatForge project.
"""

import os
from pathlib import Path

try:
    import pymysql
    pymysql.install_as_MySQLdb()
    HAVE_PYMYSQL = True
except ImportError:
    HAVE_PYMYSQL = False

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "threatforge-cyber-sec-key-btech-final-year-project"
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "web",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "web.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "web.context_processors.auth_user_context",
            ],
        },
    },
]

WSGI_APPLICATION = "threatforge.wsgi.application"

USE_SQLITE = os.environ.get("USE_SQLITE", "0") == "1"
if not USE_SQLITE and HAVE_PYMYSQL:
    try:
        conn = pymysql.connect(
            host=os.environ.get("TF_MYSQL_HOST", "127.0.0.1"),
            port=int(os.environ.get("TF_MYSQL_PORT", "3306")),
            user=os.environ.get("TF_MYSQL_USER", "root"),
            password=os.environ.get("TF_MYSQL_PASSWORD", ""),
            connect_timeout=1,
        )
        conn.close()
    except Exception:
        USE_SQLITE = True
else:
    USE_SQLITE = True

if USE_SQLITE:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.mysql",
            "NAME": os.environ.get("TF_MYSQL_DB", "threatforge"),
            "USER": os.environ.get("TF_MYSQL_USER", "root"),
            "PASSWORD": os.environ.get("TF_MYSQL_PASSWORD", ""),
            "HOST": os.environ.get("TF_MYSQL_HOST", "127.0.0.1"),
            "PORT": os.environ.get("TF_MYSQL_PORT", "3306"),
            "OPTIONS": {
                "charset": "utf8mb4",
                "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
            },
        }
    }

AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Configure SMTP via TF_EMAIL_HOST, TF_EMAIL_PORT, TF_EMAIL_HOST_USER,
# TF_EMAIL_HOST_PASSWORD, and TF_EMAIL_USE_TLS. Development defaults to the
# console backend so reset links are visible to the developer without a mail server.
EMAIL_BACKEND = os.environ.get(
    "TF_EMAIL_BACKEND",
    "django.core.mail.backends.console.EmailBackend" if DEBUG else "django.core.mail.backends.smtp.EmailBackend",
)
EMAIL_HOST = os.environ.get("TF_EMAIL_HOST", "localhost")
EMAIL_PORT = int(os.environ.get("TF_EMAIL_PORT", "25"))
EMAIL_HOST_USER = os.environ.get("TF_EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("TF_EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = os.environ.get("TF_EMAIL_USE_TLS", "0") == "1"
DEFAULT_FROM_EMAIL = os.environ.get("TF_DEFAULT_FROM_EMAIL", "ThreatForge <no-reply@localhost>")

# Session settings
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_SAVE_EVERY_REQUEST = True
