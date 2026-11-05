"""
Root URL Configuration for ThreatForge Django Project.
"""

from django.urls import include, path

urlpatterns = [
    path("", include("web.urls")),
]
