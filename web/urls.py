"""
URL routing for ThreatForge web app.
"""

from django.urls import path
from . import views

urlpatterns = [
    path("", views.landing_view, name="home"),
    path("scan/", views.scan_view, name="scan"),
    path("profile/", views.profile_view, name="profile"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("history/", views.history_view, name="history"),
    path("admin-panel/", views.admin_panel_view, name="admin_panel"),

    # API endpoints
    path("api/scan/run/", views.api_run_scan, name="api_run_scan"),
    path("api/scan/<int:scan_id>/", views.api_scan_detail, name="api_scan_detail"),
    path("api/scan/<int:scan_id>/delete/", views.api_delete_scan, name="api_delete_scan"),
    path("api/admin/user-action/", views.admin_user_action, name="admin_user_action"),
    path("api/user/change-password/", views.api_change_password, name="api_change_password"),

    # Downloads
    path("report/<int:scan_id>/pdf/", views.download_pdf_view, name="download_pdf"),
    path("report/<int:scan_id>/csv/", views.download_csv_view, name="download_csv"),
]

