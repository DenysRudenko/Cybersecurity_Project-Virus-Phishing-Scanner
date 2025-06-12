from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from scanner import views as scanner_views
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('url-scan/', views.url_scanner, name='url_scanner'),
    path('file-scan/', views.file_scanner, name='file_scanner'),
    path('register/', scanner_views.register_view, name='register'),
    path('login/', auth_views.LoginView.as_view(template_name='scanner/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('', scanner_views.home, name='home'),
    path("dashboard/", views.dashboard, name="dashboard"),
]

