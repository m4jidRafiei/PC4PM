from django.urls import path
from . import views

urlpatterns = [
    path('privacy_analysis_main', views.privacy_analysis_main, name='privacy_analysis')
    # path('role_output', views.role_output, name='role_output')
]
