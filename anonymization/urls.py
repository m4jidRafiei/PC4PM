from django.urls import path
from . import views

urlpatterns = [
    path('anonymization_main', views.anonymization_main, name='anonymization_main')
    # path('role_output', views.role_output, name='role_output')
]