from django.urls import path
from . import views

urlpatterns = [
    path('role_main', views.role_main, name='role_main')
    # path('role_output', views.role_output, name='role_output')
]