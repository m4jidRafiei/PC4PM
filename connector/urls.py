from django.urls import path
from . import views

urlpatterns = [
    path('connector_main', views.connector_main, name='connector_main')
]