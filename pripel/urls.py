from django.urls import path
from . import views

urlpatterns = [
    path('pripel_main', views.pripel_main, name='pripel_main')
]