from django.urls import path
from . import views

urlpatterns = [
    path('tlkc_main', views.tlkc_main, name='tlkc_main')
]