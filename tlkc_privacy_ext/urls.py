from django.urls import path
from . import views

urlpatterns = [
    path('tlkc_ext_main', views.tlkc_ext_main, name='tlkc_ext_main')
]