from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('start_ml/', views.start_ml, name='start_ml'),
    path('stop_ml/', views.stop_ml, name='stop_ml')
]