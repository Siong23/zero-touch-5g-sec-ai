from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.http import HttpResponse
from django.urls import path, include
from . import views

def favicon_view(request):
    return HttpResponse(status=204)

urlpatterns = [
    path('', views.home, name='home'),
    path('start_ml/', views.start_ml, name='start_ml'),
    path('stop_ml/', views.stop_ml, name='stop_ml'),
    path('receive_network_data/', views.receive_network_data, name='receive_network_data'),
    path('start_attack/', views.start_attack, name='start_attack'),
    path('stop_attack/', views.stop_attack, name='stop_attack'),
    path('start_capture/', views.NetworkTrafficCapture.start_capture, name='start_capture'),
    path('stop_capture', views.NetworkTrafficCapture.stop_capture, name='stop_capture'),

    path('favicon.ico', favicon_view, name='favicon'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)