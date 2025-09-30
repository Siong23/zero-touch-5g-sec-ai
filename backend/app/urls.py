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
    path('get_automation_status/', views.get_automation_status, name='get_automation_status'),
    path('clear_automation_results/', views.clear_automation_results, name='clear_automation_results'),
    path('start_attack/', views.start_attack, name='start_attack'),
    path('favicon.ico', favicon_view, name='favicon'),
    path('get_live_flows/', views.get_live_flows, name='get_live_flows'),
    path('get_flow_status/', views.get_flow_status, name='get_flow_status'),
    path('reset_flow_stats/', views.reset_flow_stats, name='reset_flow_status'),
    path('.well-known/appspecific/com.chrome.devtools.json', views.chrome_devtools_json, name='chrome_devtools_json')
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)