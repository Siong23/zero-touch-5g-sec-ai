from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.endpoints.views import EndpointViewSet, MLAlgorithmViewSet, MLAlgorithmStatusViewSet, MLRequestViewSet

# Create REST API routers to the database model

router = DefaultRouter(trailing_slash=False)
router.register(r"endpoints", EndpointViewSet, basename="endpoints")
router.register(r"mlalgorithm", MLAlgorithmViewSet, basename="mlalgorithm")
router.register(r"mlalgorithmstatus", MLAlgorithmStatusViewSet, basename="mlalgorithmstatus")
router.register(r"mlrequest", MLRequestViewSet, basename="mlrequest")

urlpatterns = [path(r"api/v1/", include(router.urls)),]
