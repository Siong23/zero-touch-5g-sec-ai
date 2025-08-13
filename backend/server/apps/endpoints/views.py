import json

from django.shortcuts import render
from django.db import transaction
from numpy.random import rand

from rest_framework import viewsets, mixins, views, status
from rest_framework.response import Response
from rest_framework.exceptions import APIException
from apps.endpoints.models import Endpoint, MLAlgorithm, MLAlgorithmStatus, MLRequest
from apps.endpoints.serializers import EndpointSerializer, MLAlgorithmSerializer, MLAlgorithmStatusSerializer, MLRequestSerializer
from apps.ml.registry import MLRegistry
from server.wsgi import registry

# View allow to retrieve single object or list of objects

class EndpointViewSet(mixins.RetrieveModelMixin, mixins.ListModelMixin, viewsets.GenericViewSet):
    serializer_class = EndpointSerializer
    queryset = Endpoint.objects.all()

class MLAlgorithmViewSet(mixins.RetrieveModelMixin, mixins.ListModelMixin, viewsets.GenericViewSet):
    serializer_class = MLAlgorithmSerializer
    queryset = MLAlgorithm.objects.all()

def deactivate_other_status(instance):
    old_statuses = MLAlgorithmStatus.objects.filter(parent_mlalgorithm=instance.parent_mlalgorithm, created_at_lt=instance.created_at, active=True)

    for i in range(len(old_statuses)):
        old_statuses[i].active = False
        
    MLAlgorithmStatus.objects.bulk_update(old_statuses, ["active"])

class MLAlgorithmStatusViewSet(mixins.RetrieveModelMixin, mixins.ListModelMixin, viewsets.GenericViewSet, mixins.CreateModelMixin):
    serializer_class = MLAlgorithmStatusSerializer
    queryset = MLAlgorithmStatus.objects.all()

    def perform_create(self, serializer):
        try:
            with transaction.atomic():
                instance = serializer.save(active=True)
                deactivate_other_status(instance)

        except Exception as e:
            raise APIException(str(e))

class MLRequestViewSet(mixins.RetrieveModelMixin, mixins.ListModelMixin, viewsets.GenericViewSet, mixins.UpdateModelMixin):
    serializer_class = MLRequestSerializer
    queryset = MLRequest.objects.all()

class PredictView(views.APIView):
    def post(self, request, endpoint_name, format=None):
        try:
            algorithm_status = self.request.query_params.get("status", "active")
            algorithm_version = self.request.query_params.get("version")

            print(f"Looking for endpoint: {endpoint_name}")
            print(f"Algorithm status: {algorithm_status}")
            print(f"Algorithm version: {algorithm_version}")

            algorithm = MLAlgorithm.objects.filter(parent_endpoint__name=endpoint_name).filter(status__status=algorithm_status, status__active=True)

            if algorithm_version is not None:
                algorithm = algorithm.filter(version=algorithm_version)

            print(f"Found {len(algorithm)} algorithm.")

            if len(algorithm) == 0:
                all_endpoints = Endpoint.objects.all()
                all_algorithms = MLAlgorithm.objects.all()
                all_statuses = MLAlgorithmStatus.objects.all()
                
                print(f"Available endpoints: {[e.name for e in all_endpoints]}")
                print(f"Available algorithms: {[(a.name, a.parent_endpoint.name) for a in all_algorithms]}")
                print(f"Available statuses: {[(s.status, s.active, s.parent_mlalgorithm.name) for s in all_statuses]}")

                return Response({"status": "Error", "message": "ML model is not available"}, 
                                status=status.HTTP_400_BAD_REQUEST)
            
            if len(algorithm) != 1 and algorithm_status != "ab_testing":
                return Response({"status": "Error", "message": "Invalid ML model selection"}, 
                                status=status.HTTP_400_BAD_REQUEST)
            
            algorithm_index = 0

            if algorithm_status == "ab_testing":
                algorithm_index = 0 if rand() < 0.5 else 1

            selected_algorithm = algorithm[algorithm_index]
            print(f"Selected algorithm ID: {selected_algorithm.id}")

            # Check if algorithm exists in registry
            if selected_algorithm.id not in registry.endpoints:
                print(f"Algorithm ID {selected_algorithm.id} not found in registry")
                print(f"Available registry keys: {list(registry.endpoints.keys())}")
                return Response(
                    {"status": "Error", "message": "Algorithm not found in registry"}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            algorithm_object = registry.endpoints[selected_algorithm.id]
            prediction = algorithm_object.compute_prediction(request.data)

            label = prediction["label"] if "label" in prediction else "error"

            ml_request = MLRequest(
                input_data=json.dumps(request.data),
                full_response=json.dumps(prediction),
                response=label,
                feedback="",
                parent_mlalgorithm=selected_algorithm,
            )

            ml_request.save()

            prediction["request_id"]=ml_request.id
            return Response(prediction)

        except Exception as e:
            print(f"Exception in PredictView: {str(e)}")
            import traceback
            traceback.print_exc()
            return Response(
                {"status": "Error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
