from rest_framework import serializers
from apps.endpoints.models import Endpoint, MLAlgorithm, MLAlgorithmStatus, MLRequest

# Serializers help with packing and unpacking database objects into JSON objects
# Read-only fields to create and modify objects on the server side only

class EndpointSerializer(serializers.ModelSerializer):
    class Meta:
        model = Endpoint
        read_only_fields = ("id", "name", "created_at")
        fields = read_only_fields

class MLAlgorithmSerializer(serializers.ModelSerializer):
    current_status = serializers.SerializerMethodField(read_only=True)

    def get_current_status(self, mlalgorithm):
        return MLAlgorithmStatus.objects.filter(parent_mlalgorithm=mlalgorithm).latest('created_at').status
    
    class Meta:
        model = MLAlgorithm
        # 'current_status' represents the latest status of ML algorithm
        read_only_fields = ("id", "name", "description", "code", "version", "created_at", "parent_endpoint", "current_status")
        fields = read_only_fields

class MLAlgorithmStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = MLAlgorithmStatus
        read_only_fields = ("id", "active")
        # 'status', 'created_by', 'created_at', "parent_mlalgorithm" to set algorithm status by REST API
        fields = ("id", "active", "status", "created_by", "created_at", "parent_mlalgorithm")

class MLRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = MLRequest
        read_only_fields = ("id", "input_data", "full_response", "response", "created_at", "parent_mlalgorithm")
        # 'feedback' to provide feedback regarding detections to the server
        fields = ("id", "input_data", "full_response", "response", "feedback", "created_at", "parent_mlalgorithm")

