from apps.endpoints.models import Endpoint
from apps.endpoints.models import MLAlgorithm
from apps.endpoints.models import MLAlgorithmStatus

# Keep information about available algorithms and corresponding endpoints

class MLRegistry:
    def __init__(self):
        self.endpoints = {}

    def add_algorithm(self, endpoint_name, algorithm_object, algorithm_name, algorithm_status, algorithm_version, algorithm_description, algorithm_code):
        # Get endpoint
        endpoint, _ = Endpoint.objects.get_or_create(name=endpoint_name)

        # Get algorithm
        database_object, algorithm_created = MLAlgorithm.objects.get_or_create(name=algorithm_name, description=algorithm_description, code=algorithm_code, version=algorithm_version, parent_endpoint=endpoint)

        if algorithm_created:
            status = MLAlgorithmStatus(status=algorithm_status, parent_mlalgorithm=database_object, active=True, created_by='system')
            status.save()
        
        # Add to registry
        self.endpoints[database_object.id] = algorithm_object