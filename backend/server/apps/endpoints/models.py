from django.db import models

class Endpoint(models.Model): # Keep information about endpoints
    name = models.CharField(max_length=255)
    object_type = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

class MLAlgorithm(models.Model): # Keep information about ML algorithm used
    name = models.CharField(max_length=255)
    description = models.CharField(max_length=1000)
    code = models.CharField(max_length=50000)
    version = models.CharField(max_length=128)
    owner = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    parent_endpoint = models.ForeignKey(Endpoint, on_delete=models.CASCADE)

class MLAlgorithmStatus(models.Model): # Keep information about ML algorithm status
    status = models.CharField(max_length=255)
    active = models.BooleanField()
    created_by = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    parent_mlalgorithm = models.ForeignKey(MLAlgorithm, on_delete=models.CASCADE, related_name="status")

class MLRequest(models.Model): # Keep information about all requests to ML algorithm
    input_data = models.CharField(max_length=10000)
    full_response = models.CharField(max_length=10000)
    response = models.CharField(max_length=10000)
    feedback = models.CharField(max_length=10000, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    parent_mlalgorithm = models.ForeignKey(MLAlgorithm, on_delete=models.CASCADE, related_name="requests")

