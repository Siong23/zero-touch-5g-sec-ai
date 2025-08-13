"""
WSGI config for server project.

It exposes the WSGI callable as a module-level variable named ``application``.

"""
# Specify a place in the server code 
# which will add ML Algorithms to the registry when the server starts

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'server.settings')
application = get_wsgi_application()

# ML Registry added
import inspect
from apps.ml.registry import MLRegistry
from apps.ml.ids.vanilla_lstm import VanillaLSTM

try:
    # Create ML Registry for Vanilla LSTM
    registry = MLRegistry()
    lstm = VanillaLSTM()
    registry.add_algorithm(endpoint_name="ids", algorithm_object=lstm, algorithm_name="Vanilla LSTM", algorithm_status="active", algorithm_version="1.0", algorithm_description="Vanilla LSTM with simple pre-processing", algorithm_code=inspect.getsource(VanillaLSTM))

except Exception as e:
    print("Exception while adding the algorithms to the registry, ", str(e))
    import traceback
    traceback.print_exc()
