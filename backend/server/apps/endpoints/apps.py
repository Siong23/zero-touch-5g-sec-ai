from django.apps import AppConfig
import inspect


class EndpointsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.endpoints'

class MlConfig(AppConfig):
    name = 'apps.ml'

    def ready(self):
        from apps.ml.registry import MLRegistry
        from apps.ml.ids.vanilla_lstm import VanillaLSTM

        registry = MLRegistry()
        algorithm_object = VanillaLSTM()
        registry.add_algorithm(
            endpoint_name='ids',
            algorithm_object=algorithm_object,
            algorithm_name='Vanilla LSTM',
            algorithm_status='active',
            algorithm_version='1.0',
            algorithm_description='Vanilla LSTM with simple pre-processing.',
            algorithm_code=inspect.getsource(VanillaLSTM)
        )