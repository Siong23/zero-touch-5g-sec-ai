import joblib
import pandas as pd

class VanillaLSTM:
    def __init__(self):
        model_path = '/models/vanilla_lstm_model.pkl'
        self.model = joblib.load(model_path)