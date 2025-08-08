import joblib
import pandas as pd

class VanillaLSTM:
    def __init__(self):
        model_path = '/models/vanilla_lstm_model.pkl'
        self.model = joblib.load(model_path)
    
    def predict(self, data):
        """
        Predict using the loaded LSTM model.
        
        Args:
            data (pd.DataFrame): Input data for prediction.
        
        Returns:
            pd.Series: Predicted values.
        """
        if not isinstance(data, pd.DataFrame):
            raise ValueError("Input data must be a pandas DataFrame.")
        
        # Ensure the model is ready for prediction
        if self.model is None:
            raise RuntimeError("Model is not loaded.")
        
        predictions = self.model.predict(data)
        return pd.Series(predictions)