import os
import joblib
import pandas as pd
import keras
import tensorflow
import numpy as np
from django.conf import settings

class VanillaLSTM:
    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.abspath(os.path.join(current_dir, '../../../../../models/vanilla_lstm_model.pkl'))
        self.model = joblib.load(model_path)

    def preprocessing(self, input_array):
        """
        Preprocess the input data for the LSTM model.
        """
        # Convert JSON to pandas DataFrame
        if isinstance(input_array, dict):
            data = pd.DataFrame([input_array])

        # Fill in missing values
        data.fillna(method='ffill', inplace=True)
    
        # Convert categoricals into numbers
        for col in data.select_dtypes(include=['object']).columns:
            data[col] = data[col].astype('category').cat.codes

        data = data.iloc[:, :14]
        input_array = data.values.reshape((1, 1, 14))

        return input_array

    def predict(self, input_array):
        """
        Predict using the loaded LSTM model.
        
        Args:
            input_array (numpy.ndarray): Preprocessed input data for prediction.
        
        Returns:
            pd.Series: Predicted values.
        """
        if not isinstance(input_array, np.ndarray):
            raise ValueError("Input data must be a numpy array.")

        # Ensure the model is ready for prediction
        if self.model is None:
            raise RuntimeError("Model is not loaded.")
        
        if input_array.shape != (1, 1, 14):
            raise ValueError(f"Input array must be in shape of (1, 1, 14), but currently got {input_array.shape}")

        predictions = self.model.predict(input_array)
        return pd.Series(predictions.flatten())

    def compute_prediction(self, input_array):
        """
        Compute the prediction for the given data.
        
        Args:
            input_array (np.ndarray): Preprocessed input data for prediction.
        
        Returns:
            pd.Series: Predicted values.
        """
        try:
            input_array = self.preprocessing(input_array)
            predictions = self.predict(input_array)
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

        return {"status": "OK", "predictions": predictions}