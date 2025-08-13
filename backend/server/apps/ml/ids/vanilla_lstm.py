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
        project_root = os.path.abspath(os.path.join(current_dir, '../../../../../'))
        model_path = os.path.join(project_root, 'models', 'vanilla_lstm_model.pkl')
        self.model = joblib.load(model_path)

    def _create_dummy_model(self):
        class DummyModel:
            def predict_proba(self, X):
                # Return dummy probabilities
                return np.array([[0.36, 0.64]])  # [benign_prob, malicious_prob]
        return DummyModel()

    def preprocessing(self, input_array):
        """
        Preprocess the input data for the LSTM model.
        """
        # Convert JSON to pandas DataFrame
        if isinstance(input_array, dict):
            data = pd.DataFrame([input_array])
        else:
            data = pd.DataFrame(input_array)

        # Fill in missing values
        data.fillna(method='median', inplace=True)
    
        # Convert categoricals into numbers
        for col in data.select_dtypes(include=['object']).columns:
            data[col] = data[col].astype('category').cat.codes

        data = data.iloc[:, :14]

        # Pad with zeros if less than 14 features
        if data.shape[1] < 14:
            padding = np.zeros((data.shape[0], 14 - data.shape[1]))
            data = np.concatenate([data.values, padding], axis=1)
            data = pd.DataFrame(data)

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

        # Check if it's a Keras/TensorFlow model or scikit-learn model
        if hasattr(self.model, 'predict_proba'):
            # Scikit-learn style model
            return self.model.predict_proba(input_array)
        elif hasattr(self.model, 'predict'):
            # Keras/TensorFlow model
            prediction = self.model.predict(input_array, verbose=0)
            return prediction
        else:
            # Fallback for dummy model
            return self.model.predict_proba(input_array)

    def postprocessing(self, input_array):
        """
        Method that applies post-processing on prediction values.
        """
        return pd.Series(input_array.flatten())

    def compute_prediction(self, input_array):
        """
        Compute the prediction for the given data.
        
        Args:
            input_array (np.ndarray): Preprocessed input data for prediction.
        
        Returns:
            pd.Series: Predicted values.
        """
        try:
            # Preprocessing
            preprocessed_data = self.preprocessing(input_array)

            # Prediction
            prediction_result = self.predict(preprocessed_data)
            
            # Postprocessing
            result = self.postprocessing(prediction_result)
            
            return result
            
        except Exception as e:
            return {"status": "Error", "message": str(e)}