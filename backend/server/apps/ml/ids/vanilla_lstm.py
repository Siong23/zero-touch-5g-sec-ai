import joblib
import pandas as pd

class VanillaLSTM:
    def __init__(self):
        model_path = '/models/vanilla_lstm_model.pkl'
        self.model = joblib.load(model_path)

    def preprocessing(self, data):
        """
        Preprocess the input data for the LSTM model.
        """
        # Convert JSON to pandas DataFrame
        if isinstance(data, dict):
            data = pd.DataFrame([data])

        # Fill in missing values
        data.fillna(method='ffill', inplace=True)
    
        # Convert categoricals into numbers
        for col in data.select_dtypes(include=['object']).columns:
            data[col] = data[col].astype('category').cat.codes

        return data

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
    
    def compute_prediction(self, data):
        """
        Compute the prediction for the given data.
        
        Args:
            data (dict or pd.DataFrame): Input data for prediction.
        
        Returns:
            pd.Series: Predicted values.
        """
        preprocessed_data = self.preprocessing(data)
        return self.predict(preprocessed_data)