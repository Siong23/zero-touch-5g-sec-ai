import joblib
import numpy as np
import logging
import json
import os

from django.shortcuts import render
from django.core.files.storage import default_storage
from django.contrib import messages
from django.conf import settings

from .forms import CapturedDataForm

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load trained model with error handling
model = None

try:
    model_path = os.path.join(settings.BASE_DIR, 'models', 'lstm_model.pkl')
    if os.path.exists(model_path):
        model = joblib.load(model_path)
        logger.info("Model loaded successfully!")
    else:
        logger.warning("Model file not found.")

except Exception as e:
    logger.error(f"Error loading model: {e}")

def home(request):
    detection = None
    accuracy = None
    status = "Ready"

    if request.method == 'POST':
        form = CapturedDataForm(request.POST)
        if form.is_valid():
            captured_data = form.cleaned_data['captured_data']
            logger.debug(f"Captured data: {captured_data}")

            if model is None:
                messages.error(request, "Model is not loaded.")
                return render(request, 'index.html', {'form': form, 'detection': "Error: Model not loaded!", 'accuracy': "N/A", 'status': status})

            try:
                # Parse the data to handle JSON format
                if captured_data.strip().startswith('{'):
                    # Handle JSON object format
                    data_dict = json.loads(captured_data)

                    # Extract values in the correct order
                    feature_keys = [
                        "frame.time_relative", "ip.len", "tcp.flags.syn", "tcp.flags.ack",
                        "tcp.flags.push", "tcp.flags.fin", "tcp.flags.reset", "ip.proto",
                        "ip.ttl", "tcp.window_size_value", "tcp.hdr_len", "udp.length",
                        "srcport", "dstport"
                    ]

                    data_list = [data_dict.get(key, 0.0) for key in feature_keys]
                elif captured_data.strip().startswith('['):
                    # Handle JSON array format
                    data_list = json.loads(captured_data)
                    data_list = data_list[:14]
                else:
                    # Handle CSV
                    data_list = [float(x.strip()) for x in captured_data.split(',')]
                    data_list = data_list[:14]

                logger.debug(f"Processed data list: {data_list}")
                logger.debug(f"Data list length: {len(data_list)}")

                # Ensure exactly 14 features are present
                if len(data_list) != 14:
                    messages.error(request, "Invalid data format. Please provide exactly 14 features.")
                    return render(request, 'index.html', {'form': form, 'detection': "Error: Invalid data format!", 'accuracy': "N/A", 'status': status})

                # Reshape the data into 3D array to fit in LSTM input format
                data_array = np.array(data_list).reshape(1, 1, 14)
                logger.debug(f"Data array shape: {data_array.shape}")

                # Make prediction
                prediction = model.predict(data_array)
                logger.debug(f"Model prediction: {prediction}")

                if len(prediction.shape) > 1:
                    predicted_class = np.argmax(prediction, axis=1)
                else:
                    predicted_class = int(prediction[0])

                attack_types = {
                    0: "Benign",
                    1: "HTTPFlood",
                    2: "ICMPFlood",
                    3: "SYNFlood",
                    4: "SYNScan",
                    5: "SlowrateDoS",
                    6: "TCPConnectScan",
                    7: "UDPFlood",
                    8: "UDPScan"
                }

                detection = attack_types.get(predicted_class, "Unknown")

            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {e}")
                messages.error(request, "Invalid JSON format in input data.")
                detection = "Error: Invalid JSON format!"
                accuracy = "N/A"
            except ValueError as e:
                logger.error(f"Value error: {e}")
                messages.error(request, "Invalid number format in input data.")
                detection = "Error: Invalid number format!"
                accuracy = "N/A"
            except Exception as e:
                logger.error(f"Prediction error: {e}")
                messages.error(request, f"Error during prediction: {str(e)}")
                detection = "Error: Prediction failed!"
                accuracy = "N/A"
        
        else:
            form = CapturedDataForm()

        return render(request, 'index.html', {'form': form, 'detection': detection, 'accuracy': accuracy, 'status': status})
