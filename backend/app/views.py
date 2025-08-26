import joblib
import numpy as np
import logging
import json
import os

from django.shortcuts import render
from django.core.files.storage import default_storage
from django.contrib import messages
from django.conf import settings

from django.http import HttpResponseRedirect
from django.urls import reverse

from .forms import CapturedDataForm


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

model = None    
detection = None
accuracy = None
attack_status = None
ml_status = None 

def start_ml(request):

    global model, detection, accuracy, attack_status, ml_status

    # Adjust the path as needed to load the trained model
    model_path = (r'C:\Users\nakam\Documents\zero-touch-5g-sec-ai\backend\app\model\vanilla_lstm_model.pkl')

    if os.path.exists(model_path):
        if request.method == "POST":
            model = joblib.load(model_path)
            logger.info("Model loaded successfully!")
            ml_status = "ML model is available and ready to be used."
            accuracy = "90.73%"
            detection = None

        else:
            logger.warning("Model file not found.")
            ml_status = "ML model is not available."
            accuracy = "N/A"
            detection = None
    
    return HttpResponseRedirect(reverse('home'))
    
def stop_ml(request):

    global model, detection, accuracy, attack_status, ml_status

    messages.info(request, "Machine Learning model stopped.")

    if request.method == "POST":
        ml_status = "ML model is stopped."
        detection = None

    return HttpResponseRedirect(reverse('home'))

def home(request):

    global model, detection, accuracy, attack_status, ml_status

    if request.method == 'POST':
        form = CapturedDataForm(request.POST)
        if form.is_valid():
            captured_data = form.cleaned_data['captured_data']
            logger.debug(f"Captured data: {captured_data}")

            try:
                # Parse the data to handle JSON format
                if captured_data.strip().startswith('{'):
                    # Handle JSON object format
                    data_dict = json.loads(captured_data)

                    # Extract values in the correct order
                    feature_keys = [
                        "frame.time_relative",   # Timestamp of the captured packet
                        "ip.len",                # Total length of the IP packet
                        "tcp.flags.syn",         # TCP synchronize flag status
                        "tcp.flags.ack",         # TCP acknowledgement flag status
                        "tcp.flags.push",        # TCP push flag status
                        "tcp.flags.fin",         # TCP finish flag status
                        "tcp.flags.reset",       # TCP reset flag status
                        "ip.proto",              # IP protocol number
                        "ip.ttl",                # IP time to live; max hops before discard packet
                        "tcp.window_size_value", # TCP window size; receive buffer space
                        "tcp.hdr_len",           # TCP header length
                        "udp.length",            # UDP datagram length
                        "srcport",               # Source port number
                        "dstport"                # Destination port number
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
                    return render(request, 'index.html', {'form': form, 'detection': "Error: Invalid data format!", 'accuracy': "N/A", 'attack_status': attack_status, 'ml_status': ml_status})

                # Reshape the data into 3D array to fit in LSTM input format
                data_array = np.array(data_list).reshape(1, 1, 14)
                logger.debug(f"Data array shape: {data_array.shape}")

                # Make prediction
                prediction = model.predict(data_array)
                logger.debug(f"Model prediction: {prediction}")

                if len(prediction.shape) > 1:
                    predicted_class = np.argmax(prediction, axis=1)

                    if isinstance(predicted_class, np.ndarray):
                        predicted_class = int(predicted_class[0])
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
                accuracy  = "N/A"

            pass
        
        else:
            form = CapturedDataForm()

        return render(request, 'index.html', {'form': form, 'detection': detection, 'accuracy': accuracy, 'attack_status': attack_status, 'ml_status': ml_status, 'captured_data': request.POST.get('captured_data', '')})

    form = CapturedDataForm()
    return render(request, 'index.html', {'form': form, 'detection': detection, 'accuracy': accuracy, 'attack_status': attack_status, 'ml_status': ml_status, 'captured_data': ''})