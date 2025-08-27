import joblib
import numpy as np
import logging
import json
import os
import io
import csv
from datetime import datetime, timedelta

from django import forms
from django.shortcuts import render
from django.core.files.storage import default_storage
from django.contrib import messages
from django.conf import settings
from django.core.cache import cache

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

# Analyze attack severity levels using network features and patterns
class SeverityLevelAnalyzer:
    def __init__(self):
        # Set the severity threshold for each attack type
        self.severity_thresholds = {
            'HTTPFlood': {
                'Minor': {'packet_rate': 100, 'payload_size': 1000},
                'Major': {'packet_rate': 1000, 'payload_size': 10000},
                'Critical': {'packet_rate': 2000, 'payload_size': 20000}
            },

            'ICMPFlood': {
                'Minor': {'packet_rate': 50, 'payload_size': 500},
                'Major': {'packet_rate': 500, 'payload_size': 2000},
                'Critical': {'packet_rate': 1000, 'payload_size': 5000}
            },

            'SYNFlood': {
                'Minor': {'packet_rate': 100, 'connection_attempts': 50},
                'Major': {'packet_rate': 600, 'connection_attempts': 300},
                'Critical': {'packet_rate': 1200, 'connection_attempts': 600}
            },

            ('SYNScan', 'TCPConnectScan', 'UDPScan'): {
                'Minor': {'packet_rate': 100, 'connection_attempts': 50},
                'Major': {'packet_rate': 600, 'connection_attempts': 300},
                'Critical': {'packet_rate': 1200, 'connection_attempts': 600}
            },

            'SlowrateDoS': {
                'Minor': {'frame.time_relative': 300, 'connection_rate': 1},
                'Major': {'frame.time_relative': 1200, 'connection_rate': 0.2},
                'Critical': {'frame.time_relative': 1800, 'connection_rate': 0.1}
            },

            'UDPFlood': {
                'Minor': {'packet_rate': 200, 'payload_size': 1000},
                'Major': {'packet_rate': 1000, 'payload_size': 6000},
                'Critical': {'packet_rate': 2000, 'payload_size': 12000}
            }
        }
    
    def calculate_traffic_metrics(self, features):
        traffic_metrics = {}

        # Extract key features
        frame_time = features.get('frame.time_relative', 0)
        ip_len = features.get('ip.len', 0)
        udp_len = features.get('udp.length', 0)
        tcp_window = features.get('tcp.window_size_value', 0)
        src_port = features.get('srcport', 0)
        dst_port = features.get('dstport', 0)

        # Calculate derived metrics
        traffic_metrics['packet_size'] = max(ip_len, udp_len)
        traffic_metrics['window_efficiency'] = tcp_window / max(ip_len, 1)
        traffic_metrics['port_randomness'] = abs(src_port - dst_port) / 65535.0

        # Estimate packet rate
        traffic_metrics['estimated_packet_rate'] = 1.0 / max(frame_time, 0.001)

        return traffic_metrics  
    
    def historical_context(self, src_ip=None, dst_ip=None, window_minutes=5):
        cache_key = f"traffic_history_{src_ip}_{dst_ip}_{window_minutes}"
        traffic_history = cache.get(cache_key, [])

        cutoff_time = datetime.now() - timedelta(minutes=window_minutes)

        # Filter out old entries
        traffic_history = [entry for entry in traffic_history if entry['timestamp'] > cutoff_time]

        return traffic_history
    
    def update_traffic_history(self, metrics, src_ip=None, dst_ip=None):
        cache_key = f"traffic_history_{src_ip}_{dst_ip}_5"
        traffic_history = cache.get(cache_key, [])

        # Append new entry with timestamp
        traffic_history.append({
            'timestamp': datetime.now(),
            'metrics': metrics
        })

        # Update the cache
        cache.set(cache_key, traffic_history, timeout=900)  # Cache for 15 minutes

# Captured Data Form
class CapturedDataForm(forms.Form):
    captured_data = forms.FileField(required=True)

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
        form = CapturedDataForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['captured_data']
            filename = uploaded_file.name.lower()
            data = None

            try:
                # Parse the data to handle JSON format
                if filename.endswith('.json'):
                    # Handle JSON format
                    file_content = uploaded_file.read().decode('utf-8')
                    obj = json.loads(file_content)

                    # Extract values by keys if its dict
                    if isinstance(obj, dict):
                        feature_keys = list(obj.keys())
                        data = [float(obj[k]) for k in feature_keys]
                    elif isinstance(obj, list):
                        data = [float(x) for x in obj[:14]]

                elif filename.endswith('.csv'):
                    # Handle CSV format
                    file_content = uploaded_file.read().decode('utf-8')
                    reader = csv.reader(io.StringIO(file_content))
                    row = next(reader)
                    data = [float(x) for x in row[:14]]

                elif filename.endswith('.npy'):
                    # Handle NPY format
                    file_buffer = io.BytesIO(uploaded_file.read())
                    arr = np.load(file_buffer, allow_pickle=True)
                    arr = arr.flatten()
                    data = [float(x) for x in arr[:14]]

                elif filename.endswith('.netflow'):
                    # Handle NetFlow format
                    file_content = uploaded_file.read().decode('utf-8')
                    data = [line.split() for line in file_content.splitlines()][0]

                else:
                    detection = "Error: Unsupported file format!"

                logger.debug(f"Processed data list: {data}")
                logger.debug(f"Data list length: {len(data)}")

                # Ensure exactly 14 features are present
                if len(data) != 14:
                    messages.error(request, "Invalid data format. Please provide exactly 14 features.")
                    return render(request, 'index.html', {'form': form, 'detection': "Error: Invalid data format!", 'accuracy': "N/A", 'attack_status': attack_status, 'ml_status': ml_status})

                # Reshape the data into 3D array to fit in LSTM input format
                data_array = np.array(data).reshape(1, 1, 14)
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