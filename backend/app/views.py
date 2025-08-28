import joblib
import numpy as np
import logging
import json
import os
import io
import csv
from datetime import datetime, timedelta
from collections import deque, defaultdict

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
attack_level = None
attack_severity_num = 0
accuracy = None
attack_status = None
ml_status = None
analysis_report = {}

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
        frame_time = features.get('frame.time_relative', (features.get('feature_1', 0)))
        ip_len = features.get('ip.len', (features.get('feature_2', 0)))
        udp_len = features.get('udp.length', (features.get('feature_10', 0)))
        tcp_window = features.get('tcp.window_size_value', (features.get('feature_11', 0)))
        tcp_hdr_len = features.get('tcp.hdr_len', (features.get('feature_12', 0)))
        src_port = features.get('srcport', (features.get('feature_13', 0)))
        dst_port = features.get('dstport', (features.get('feature_14', 0)))

        # Calculate derived metrics
        traffic_metrics['packet_size'] = max(ip_len, udp_len)
        traffic_metrics['payload_size'] = max(ip_len - tcp_hdr_len, 0)
        traffic_metrics['window_efficiency'] = tcp_window / max(ip_len, 1)
        traffic_metrics['port_randomness'] = abs(src_port - dst_port) / 65535.0 if src_port!=0 and dst_port!=0 else 0

        # Estimate packet rate
        traffic_metrics['estimated_packet_rate'] = 1.0 / max(frame_time, 0.001)
        traffic_metrics['packet_rate'] = traffic_metrics['estimated_packet_rate']

        traffic_metrics['connection_attempts'] = traffic_metrics['packet_rate'] * 0.1
        traffic_metrics['connection_rate'] = 1.0 / max(frame_time, 1.0)
        traffic_metrics['frame_time_relative'] = frame_time

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

    def calculate_anomaly_score(self, current_metrics, historical_metrics):
        if not historical_metrics:
            return 0.5 # Average anomaly when no history is available
        
        # Calculate anomaly score using statistical deviations
        packet_rates = [m['packet_rate'] for m in historical_metrics if 'packet_rate' in m]
        packet_sizes = [m['packet_size'] for m in historical_metrics if 'packet_size' in m]

        if not packet_rates or not packet_sizes:
            return 0.5

        # Calculate packet_rates and packet_sizes using z-scores
        avg_rate = np.mean(packet_rates)
        std_rate = np.std(packet_rates) or 1
        avg_size = np.mean(packet_sizes)
        std_size = np.std(packet_sizes) or 1

        rate_zscore = abs((current_metrics.get('estimated_packet_rate', 0) - avg_rate) / std_rate)
        size_zscore = abs((current_metrics.get('packet_size', 0) - avg_size) / std_size)

        # Combine z-scores into anomaly score
        anomaly_score = min((rate_zscore + size_zscore) / 10.0, 1.0)
        return anomaly_score
    
    def decide_attack_level(self, attack_type, features, anomaly_score):
        if attack_type == "Benign":
            return "None", 0, {}
        
        # Calculate traffic metrics
        traffic_metrics = self.calculate_traffic_metrics(features)

        # Get the thresholds for specific attack
        thresholds = self.severity_thresholds.get(attack_type, {})

        if not thresholds:
            # For unknown attack types, can use generic severity level based on anomaly score
            if anomaly_score < 0.3:
                return "Minor", 1, traffic_metrics
            elif anomaly_score < 0.8:
                return "Major", 2, traffic_metrics
            else:
                return "Critical", 3, traffic_metrics
            
        # Calculate severity levels based on different factors
        severity_level = "Minor"
        severity_score = 1 

        # Check each severity level from highest to lowest
        for level, level_thresholds in [('Critical', thresholds.get('Critical', {})),
                                        ('Major', thresholds.get('Major', {})),
                                        ('Minor', thresholds.get('Minor', {}))]:
            if not level_thresholds:
                continue

            # Check if current metrics exceed thresholds for this level
            exceeds_threshold = True

            for metric_name, threshold_value in level_thresholds.items():
                current_value = traffic_metrics.get(metric_name, 0)

                if metric_name == 'frame_time_relative':
                    if current_value < threshold_value:
                        exceeds_threshold = False
                        break
                
                # Lower rates indicate more severe attacks for connection rate in SlowrateDoS
                elif metric_name == 'connection_rate' and attack_type == 'SlowrateDoS':
                    if current_value > threshold_value:
                        exceeds_threshold = False
                        break
                
                else:
                    if current_value < threshold_value:
                        exceeds_threshold = False
                        break
            
            if exceeds_threshold:
                severity_level = level
                severity_score = 3 if level == 'Critical' else (2 if level == 'Major' else 1)
                break

        traffic_metrics['anomaly_score'] = anomaly_score
        traffic_metrics['severity_level'] = severity_level
        traffic_metrics['severity_score'] = severity_score

        return severity_level, severity_score, traffic_metrics
    
# Initialize the SeverityLevelAnalyzer class
severity_analyzer = SeverityLevelAnalyzer()

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

    global model, detection, attack_level, attack_severity_num, accuracy, attack_status, ml_status, analysis_report

    if request.method == 'POST':
        form = CapturedDataForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES.get('captured_data')
            captured_text = form.cleaned_data.get('captured_text', '').strip()
            data = None

            try:
                # If file is submitted
                if uploaded_file:
                    filename = uploaded_file.name.lower()
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
                    
                    pass

                # If text form is submitted
                elif captured_text:
                    if captured_text.strip().startswith('{'):
                        # Handle JSON object format
                        data_dict = json.loads(captured_text)

                        # Extract values in the correct order
                        feature_keys = [
                            "frame.time_relative",
                            "ip.len",
                            "tcp.flags.syn",
                            "tcp.flags.ack",
                            "tcp.flags.push",
                            "tcp.flags.fin",
                            "tcp.flags.reset",
                            "ip.proto",
                            "ip.ttl",
                            "tcp.window_size_value",
                            "tcp.hdr_len",
                            "udp.length",
                            "srcport",
                            "dstport" 
                        ]

                        data = [float(data_dict.get(key, 0.0)) for key in feature_keys]

                    elif captured_text.strip().startswith('['):
                        data = json.loads(captured_text)
                        data = [float(x) for x in data[:14]]

                    else:
                        if ',' in captured_text:
                            fields = [x.strip() for x in captured_text.split(',')]
                        else:
                            fields = captured_text.replace('\t', ' ')
                        data = [float(x) for x in fields[:14]]

                else:
                    detection = "Error: No data provided!"
                    attack_level = "N/A"
                    accuracy = "N/A"
                    return render(request, 'index.html', 
                                  {'form': form, 
                                   'detection': detection, 
                                   'attack_level': attack_level, 
                                   'accuracy': accuracy, 
                                   'attack_status': attack_status, 
                                   'ml_status': ml_status})

                logger.debug(f"Processed data list: {data}")
                logger.debug(f"Data list length: {len(data)}")

                # Ensure exactly 14 features are present
                if len(data) != 14:
                    messages.error(request, "Invalid data format. Please provide exactly 14 features.")
                    return render(request, 'index.html', {'form': form, 'detection': "Error: Invalid data format!", 'attack_level': "N/A", 'accuracy': "N/A", 'attack_status': attack_status, 'ml_status': ml_status})

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

                # Create feature dictionary for severity report
                feature_dict = {}
                feature_names = [
                    "frame.time_relative",
                    "ip.len",
                    "tcp.flags.syn",
                    "tcp.flags.ack",
                    "tcp.flags.push",
                    "tcp.flags.fin",
                    "tcp.flags.reset",
                    "ip.proto",
                    "ip.ttl",
                    "tcp.window_size_value",
                    "tcp.hdr_len",
                    "udp.length",
                    "srcport",
                    "dstport" 
                ]

                for i, value in enumerate(data):
                    if i < len(feature_names):
                        feature_dict[feature_names[i]] = value
                    else:
                        feature_dict[f'feature_{i+1}'] = value

                # Determine attack severity level
                attack_level, attack_severity_num, analysis_report = severity_analyzer.decide_attack_level(detection, feature_dict, anomaly_score=0.5)
                logger.info(f"Attack detected: {detection}, Severity Level: {attack_level}, Severity Num: {attack_severity_num}")

                # Set attack status based on detection results
                if detection == "Benign":
                    attack_status = "Safe"
                else:
                    attack_status = "Under Attack!"

            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {e}")
                messages.error(request, "Invalid JSON format in input data.")
                detection = "Error: Invalid JSON format!"
                attack_level = "N/A"
                accuracy = "N/A"

            except ValueError as e:
                logger.error(f"Value error: {e}")
                messages.error(request, "Invalid number format in input data.")
                detection = "Error: Invalid number format!"
                attack_level = "N/A"
                accuracy = "N/A"

            except Exception as e:
                logger.error(f"Prediction error: {e}")
                messages.error(request, f"Error during prediction: {str(e)}")
                detection = "Error: Prediction failed!"
                attack_level = "N/A"
                accuracy  = "N/A"

            pass
        
        else:
            form = CapturedDataForm()

        return render(request, 'index.html', 
                      {'form': form, 
                       'detection': detection, 
                       'attack_level': attack_level, 
                       'attack_severity': attack_severity_num, 
                       'analysis_report': analysis_report,
                       'accuracy': accuracy, 
                       'attack_status': attack_status, 
                       'ml_status': ml_status, 
                       'captured_data': request.POST.get('captured_data', ''),
                       'captured_text': request.POST.get('captured_text', '')})

    form = CapturedDataForm()
    return render(request, 'index.html', 
                  {'form': form, 
                   'detection': detection, 
                   'attack_level': attack_level, 
                   'attack_severity': attack_severity_num, 
                   'analysis_report': analysis_report,
                   'accuracy': accuracy, 
                   'attack_status': attack_status, 
                   'ml_status': ml_status, 
                   'captured_data': '',
                   'captured_text': ''})