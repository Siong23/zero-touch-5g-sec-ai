import joblib
import timeshap
import socket
import threading
import scapy.all as scapy
import numpy as np
import logging
import json
import os
import io
import csv
import subprocess
import paramiko

from datetime import datetime, timedelta
from collections import deque, defaultdict

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

from django import forms
from django.shortcuts import render
from django.core.files.storage import default_storage
from django.contrib import messages
from django.conf import settings
from django.core.cache import cache
from django.views.decorators.csrf import csrf_exempt

from django.http import JsonResponse
from django.http import HttpResponseRedirect
from django.urls import reverse

from .forms import CapturedDataForm
from detection.settings import OPEN5GS_CONFIG

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

model = None    
detection = None
attack_level = None
attack_severity_num = 0
accuracy = None
connection_status = None
network_capture = None
attack_status = None
ml_status = None
analysis_report = {}
target_ip = None
attack_type = None
mitigation = None

# Capture network traffic of 5G Network core with direct network access integration
class NetworkTrafficCapture:
    def __init__(self, host, interface="ogstun", buffer_size=1000):
        self.host = host
        self.interface = interface
        self.capture_active = False
        self.captured_packets = deque(maxlen=buffer_size)
        self.capture_thread = None

        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'malformed_packets': 0
        }

    # Start capturing packets from Open5Gs network 
    def start_capture(self, filter_expr=None):
        
        if self.capture_active:
            logger.warning("Capture is actived")
            return
        
        if filter_expr is None:
            filter_expr = "host {}".format(self.host)

        self.capture_active = True

        def packet_handler(packet):
            if self.capture_active:
                try:
                    features = self.extract_features(packet)

                    if features:
                        self.captured_packets.append(features)
                        self.stats['total_packets'] += 1

                        if packet.haslayer(TCP):
                            self.stats['tcp_packets'] += 1
                        
                        elif packet.haslayer(UDP):
                            self.stats['udp_packets'] += 1
                        
                        elif packet.haslayer(ICMP):
                            self.stats['icmp_packets'] += 1
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")
                    self.stats['malformed_packets'] += 1
        
        # Start capturing packet in separate thread
        try:

            self.capture_thread = threading.Thread(
                target=lambda: scapy.sniff(
                    iface=self.interface,
                    filter=filter_expr,
                    prn=packet_handler,
                    stop_filter=lambda x: not self.capture_active
                )
            )

            self.capture_thread.daemon = True
            self.capture_thread.start()
            logger.info("Packet capture started successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to start packet capture: {e}")
            self.capture_active = False
            return False

    def stop_capture(self):
        self.capture_active = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        logger.info("Packet capture stopped.")
    
    def extract_features(self, packet):
        try:
            features = {}

            features['frame.time_relative'] = float(packet.time) if hasattr(packet, 'time') else 0.0
            features['ip.len'] = len(packet) if packet.haslayer(IP) else 0

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                features['tcp.flags.syn'] = 1 if tcp_layer.flags & 0x02 else 0
                features['tcp.flags.ack'] = 1 if tcp_layer.flags & 0x10 else 0
                features['tcp.flags.push'] = 1 if tcp_layer.flags & 0x08 else 0
                features['tcp.flags.fin'] = 1 if tcp_layer.flags & 0x01 else 0
                features['tcp.flags.reset'] = 1 if tcp_layer.flags & 0x04 else 0
                features['tcp.window_size_value'] = tcp_layer.window
                features['tcp.hdr_len'] = tcp_layer.dataofs * 4 if tcp_layer.dataofs else 20
                features['srcport'] = tcp_layer.sport
                features['dstport'] = tcp_layer.dport
            
            else:
                features.update({
                    'tcp.flags.syn': 0,
                    'tcp.flags.ack': 0,
                    'tcp.flags.push': 0,
                    'tcp.flags.fin': 0,
                    'tcp.flags.reset': 0,
                    'tcp.window_size_value': 0,
                    'tcp.hdr_len': 0,
                    'srcport': 0,
                    'dstport': 0
                })
            
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                features['ip.proto'] = ip_layer.proto
                features['ip.ttl'] = ip_layer.ttl
            
            else:
                features['ip.proto'] = 0
                features['ip.ttl'] = 0
            
            features['udp.length'] = len(packet[UDP]) if packet.haslayer(UDP) else 0

            if packet.haslayer(UDP) and not packet.haslayer(TCP):
                udp_layer = packet[UDP]
                features['srcport'] = udp_layer.sport
                features['dstport'] = udp_layer.dport
            
            return features
        
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None

# Create API endpoints to receive data from the Open5gs network host
@csrf_exempt
def receive_network_data(request):

    global connection_status

    if request.method == 'POST':
        try:

            command = "sudo service open5gs-amfd status"

            ssh = paramiko.client.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect('192.168.0.115', username='server2', password='mmuzte123', timeout=30)
            _stdin, _stdout, _stderr = ssh.exec_command("sudo service open5gs-amfd status")
            print(_stdout.read().decode())
            connection_status = "Connected to 5G Network"

        except Exception as e:
            logger.error(f"API data processing error: {e}")
            connection_status = "Connection error"
            return HttpResponseRedirect(reverse('home'))
    
    return HttpResponseRedirect(reverse('home'))

def perform_detection(features):
    global model

    if model is None:
        return {'model': 'Model not loaded', 'attack_type': 'N/A', 'severity_level': 'N/A'}
    
    try:
        data_array = np.array(features).reshape(1, 1, 14)
        prediction = model.predict(data_array)
        predicted_class = np.argmax(prediction, axis=1)[0]

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
        
        attack_type = attack_types.get(predicted_class, "Unknown")

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

        feature_dict = {feature_names[i]: features[i] for i in range(min(len(features), len(feature_names)))}

        severity_level, severity_score, traffic_metrics = severity_analyzer.decide_attack_level(attack_type, feature_dict, anomaly_score=0.5)

        return {
            'model': 'Model loaded',
            'attack_type': attack_type,
            'severity_level': severity_level,
            'severity_score': severity_score
        }
    except Exception as e:
        logger.error(f"Detection error: {e}")
        return {'model': 'Error', 'attack_type': 'N/A', 'severity_level': 'N/A'}

# Simulate different types of network attacks by injecting attack into the 5G Networ
class AttackSimulator:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password or "mmuzte123"

    # Trigger a DoS attack (SYNFlood) on the specified target IP
    def trigger_dos_attack(self, target_ip, attack_type="SYNFlood"):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.host, username=self.username, password=self.password, timeout=10)

            attack_command = {
                'SYNFlood': f'sudo hping3 -S -p 80 --flood {target_ip}'
            }

            command = attack_command.get(attack_type, attack_command['SYNFlood'])

            if command:
                stdin, stdout, stderr = ssh.exec_command(f'timeout 30 {command}')
                logger.info(f"{attack_type} attack triggered on {target_ip}")

                ssh.close()
                return True
        
        except Exception as e:
            logger.error(f"Attack simulation error: {e}")
            return False

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

# Mitigation strategies based on attack type (suggestion - temporary)
class AIMitigation:
    def http_flood_mitigation(self, traffic_data):
        mitigation = "- Implement rate limiting for HTTP requests from the source IP \n - Block the source IP temporarily \n - Use a Web Application Firewall(WAF) to filter malicious HTTP traffic"
        return mitigation

    def icmp_flood_mitigation(self, traffic_data):
        mitigation = "Disable the ICMP functionality of the targeted router, computer or other device"
        return mitigation
    
    def syn_flood_mitigation(self, traffic_data):
        mitigation = "- Increase the backlog queue size\n - Overwrite the oldest half-open TCP connection once the backlog has been filled\n - Deploy SYN cookies\n Use a firewall to drop suspicious SYN packets"
        return mitigation

    def syn_scan_mitigation(self, traffic_data):
        mitigation = "Use a firewall to block or filter suspicious IP addresses and traffic patterns"
        return mitigation
    
    def slowrate_dos_mitigation(self, traffic_data):
        mitigation = "Use reverse proxy-based protection"
        return mitigation
    
    def tcp_connect_scan_mitigation(self, traffic_data):
        mitigation = "Use a firewall to block or filter suspicious IP addresses and traffic patterns"
        return mitigation
    
    def udp_flood_mitigation(self,traffic_data):
        mitigation = "- Block the source IP\n Use filtering rules to drop malicious UDP traffic"
        return mitigation

    def udp_scan_mitigation(self, traffic_data):
        mitigation = "Use a firewall to block or filter suspicious IP addresses and traffic patterns"
        return mitigation
    
mitigation_analyzer = AIMitigation()

# Start the attack simulation when the start button is clicked
def start_attack(request):
    global target_ip, attack_type, attack_status

    if request.method == "POST":
        attack_type = request.POST.get('attack_type', 'SYNFlood')
        target_ip = request.POST.get('target_ip', '192.168.0.115')

        config = OPEN5GS_CONFIG[0] if OPEN5GS_CONFIG else {}
        host = OPEN5GS_CONFIG.get('HOST', '192.168.0.115')
        username = config.get('USERNAME', 'server2')
        password = config.get('PASSWORD', 'mmuzte123')
        simulator = AttackSimulator(host, username, password)
        
        if simulator.trigger_dos_attack(target_ip, attack_type):
            attack_status = f"Attack simulation started. {attack_type} attack injected on {target_ip}"
        else:
            attack_status = "Failed to inject attack"
        
    return HttpResponseRedirect(reverse('home'))

# Stop the attack simulation when the stop button is clicked
def stop_attack(request):
    global attack_status

    if request.method == "POST":
        attack_status = "Attack simulation stopped."
    
    return HttpResponseRedirect(reverse('home'))

# Start the machine learning model when the start button is clicked
def start_ml(request):

    global model, detection, accuracy, ml_status

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
    
# Stop the machine learning model when the stop button is clicked
def stop_ml(request):

    global model, detection, accuracy, attack_status, ml_status

    if request.method == "POST":
        ml_status = "ML model is stopped."
        model = None
        detection = None
        messages.info(request, "Machine Learning model stopped.")

    return HttpResponseRedirect(reverse('home'))

def home(request):

    global model, detection, attack_level, attack_severity_num, accuracy, connection_status, attack_status, ml_status, target_ip, attack_type, analysis_report, mitigation

    if request.method == 'POST' and model is not None:
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
                            "frame.time_relative",      # Timestamp of the captured packet
                            "ip.len",                   # Total length of the IP packet
                            "tcp.flags.syn",            # TCP synchronize flag status
                            "tcp.flags.ack",            # TCP acknowledgement flag status
                            "tcp.flags.push",           # TCP push flag status
                            "tcp.flags.fin",            # TCP finish flag status
                            "tcp.flags.reset",          # TCP reset flag status
                            "ip.proto",                 # IP protocol number
                            "ip.ttl",                   # IP time to live; max hops before discard packet
                            "tcp.window_size_value",    # TCP window size; receive buffer space
                            "tcp.hdr_len",              # TCP header length
                            "udp.length",               # UDP datagram length
                            "srcport",                  # Source port number
                            "dstport"                   # Destination port number
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
                                   'connection_status': connection_status, 
                                   'attack_status': attack_status, 
                                   'ml_status': ml_status,
                                   'attack_type': attack_type
                                   })

                logger.debug(f"Processed data list: {data}")
                logger.debug(f"Data list length: {len(data)}")

                # Ensure exactly 14 features are present
                if len(data) != 14:
                    messages.error(request, "Invalid data format. Please provide exactly 14 features.")
                    return render(request, 'index.html', 
                                  {'form': form, 
                                   'detection': "Error: Invalid data format!", 
                                   'attack_level': "N/A", 
                                   'accuracy': "N/A", 
                                   'connection_status': connection_status,
                                   'attack_status': attack_status, 
                                   'ml_status': ml_status,
                                   'attack_type': attack_type})

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

                # Set attack status and mitigation based on detection results
                if detection == "Benign":
                    attack_status = "Safe"
                    mitigation = "No action needed"

                else:  
                    attack_status = "Under Attack!"
                    mitigation = mitigation_analyzer.get_mitigation(detection, analysis_report)
                # Will implement mitigation strategies

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
                       'connection_status': connection_status,
                       'attack_status': attack_status, 
                       'ml_status': ml_status,
                       'target_ip': target_ip,
                       'attack_type': attack_type,
                       'mitigation': mitigation,
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
                   'connection_status': connection_status,
                   'attack_status': attack_status, 
                   'ml_status': ml_status, 
                   'target_ip': target_ip,
                   'attack_type': attack_type,
                   'mitigation': mitigation,
                   'captured_data': '',
                   'captured_text': ''})