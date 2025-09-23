import joblib
import timeshap
import socket
import threading
import queue
import time
import asyncio
import pyshark
import scapy.all as scapy
import numpy as np
import logging
import json
import os
import io
import csv
import subprocess
import tempfile
import paramiko
import glob
import time
import tensorflow as tf
import psutil

from datetime import datetime, timedelta
from collections import deque, defaultdict

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.all import *

from django import forms
from django.shortcuts import render
from django.core.files.storage import default_storage
from django.contrib import messages
from django.conf import settings
from django.core.cache import cache
from django.views.decorators.csrf import csrf_exempt

from django.http import JsonResponse
from django.http import HttpResponseRedirect
from django.urls import path, reverse

from .forms import CapturedDataForm
from detection.settings import OPEN5GS_CONFIG

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

auto_analysis_results = {}
automation_queue = queue.Queue()
automation_thread = None
automation_active = False
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
capture_thread = None
capture_active = False
latest_capture_file = None

class AutomationManager:
    def __init__(self):
        self.current_task = None
        self.progress = 0
        self.status = "Idle"
        self.results = {}

    def start_automation(self, attack_type, target_ip):
        self.current_task = {
            'attack_type': attack_type,
            'target_ip': target_ip,
            'start_time': datetime.now(),
            'steps': [
                'attack_simulation',
                'packet_capture',
                'ml_loading',
                'data_analysis',
                'results_generation'
            ]
        }
        self.progress = 0
        self.status = "Running"
        return True
    
    def get_status(self):

        return {
            'status': self.status,
            'progress': self.progress,
            'current_task': self.current_task,
            'results': self.results
        }
    
    def complete_step(self, step_name, results=None):
        if self.current_task and step_name in self.current_task['steps']:
            step_index = self.current_task['steps'].index(step_name)
            self.progress = int(((step_index + 1) / len(self.current_task['steps'])) * 100)
           
            if results:
                self.results[step_name] = results
            
    def complete_automation(self, final_results):
        self.status = "Completed"
        self.progress = 100
        self.results['final'] = final_results

        logger.info("Automation process completed.")

automation_manager = AutomationManager()

# Capture network traffic of 5G Network core with direct network access integration
class NetworkTrafficCapture:

    def __init__(self):
        self.capture_active = False
        self.packets_captured = []
        self.capture_interface = self.get_active_interface()
    
    def get_active_interface(self):
        try:
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()

            for interface_name, interface_addresses in interfaces.items():
                if interface_name in stats and stats[interface_name].isup:
                    for address in interface_addresses:
                        if address.family == socket.AF_INET and not address.address.startswith("127."):
                            logger.info(f"Network interface used: {interface_name} with IP {address.address}")
                            return interface_name
            
            fallback_interfaces = ["Wi-Fi", "wlan0", "eth0", "Ethernet"]
            for interface in fallback_interfaces:
                if interface in interfaces:
                    logger.info(f"Fallback to interface: {interface}")
                    return interface
        
        except Exception as e:
            logger.error(f"Error getting active network interface: {e}")
            return "Wi-Fi"  # Default to Wi-Fi if an error occurs

    # Start capturing packets from Open5Gs network (Current - Stop automatically after 30s)
    def start_capture_with_auto_analysis(self, duration=30, attack_type=None, target_ip=None):

        global capture_active, capture_thread, latest_capture_file

        if capture_active:
            logger.warning("Capture already running")
            return False, None
        
        try:
            timestamp = int(time.time())
            filename = f"{attack_type}.pcap"
            filepath = os.path.join(settings.BASE_DIR, 'captures', filename)

            os.makedirs(os.path.dirname(filepath), exist_ok=True)

            capture_active = True
            latest_capture_file = filepath
            self.capture_file_path = filepath

            capture_thread = threading.Thread(target=self._capture_with_analysis, args=(duration, filepath, attack_type, target_ip))
            capture_thread.daemon = True
            capture_thread.start()
            logger.info(f"Packet capture started on interface {self.capture_interface} for {duration} seconds.")
            return True, filepath

        except Exception as e:
            logger.error(f"Error starting packet capture: {e}")
            capture_active = False
            return False, None

    def _capture_with_analysis(self, duration, filepath, attack_type, target_ip):
        # Start packet capture and analysis
        global capture_active, auto_analysis_results

        try:
            loop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(loop)

            capture = pyshark.LiveCapture(interface=self.capture_interface, eventloop=loop, output_file=filepath)
            capture.sniff(timeout=duration)

            if 'capture' in locals() and capture:
                capture.close()
                logger.info(f"Packet capture completed. Saved to {filepath}")

        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
        
        finally:
            capture_active = False

    # Process captured data in packet
    def auto_analyze_capture(self,filepath, attack_type, target_ip):

        global model

        if not model:
            logger.error("ML model is not loaded.")
            return None
        
        if not os.path.exists(filepath):
            logger.error("Capture file not found.")
            return None

        try:
            packets = rdpcap(filepath)

            if len(packets) == 0:
                logger.warning("Error: No packets of data found.")
                return None
            
            analysis_results = {
                'filepath': filepath,
                'attack_type': attack_type,
                'target_ip': target_ip,
                'total_packets': len(packets),
                'detections': [],
                'summary': [],
                'timestamp': datetime.now().isoformat()
            }

            packets_to_analyze = packets[:50]
            logger.info(f"Analyzing {len(packets_to_analyze)} packets from capture.")

            attack_detections = defaultdict(int)
            severity_levels = defaultdict(int)

            for i, packet in enumerate(packets_to_analyze):
                features = self.extract_features(packet)

                if not features:
                    continue

                # Convert features dict to ordered list
                feature_list = [
                    features.get('frame.time_relative', 0.0),
                    features.get('ip.len', 0),
                    features.get('tcp.flags.syn', 0),
                    features.get('tcp.flags.ack', 0),
                    features.get('tcp.flags.push', 0),
                    features.get('tcp.flags.fin', 0),
                    features.get('tcp.flags.reset', 0),
                    features.get('ip.proto', 0),
                    features.get('ip.ttl', 0),
                    features.get('tcp.window_size_value', 0),
                    features.get('tcp.hdr_len', 0),
                    features.get('udp.length', 0),
                    features.get('srcport', 0),
                    features.get('dstport', 0)
                ]

                return JsonResponse({
                    'status': 'success',
                    'data': {
                        'features': feature_list,
                        'file_path': filepath,
                        'packet_count': len(packets),
                        'auto_analysis': auto_analysis_results
                    }
                })

        except Exception as e:
            logger.error(f"Error processing file: {e}")
            return HttpResponseRedirect(reverse('home'))

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

            ssh = paramiko.client.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Modify the (HOST, USERNAME, PASSWORD) as needed to connect to the server
            ssh.connect('192.168.0.132', username='open5gs', password='mmuzte123', timeout=10)
            _stdin, _stdout, _stderr = ssh.exec_command(" service open5gs-amfd status")
            output = _stdout.readlines()
            
            for line in output:
                if "Active" in line:
                    print("open5gs-amfd-service: ", line)

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

# Simulate different types of network attacks by injecting attack into the 5G Network
class AttackSimulator:
    def __init__(self, host, username, password):
        self.host = host or "192.168.0.132"
        self.username = username or "open5gs"
        self.password = password or "mmuzte123"

    # Trigger a DoS attack (SYNFlood) on the specified target IP
    def trigger_dos_attack(self, target_ip, attack_type):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.host, username=self.username, password=self.password, timeout=30)

            attack_command = {
                'HTTPFlood': f'python3 goldeneye.py http://{target_ip}',
                'ICMPFlood': f'hping3 -1 {target_ip}',
                'SYNFlood': f'hping3 -S -p 80 --flood --rand-source {target_ip}',
                'UDPFlood': f'hping3 -1 {target_ip}',
                'SYNScan': f'nmap -sS {target_ip} -p 1-1000',
                'TCPConnectScan': f'nmap -sT {target_ip} -p 1-1000',
                'UDPScan': f'nmap -sU {target_ip} -p 1-1000',
                'SlowrateDoS': f'python3 slowloris.py {target_ip}'
            }

            command = attack_command.get(attack_type)

            if command:
                stdin, stdout, stderr = ssh.exec_command(f'timeout 60 {command}')
                print(stdout.readlines())
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
network_capture = NetworkTrafficCapture()

# Mitigation strategies based on attack type
class AIMitigation:

    if detection!="Benign":

        ssh = paramiko.client.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Modify the (HOST, USERNAME, PASSWORD) as needed to connect to the server
        # ssh.connect('192.168.0.115', username='server2', password='mmuzte123', timeout=30)

        def http_flood_mitigation(self, ssh):
            _stdin, _stdout, _stderr = ssh.exec_command("sudo iptables -I INPUT 2 -j prohibited_traffic")
            output = _stdout.readlines()
            mitigation = "Block IP source temporarily"
            return mitigation

        def icmp_flood_mitigation(self, ssh):
            _stdin, _stdout, _stderr = ssh.exec_command("sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP")
            output = _stdout.readlines()
            mitigation = "Block ICMP echo requests"
            return mitigation
        
        def syn_flood_mitigation(self, ssh):
            _stdin, _stdout, _stderr = ssh.exec_command("sudo iptables -A BLOCK -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -j DROP")
            output = _stdout.readlines()
            mitigation = "Drop all SYN packets"
            return mitigation

        def syn_scan_mitigation(self, ssh):
            _stdin, _stdout, _stderr = ssh.exec_command("sudo iptables -I INPUT 2 -j prohibited_traffic")
            output = _stdout.readlines()
            mitigation = "Block IP source temporarily"
            return mitigation
        
        def slowrate_dos_mitigation(self, ssh):
            _stdin, _stdout, _stderr = ssh.exec_command("sudo iptables -I INPUT 2 -j prohibited_traffic")
            output = _stdout.readlines()
            mitigation = "Block IP source temporarily"
            return mitigation
        
        def tcp_connect_scan_mitigation(self, ssh):
            _stdin, _stdout, _stderr = ssh.exec_command("sudo iptables -I INPUT 2 -j prohibited traffic")
            output = _stdout.readlines()
            mitigation = "Block IP addresses temporarily"
            return mitigation
        
        def udp_flood_mitigation(self,ssh):
            _stdin, _stdout, _stderr = ssh.exec_command("sudo iptables -I INPUT 2 -j prohibited traffic")
            output = _stdout.readlines()
            mitigation = "Block the source IP temporarily"
            return mitigation

        def udp_scan_mitigation(self, ssh):
            _stdin, _stdout, _stderr = ssh.exec_command("sudo iptables -I INPUT 2 -j prohibited traffic")
            output = _stdout.readlines()
            mitigation = "Block IP addresses temporarily"
            return mitigation
    
# Start the attack simulation when the start button is clicked
def start_attack(request):
    global target_ip, attack_type, attack_status, network_capture, latest_capture_file
    global model, ml_status, automation_manager

    if request.method == "POST":
        automation_manager.start_automation(attack_type, target_ip)

        attack_type = request.POST.get('attack_type')
        target_ip = request.POST.get('target_ip', '192.168.0.165')

        host = OPEN5GS_CONFIG.get('HOST', '192.168.0.132')
        username = OPEN5GS_CONFIG.get('USERNAME', 'open5gs')
        password = OPEN5GS_CONFIG.get('PASSWORD', 'mmuzte123')
        simulator = AttackSimulator(host, username, password)

        # 1. Start packet capture with auto analysis
        capture_success, capture_file = network_capture.start_capture_with_auto_analysis(duration=60, attack_type=attack_type, target_ip=target_ip)

        if capture_success:
            logger.info("Packet capture thread started.")

            automation_manager.complete_step('packet_capture', {'file_path': capture_file})

            time.sleep(2)
        
            # 2. Start attack simulation
            if simulator.trigger_dos_attack(target_ip, attack_type):
                attack_status = f"Attack simulation started. {attack_type} attack injected on {target_ip}"
                latest_capture_file = capture_file
                automation_manager.complete_step('attack_simulation', {'status': 'success'})
                cache.set('latest_capture_info', 
                    {
                    'file_path': capture_file,
                    'attack_type': attack_type,
                    'target_ip': target_ip,
                    'timestamp': datetime.now().isoformat(),
                    'automation_id': id(automation_manager.current_task)
                }, timeout=3600) # Cache for 1 hour 

                # 3. ML model loading and analysis
                threading.Thread(
                    target=schedule_ml_automation,
                    args=(capture_file, attack_type, target_ip),
                    daemon=True
                ).start()
            
            else:
                attack_status = "Failed to inject attack"
                automation_manager.status = "Failed"
                network_capture.stop_capture()
                messages.error(request, "Attack simulation failed.")
        
        else:
            attack_status = "Failed to start packet capture"
            automation_manager.status = "Failed"
            messages.error("Failed to intialize packet capture.")
        
    return HttpResponseRedirect(reverse('home'))

def schedule_ml_automation(capture_file, attack_type, target_ip):
    global model, ml_status, automation_manager

    try:
        time.sleep(37) # Wait for capture to complete

        # 4. Auto load ML model
        if model is None:
            logger.info("Loading ML model for automation...")
            model_loaded = auto_load_ml_model()

            if model_loaded:
                automation_manager.complete_step('ml_loading', {'status': 'Model loaded'})
                logger.info("ML model auto-loaded successfully.")
            
            else:
                automation_manager.status = "Failed"
                logger.error("Failed to auto-load ML model.")
                return
        else:
            automation_manager.complete_step('ml_loading', {'status': 'Model already loaded'})
            logger.info("ML model is already loaded.")

        time.sleep(3) # Ensure file is ready 

        # 5. Automatically analyze the captured data
        if os.path.exists(capture_file):
            analysis_results = auto_analyze_captured_data(capture_file, attack_type, target_ip)

            if analysis_results:
                automation_manager.complete_step('data_analysis', analysis_results)
                automation_manager.complete_automation(analysis_results)
                logger.info("Captured data analyzed successfully.")

                cache.set('automation_results', {
                    'analysis': analysis_results,
                    'capture_file': capture_file,
                    'attack_type': attack_type,
                    'target_ip': target_ip,
                    'completed_at': datetime.now().isoformat()
                }, timeout=3600) # Cache for 1 hour
            
            else:
                automation_manager.status = "analysis_failed"
                logger.error("Failed to analyze captured data.")
        else:
            automation_manager.status = "file_not_found"
            logger.error("Capture file not found for analysis.")
    
    except Exception as e:
        automation_manager.status = "Error"
        logger.error(f"Automation scheduling error: {e}")

def auto_load_ml_model():

    global model, accuracy, ml_status

    try:

        # Adjust the path as needed to load the trained model
        # model_path = (r'C:\Users\nakam\Documents\zero-touch-5g-sec-ai\backend\app\model\vanilla_lstm_model.pkl')
        model_path = os.path.join(settings.BASE_DIR, 'app','model', 'vanilla_lstm_model.pkl')

        alternative_path = [os.path.join(os.path.dirname(__file__), 'model', 'vanilla_lstm_model.pkl'),
                            '/app/app/model/vanilla_lstm_model.pkl',
                            './app/model/vanilla_lstm_model.pkl',
        ]

        model_file_found = False
        actual_model_path = None

        if os.path.exists(model_path):
            model_file_found = True
            actual_model_path = model_path
        
        else:
            for alt_path in alternative_path:
                if os.path.exists(alt_path):
                    model_file_found = True
                    actual_model_path = alt_path
                    break

        if model_file_found:
            model = joblib.load(actual_model_path)
            logger.info("Model loaded successfully!")
            ml_status = "ML model is available and ready to be used."
            accuracy = "91.01%"
            return True
        
        else:
            logger.error(f"Error loading model: {e}")
            ml_status = "Failed to load ML model."
            return False

    except Exception as e:
        logger.error(f"Error loading model: {e}")
        ml_status = "Failed to load ML model."
        return False

def auto_analyze_captured_data(capture_file, attack_type, target_ip):
    global model, detection, attack_level, attack_severity_num, accuracy
    global analysis_report, mitigation

    if not model:
        logger.error("ML model is not loaded.")
        return None
    
    try:
        packets = rdpcap(capture_file)

        if len(packets) == 0:
            logger.warning("Error: No packets of data found.")
            return None
        
        packet = packets[0]
        
        capture_instance = NetworkTrafficCapture()
        features = capture_instance.extract_features(packet)

        if not features:
            logger.warning("Error: No features extracted.")
            return None

        feature_list = [
            features.get('frame.time_relative', 0.0),
            features.get('ip.len', 0),
            features.get('tcp.flags.syn', 0),
            features.get('tcp.flags.ack', 0),
            features.get('tcp.flags.push', 0),
            features.get('tcp.flags.fin', 0),
            features.get('tcp.flags.reset', 0),
            features.get('ip.proto', 0),
            features.get('ip.ttl', 0),
            features.get('tcp.window_size_value', 0),
            features.get('tcp.hdr_len', 0),
            features.get('udp.length', 0),
            features.get('srcport', 0),
            features.get('dstport', 0)
            ]

        # Reshape the data into 3D array to fit in LSTM input format
        data_array = np.array(feature_list).reshape(1, 1, 14)

        # Make prediction
        prediction = model.predict(data_array)

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

        feature_dict = {}

        for i, value in enumerate(feature_list):
            if i < len(feature_names):
                feature_dict[feature_names[i]] = value
            else:
                feature_dict[f'feature_{i+1}'] = value

        # Determine attack severity level
        attack_level, attack_severity_num, analysis_report = severity_analyzer.decide_attack_level(detection, feature_dict, anomaly_score=0.5)
        logger.info(f"Attack detected: {detection}, Severity Level: {attack_level}, Severity Num: {attack_severity_num}")

        # Set attack status and mitigation based on detection results
        if detection == "Benign":
            mitigation = "No action needed"

        #else:  
            #mitigation = AIMitigation.get_mitigation(detection, analysis_report)
        
        accuracy = "91.01%"

        auto_analysis_results = {
            'detection': detection,
            'attack_level': attack_level,
            'attack_severity_num': attack_severity_num,
            'accuracy': accuracy,
            'mitigation': mitigation,
            'analysis_report': analysis_report,
            'expected_attack': attack_type,
            'target_ip': target_ip,
            'capture_file': capture_file,
            'total_packets': len(packets),
            'timestamp': datetime.now().isoformat()
        }

        logger.info(f"Analysis Results: {auto_analysis_results}")
        return auto_analysis_results
    
    except Exception as e:
        logger.error(f"Error analyzing captured data: {e}")
        return None
    
def get_automation_status(request):
    if request.method == "GET":
        status = automation_manager.get_status()

        # Check for completed results in cache
        automation_results = cache.get('automation_results', None)

        if automation_results:
            status['results'] = automation_results

        return JsonResponse({
            'status': status,
            'automation': status
        })
    return JsonResponse({'status':'error', 'message': 'Invalid request method'})

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

    global model, detection, attack_level, attack_severity_num, accuracy, connection_status, attack_status, ml_status, target_ip, attack_type, analysis_report, mitigation, auto_analysis_results, latest_capture_file, automation_manager

    automation_results = cache.get('automation_results')

    if automation_results and not detection:
        detection = automation_results['analysis']['detection']
        attack_level = automation_results['analysis']['attack_level']
        attack_severity_num = automation_results['analysis']['attack_severity_num']
        accuracy = automation_results['analysis']['accuracy']
        mitigation = automation_results['analysis']['mitigation']
        analysis_report = automation_results['analysis']['analysis_report']

        messages.info(request, "Automation completed. Results are available.")

        cache.delete('automation_results')

    if request.method == 'POST' and model is not None:
        form = CapturedDataForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES.get('captured_data')
            captured_text = form.cleaned_data.get('captured_text', '').strip()
            data = None
            accuracy = "91.01%"

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

                    elif filename.endswith('.pcap', '.pcapng'):
                        # Handle PCAP format
                        file_content = uploaded_file.read()
                        temp_filename = f"temp_{filename}"
                        with open(temp_filename, "wb") as f:
                            f.write(file_content)
                        

                        try:

                            packets = rdpcap(temp_filename)

                            if len(packets) == 0:
                                detection = "Error: No packets of data found."
                                if os.path.exists(temp_filename):
                                    os.remove(temp_filename)
                                return render(request, 'index.html', {'form': form, 'detection': detection})
                            
                            packet = packets[0]
                            
                            capture_instance = NetworkTrafficCapture()
                            features = capture_instance.extract_features(packet)

                            if features:
                                data = [
                                    features.get('frame.time_relative', 0.0),
                                    features.get('ip.len', 0),
                                    features.get('tcp.flags.syn', 0),
                                    features.get('tcp.flags.ack', 0),
                                    features.get('tcp.flags.push', 0),
                                    features.get('tcp.flags.fin', 0),
                                    features.get('tcp.flags.reset', 0),
                                    features.get('ip.proto', 0),
                                    features.get('ip.ttl', 0),
                                    features.get('tcp.window_size_value', 0),
                                    features.get('tcp.hdr_len', 0),
                                    features.get('udp.length', 0),
                                    features.get('srcport', 0),
                                    features.get('dstport', 0)
                                ]
                                
                        except Exception as e:
                            logger.warning(f"Error processing data packet: {e}")
                            detection = f"Error: Processing file failed - {str(e)}"
                            return render(request, 'index.html', {'form': form, 'detection': detection})

                        data = [float(len((x))) for x in packets[:14]]

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
                        data = [float(x) for x in row[:14]]

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
                                   'mitigation': "N/A",
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
                    mitigation = AIMitigation.get_mitigation(detection, analysis_report)
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
                       'captured_text': request.POST.get('captured_text', ''),
                       'auto_analysis_results': auto_analysis_results,
                       'latest_capture_file': latest_capture_file,
                       'automation_status': automation_manager.get_status()
                       })

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
                   'captured_text': '',
                   'auto_analysis_results': auto_analysis_results,
                   'latest_capture_file': latest_capture_file,
                   'automation_status': automation_manager.get_status()
                   })