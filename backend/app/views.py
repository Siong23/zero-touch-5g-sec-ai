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
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

from django.http import JsonResponse
from django.http import HttpResponseRedirect
from django.urls import path, reverse

from .forms import CapturedDataForm
from detection.settings import RAN5G_CONFIG

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

live_flows_buffer = deque()
flow_stats = {'benign': 0, 'suspicious': 0, 'malicious': 0}
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
mitigation_flows_buffer = deque() # Store last 50 mitigation actions
mitigation_stats = {'applied': 0, 'pending': 0, 'failed': 0}
capture_thread = None
capture_active = False
capture_mode = None
latest_capture_file = None

class AutomationManager:
    def __init__(self):
        self.current_task = None
        self.progress = 0
        self.status = "Idle"
        self.results = {}
        self.step_results = {}

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
        self.results = {}
        self.step_results = {}
        logger.info(f"Automation started for {attack_type} on {target_ip}")
        return True
    
    def get_status(self):

        return {
            'status': self.status,
            'progress': self.progress,
            'current_task': self.current_task,
            'results': self.results,
            'step_results': self.step_results
        }
    
    def complete_step(self, step_name, results=None):
        if self.current_task and step_name in self.current_task['steps']:
            step_index = self.current_task['steps'].index(step_name)
            self.progress = int(((step_index + 1) / len(self.current_task['steps'])) * 100)
           
            if results:
                self.step_results[step_name] = results

            logger.info(f"Step completed: {step_name} ({self.progress}%)")
            
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
        self.capture_file_path = None
        self.live_monitoring = False
        self.ssh_client = None
        self.capture_process = None
    
    def get_active_interface(self):
        try:
            # Get the configured interface from settings
            configured_interface = RAN5G_CONFIG.get('NETWORK_INTERFACE', 'ens18')
            logger.info(f"Using configured interface: {configured_interface}")
            return configured_interface
            
        except Exception as e:
            logger.error(f"Error checking network interface: {e}")
            # Return the default configured interface even on error
            return RAN5G_CONFIG.get('NETWORK_INTERFACE', 'ens18')

    # Start live monitoring without saving to file
    def start_live_monitoring_only(self):
        global capture_active, live_flows_buffer, flow_stats, capture_mode

        if capture_active:
            logger.warning("Capture already running")
            return False
        
        try:
            # Pre-flight checks
            logger.info("Starting live monitoring pre-flight checks...")

            test_ssh = paramiko.client.SSHClient()
            test_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            test_ssh.connect('100.65.52.69', username='ran', password='mmuzte123', timeout=10)
            
            # Test if tcpdump is available
            stdin, stdout, stderr = test_ssh.exec_command("which tcpdump")
            tcpdump_path = stdout.read().decode('utf-8').strip()
            
            if not tcpdump_path:
                logger.error("tcpdump not found on remote system")
                test_ssh.close()
                return False
            
            logger.info(f"tcpdump found at: {tcpdump_path}")
            
            # Test interface
            stdin, stdout, stderr = test_ssh.exec_command(f"sudo ip link show {self.capture_interface}")
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if error or 'does not exist' in output.lower():
                logger.error(f"Interface {self.capture_interface} not found: {error}")
                test_ssh.close()
                return False
            
            logger.info(f"Interface {self.capture_interface} is available")
            test_ssh.close()

            capture_mode = 'live_monitoring'
            capture_active = True
            self.live_monitoring = True

            live_flows_buffer.clear()
            flow_stats['benign'] = 0
            flow_stats['suspicious'] = 0
            flow_stats['malicious'] = 0

            logger.info(f"Starting live monitor thread on interface {self.capture_interface}")
            
                        # Start monitoring in a separate thread
            monitor_thread = threading.Thread(
                target=self.live_monitor_packets, 
                daemon=True,
                name="LiveMonitorThread"
            )
            monitor_thread.start()
            
            # Give it a moment to initialize
            time.sleep(2)
            
            # Verify thread is actually running
            if monitor_thread.is_alive():
                logger.info("[OK] Live monitoring thread started successfully")
                return True
            else:
                logger.error("[FAILED] Monitor thread died immediately")
                capture_active = False
                self.live_monitoring = False
                capture_mode = None
                return False

        except Exception as e:
            logger.error(f"[ERROR] Error starting live monitoring: {e}")
            import traceback
            logger.error(traceback.format_exc())
            capture_active = False
            self.live_monitoring = False
            capture_mode = None
            return False
    
    # Monitor packets in real time without saving
    def live_monitor_packets(self):
        global capture_active, live_flows_buffer, flow_stats, mitigation_flows_buffer

        try:
            import asyncio
            # Ensure async features can work in this thread
            try:
                asyncio.set_event_loop(asyncio.new_event_loop())
            except Exception:
                pass

            logger.info(f"[MONITOR] Starting live monitoring on {self.capture_interface}")

            ssh = paramiko.client.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect('100.65.52.69', username='ran', password='mmuzte123', timeout=30)

            # Verify interface availability
            test_cmd = f"sudo ip link show {self.capture_interface}"
            stdin, stdout, stderr = ssh.exec_command(test_cmd)
            test_output = stdout.read().decode('utf-8')
            test_error = stderr.read().decode('utf-8')
            if test_error or 'does not exist' in test_output.lower():
                logger.error(f"Interface {self.capture_interface} not found or not accessible")
                ssh.close()
                return

            # Start tcpdump (unbuffered, continuous output)
            tcpdump_cmd = f"sudo tcpdump -i {self.capture_interface} -U -n -tttt 2>&1"
            logger.info(f"[MONITOR] Executing: {tcpdump_cmd}")

            transport = ssh.get_transport()
            channel = transport.open_session()
            channel.get_pty(term='vt100', width=200, height=24)
            channel.exec_command(tcpdump_cmd)

            # Send sudo password if prompted
            time.sleep(0.5)
            if channel.recv_ready():
                prompt = channel.recv(1024).decode('utf-8', errors='ignore')
                if '[sudo]' in prompt or 'password' in prompt.lower():
                    channel.send('mmuzte123\n')
                    time.sleep(1)

            packet_count = 0
            buffer = ""
            line_count = 0
            last_data_time = time.time()
            idle_timeout = 60  # seconds before considering it idle
            reconnect_delay = 5

            channel.settimeout(2.0)  # longer read timeout

            logger.info("[MONITOR] Reading tcpdump output...")

            while capture_active and self.live_monitoring:
                try:
                    current_time = time.time()

                    # Attempt to read stdout
                    if channel.recv_ready():
                        data = channel.recv(4096).decode('utf-8', errors='ignore')
                        if data:
                            buffer += data
                            last_data_time = current_time

                    # Attempt to read stderr
                    if channel.recv_stderr_ready():
                        err_data = channel.recv_stderr(4096).decode('utf-8', errors='ignore')
                        if err_data:
                            buffer += err_data
                            last_data_time = current_time

                    # Process complete lines
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        line = line.strip()
                        if not line:
                            continue

                        # Ignore meta lines
                        if any(x in line.lower() for x in ['tcpdump:', 'listening on', 'captured', 'kernel', 'dropped']):
                            continue

                        line_count += 1
                        packet_count += 1

                        flow = self.parse_tcpdump_line(line, packet_count)
                        if flow:
                            live_flows_buffer.append(flow)
                            classification = flow.get('classification', 'benign')

                            if classification == 'malicious':
                                flow_stats['malicious'] += 1
                                attack_type = flow.get('attack_type', 'Unknown')
                                target_ip = flow.get('src_ip', 'Unknown')

                                logger.info(f"[ALERT] Malicious flow detected: {attack_type} from {target_ip}")

                                threading.Thread(
                                    target=self._apply_mitigation_async,
                                    args=(attack_type, target_ip, flow),
                                    daemon=True
                                ).start()

                            elif classification == 'suspicious':
                                flow_stats['suspicious'] += 1
                            else:
                                flow_stats['benign'] += 1

                        if packet_count % 10 == 0:
                            logger.info(f"[MONITOR] {packet_count} packets, Stats={flow_stats}")

                    # Check for idle timeout
                    if current_time - last_data_time > idle_timeout:
                        logger.warning("[MONITOR] No data received for a while — reconnecting tcpdump...")
                        break  # Exit to reconnect loop

                    # Check if tcpdump exited
                    if channel.exit_status_ready():
                        exit_status = channel.recv_exit_status()
                        logger.warning(f"[MONITOR] tcpdump exited with status {exit_status}")
                        break

                    time.sleep(0.2)

                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"[MONITOR] Error reading packet: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    break

            # Cleanup connection
            try:
                channel.close()
            except:
                pass
            ssh.close()
            logger.info(f"[MONITOR] Live monitoring stopped. Total packets: {packet_count}")

            # Auto-reconnect if monitoring should continue
            if capture_active and self.live_monitoring:
                logger.info(f"[MONITOR] Restarting monitoring after {reconnect_delay}s delay...")
                time.sleep(reconnect_delay)
                self.live_monitor_packets()

        except Exception as e:
            logger.error(f"[MONITOR] Fatal error during live monitoring: {e}")
            import traceback
            logger.error(traceback.format_exc())
        finally:
            capture_active = False
            self.live_monitoring = False
            logger.info("[MONITOR] Cleanup complete")

    def parse_tcpdump_line(self, line, packet_count):
        try:
            # Skip empty lines and tcpdump status messages
            if not line or 'listening on' in line or 'captured' in line:
                return None
            
            parts = line.split()
            if len(parts) < 6:
                return None
            
            # Initialize defaults
            protocol = 'Other'
            src_ip = 'Unknown'
            dst_ip = 'Unknown'
            src_port = 0
            dst_port = 0
            attack_type = "Normal Traffic"
            classification = 'benign'
            packet_size = 60
            
            # Find IP keyword position
            ip_idx = -1
            for i, part in enumerate(parts):
                if part == 'IP' or part == 'IP6':
                    ip_idx = i
                    break
            
            if ip_idx == -1:
                return None
            
            # Parse source (after IP keyword)
            if ip_idx + 1 < len(parts):
                src = parts[ip_idx + 1]
                if '.' in src or ':' in src:
                    # Handle IP.port or IP:port format
                    if src.count('.') > 3:  # Has port
                        src_parts = src.rsplit('.', 1)
                        src_ip = src_parts[0]
                        try:
                            src_port = int(src_parts[1])
                        except:
                            src_port = 0
                    else:
                        src_ip = src.rstrip(':')
            
            # Find destination (after '>')
            dst_idx = -1
            for i, part in enumerate(parts):
                if part == '>':
                    dst_idx = i
                    break
            
            if dst_idx > 0 and dst_idx + 1 < len(parts):
                dst = parts[dst_idx + 1].rstrip(':')
                if '.' in dst or ':' in dst:
                    if dst.count('.') > 3:  # Has port
                        dst_parts = dst.rsplit('.', 1)
                        dst_ip = dst_parts[0]
                        try:
                            dst_port = int(dst_parts[1])
                        except:
                            dst_port = 0
                    else:
                        dst_ip = dst.rstrip(':')
            
            # Determine protocol and attack type
            line_lower = line.lower()

            cache_key = f"packet_rate_{src_ip}_{dst_ip}"
            packet_history = cache.get(cache_key, [])
            packet_history.append(time.time())

            cutoff = time.time() - 10
            packet_history = [t for t in packet_history if t > cutoff]
            cache.set(cache_key, packet_history, timeout=60)

            packet_rate = len(packet_history) / 10.0
            
            if 'icmp' in line_lower:
                protocol = 'ICMP'
                if packet_count > 10:  # High rate detection
                    attack_type = 'ICMP Flood Attack'
                    classification = 'malicious'
                elif packet_count > 5:
                    attack_type = "Possible ICMP Flood"
                    classification = 'suspicious'
                else:
                    attack_type = 'ICMP Traffic'

            elif '[S]' in line and '[.]' not in line:
                protocol = 'TCP'
                if packet_count > 20:  # High rate detection
                    attack_type = 'SYN Flood Attack'
                    classification = 'malicious'
                elif packet_count > 10:
                    attack_type = "Possible SYN Scan"
                    classification = 'suspicious'
                else:
                    attack_type = 'SYN Packet'
            elif 'udp' in line_lower:
                protocol = 'UDP'
                if packet_count > 50:  # High rate detection
                    attack_type = 'UDP Flood Attack'
                    classification = 'malicious'
                elif packet_count > 25:
                    attack_type = "Possible UDP Flood"
                    classification = 'suspicious'
                else:
                    attack_type = 'UDPTraffic'
            elif 'tcp' in line_lower or '[.]' in line or '[P]' in line or '[F]' in line:
                protocol = 'TCP'
                attack_type = 'TCP Traffic'
            
            # Extract packet size if present
            try:
                for i, part in enumerate(parts):
                    if 'length' in part.lower():
                        if i + 1 < len(parts):
                            size_str = parts[i + 1].replace(':', '').replace(',', '')
                            packet_size = int(size_str)
                            break
            except:
                pass
            
            confidence = 90.0 if classification == 'malicious' else (75.0 if classification == 'suspicious' else 60.0)
            
            return {
                'timestamp': datetime.now().isoformat(),
                'classification': classification,
                'attack_type': attack_type,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': protocol,
                'bytes': packet_size,
                'packets': 1,
                'confidence': confidence,
                'packet_rate': round(packet_rate, 2)
            }
        
        except Exception as e:
            logger.debug(f"Parse error: {e} | Line: {line[:100]}")
            return None

    # Start capturing packets from Open5Gs network (Current - Stop automatically after 30s)
    def start_capture_with_auto_analysis(self, duration=60, attack_type=None, target_ip=None):

        global capture_active, capture_thread, latest_capture_file

        if capture_active:
            logger.warning("Capture already running")
            return False, None
        
        if self.live_monitoring:
            logger.warning("Live monitoring is active. Cannot start dedicated capture.")
            return False, None
        
        try:
            timestamp = int(time.time())
            filename = f"{attack_type}_{timestamp}.pcap"
            filepath = os.path.join(settings.BASE_DIR, 'captures', filename)

            os.makedirs(os.path.dirname(filepath), exist_ok=True)

            capture_active = True
            self.live_monitoring = False
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
        global capture_active, live_flows_buffer, flow_stats, captture_mode

        ssh = None
        channel = None
        success = False

        try:
            if capture_mode == 'dedicated_capture':
                live_flows_buffer.clear()
                flow_stats['benign'] = 0
                flow_stats['malicious'] = 0
                flow_stats['suspicious'] = 0
                logger.info("Buffer cleared for dedicated capture")
            else:
                logger.info("Preserving buffer - live monitoring mode active")

            capture_filter = self._get_capture_filter(attack_type, target_ip)

            logger.info(f"Starting packet capture with filter: {capture_filter}")

            ssh = paramiko.client.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect('100.65.52.69', username='ran', password='mmuzte123')

            # Build tcpdump command with filter - use text output for parsing
            if capture_filter:
                tcpdump_cmd = f"timeout {duration} sudo tcpdump -i {self.capture_interface} -U -n -tttt host {target_ip} 2>&1"
            else:
                tcpdump_cmd = f"timeout {duration} sudo tcpdump -i {self.capture_interface} -U -n -tttt 2>&1"
            
            logger.info(f"Executing: {tcpdump_cmd}")

            # Open SSH channel for streaming output
            transport = ssh.get_transport()
            channel = transport.open_session()
            channel.get_pty(term='vt100', width=200, height=24)
            channel.exec_command(tcpdump_cmd)
            
            # Handle sudo password if needed
            time.sleep(0.5)
            if channel.recv_ready():
                prompt = channel.recv(1024).decode('utf-8', errors='ignore')
                if '[sudo]' in prompt or 'password' in prompt.lower():
                    channel.send('mmuzte123\n')
                    time.sleep(1)

            packet_count = 0
            buffer = ""
            last_data_time = time.time()

            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Also save raw output to file for later analysis
            with open(filepath, 'w') as pcap_file:
                channel.settimeout(0.5)
                
                while capture_active and self.live_monitoring:
                    try:
                        current_time = time.time()
                        
                        # Timeout check
                        if current_time - last_data_time > 30:
                            logger.warning("No data received for 30 seconds")
                            break
                        
                        # Read data
                        data_received = False
                        
                        if channel.recv_ready():
                            data = channel.recv(4096).decode('utf-8', errors='ignore')
                            if data:
                                buffer += data
                                pcap_file.write(data)  # Save to file
                                pcap_file.flush()
                                data_received = True
                                last_data_time = current_time
                        
                        if channel.recv_stderr_ready():
                            stderr_data = channel.recv_stderr(4096).decode('utf-8', errors='ignore')
                            if stderr_data:
                                buffer += stderr_data
                                data_received = True
                                last_data_time = current_time
                        
                        if not data_received:
                            if channel.exit_status_ready():
                                break
                            continue
                        
                        # Process complete lines for live monitoring
                        while '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)
                            line = line.strip()
                            
                            if not line:
                                continue
                            
                            # Skip tcpdump meta-output
                            if any(x in line.lower() for x in ['tcpdump:', 'listening on', 'captured', 'kernel', 'dropped']):
                                continue
                            
                            # Parse packet line and create flow
                            packet_count += 1
                            flow = self.parse_tcpdump_line(line, packet_count)
                            
                            if flow:
                                # Add to live buffer for real-time display
                                live_flows_buffer.append(flow)
                                
                                # Update stats
                                classification = flow.get('classification', 'benign')
                                if classification == 'malicious':
                                    flow_stats['malicious'] += 1
                                elif classification == 'suspicious':
                                    flow_stats['suspicious'] += 1
                                else:
                                    flow_stats['benign'] += 1
                                
                                # Log progress
                                if packet_count % 50 == 0:
                                    logger.info(f"Captured {packet_count} packets, live buffer: {len(live_flows_buffer)}")
                    
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logger.error(f"Error reading packet: {e}")
                        break
            
            # Cleanup
            try:
                channel.close()
            except:
                pass
            
            ssh.close()
            
            success = os.path.exists(filepath) and os.path.getsize(filepath) > 0
            
            if success:
                logger.info(f"Capture completed: {packet_count} packets, file: {filepath}")
            else:
                logger.warning("Capture file is empty or not created")
                
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            import traceback
            logger.error(traceback.format_exc())
            success = False
        
        finally:
            if capture_mode == 'dedicated_capture':
                capture_active = False
                self.live_monitoring = False
            logger.info(f"Capture cleanup complete. Total flows in buffer: {len(live_flows_buffer)}")

    def _get_capture_filter(self, attack_type, target_ip):
        filters = {
            'ICMPFlood': f'icmp and (src host {target_ip} or dst host {target_ip})',
            'HTTPFlood': f'tcp port 80 and (src host {target_ip} or dst host {target_ip})',
            'SYNFlood': f'tcp[tcpflags] & tcp-syn != 0 and (src host {target_ip} or dst host {target_ip})',
            'UDPFlood': f'udp and (src host {target_ip} or dst host {target_ip})',
            'SYNScan': f'tcp[tcpflags] & tcp-syn != 0 and (src host {target_ip} or dst host {target_ip})',
            'TCPConnectScan': f'tcp and (src host {target_ip} or dst host {target_ip})',
            'UDPScan': f'udp and (src host {target_ip} or dst host {target_ip})',
            'SlowrateDoS': f'tcp port 80 and (src host {target_ip} or dst host {target_ip})'
        }
        
        filter_str = filters.get(attack_type, f'host {target_ip}')
        logger.info(f"Generated capture filter for {attack_type}: {filter_str}")
        return filter_str
    
    def process_pyshark_packet(self, packet):
        global capture_active, live_flows_buffer, flow_stats

        try:
            # Extract basic info from PyShark packet
            src_ip = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
            
            protocol = 'Unknown'
            src_port = 0
            dst_port = 0
            
            if hasattr(packet, 'tcp'):
                protocol = 'TCP'
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
            elif hasattr(packet, 'udp'):
                protocol = 'UDP'
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
            elif hasattr(packet, 'icmp'):
                protocol = 'ICMP'

            # Create flow object
            flow = {
                'timestamp': datetime.now().isoformat(),
                'classification': 'benign',
                'attack_type': 'Normal Traffic',
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': protocol,
                'bytes': int(packet.length) if hasattr(packet, 'length') else 0,
                'packets': 1,
                'confidence': 0.0
            }

            # Add flow object to buffer
            live_flows_buffer.append(flow)
            flow_stats['benign'] += 1
        
        except Exception as e:
            logging.debug(f"Error processing packet: {e}")

    # Process scapy packet and add to live flow
    def process_packet_realtime(self, packet):
        global capture_active, live_flows_buffer, flow_stats

        try:
            features = self.extract_features(packet)
            if not features:
                return
            
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

            classification = 'benign'
            attack_type = 'Normal Traffic'
            confidence = 0.0

            if model:
                try:
                    from app.views import perform_detection
                    detection_result = perform_detection(feature_list)
                    attack_type = detection_result.get('attack_type', 'Unknown')
                    classification = 'benign' if attack_type == 'Benign' else 'malicious'
                    confidence = detection_result.get('confidence', 0.0) * 100
                
                except Exception as e:
                    logging.debug(f"Error in ML classification: {e}")

            # Extract network info
            src_ip = packet[IP].src if packet.haslayer(IP) else 'N/A'
            dst_ip = packet[IP].dst if packet.haslayer(IP) else 'N/A'
            src_port = features.get('srcport', 0)
            dst_port = features.get('dstport', 0)

            # Determine protocol
            if packet.haslayer(TCP):
                protocol = 'TCP'
            elif packet.haslayer(UDP):
                protocol = 'UDP'
            elif packet.haslayer(ICMP):
                protocol = 'ICMP'
            else:
                protocol = 'Other'

            # Create flow object
            flow = {
                'timestamp': datetime.now().isoformat(),
                'classification': classification,
                'attack_type': attack_type,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': protocol,
                'bytes':int(features.get('ip.len', 0)),
                'packets': 1,
                'confidence': round(confidence, 1)
            }

            # Add flow object to buffer
            live_flows_buffer.append(flow)

            # Update stats
            if classification == 'benign':
                flow_stats['benign'] += 1
            
            elif classification == 'malicious':
                flow_stats['malicious'] += 1

            else:
                flow_stats['suspicious'] += 1

            logging.debug(f"Live flow added: {attack_type} from {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        except Exception as e:
            logging.error(f"Error processing packet for live monitoring: {e}")

    def extract_features(self, packet):
        try:
            features = {}

            # Frame time - handle different packet formats
            if hasattr(packet, 'time'):
                features['frame.time_relative'] = float(packet.time)
            elif hasattr(packet, 'timestamp'):
                features['frame.time_relative'] = float(packet.timestamp)
            else:
                features['frame.time_relative'] = 0.0

            # IP length
            features['ip.len'] = float(len(packet)) if packet.haslayer(IP) else 0.0

            # TCP features
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                features['tcp.flags.syn'] = 1.0 if tcp_layer.flags & 0x02 else 0.0
                features['tcp.flags.ack'] = 1.0 if tcp_layer.flags & 0x10 else 0.0
                features['tcp.flags.push'] = 1.0 if tcp_layer.flags & 0x08 else 0.0
                features['tcp.flags.fin'] = 1.0 if tcp_layer.flags & 0x01 else 0.0
                features['tcp.flags.reset'] = 1.0 if tcp_layer.flags & 0x04 else 0.0
                features['tcp.window_size_value'] = float(tcp_layer.window) if tcp_layer.window else 0.0
                features['tcp.hdr_len'] = float(tcp_layer.dataofs * 4) if tcp_layer.dataofs else 20.0
                features['srcport'] = float(tcp_layer.sport) if tcp_layer.sport else 0.0
                features['dstport'] = float(tcp_layer.dport) if tcp_layer.dport else 0.0
            else:
                # Default TCP features
                features.update({
                    'tcp.flags.syn': 0.0, 'tcp.flags.ack': 0.0, 'tcp.flags.push': 0.0,
                    'tcp.flags.fin': 0.0, 'tcp.flags.reset': 0.0, 'tcp.window_size_value': 0.0,
                    'tcp.hdr_len': 0.0, 'srcport': 0.0, 'dstport': 0.0
                })

            # IP features
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                features['ip.proto'] = float(ip_layer.proto) if ip_layer.proto else 0.0
                features['ip.ttl'] = float(ip_layer.ttl) if ip_layer.ttl else 0.0
            else:
                features['ip.proto'] = 0.0
                features['ip.ttl'] = 0.0

            # UDP features
            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                features['udp.length'] = float(len(udp_layer)) if udp_layer else 0.0
                # Override ports for UDP packets if TCP ports weren't set
                if not packet.haslayer(TCP):
                    features['srcport'] = float(udp_layer.sport) if udp_layer.sport else 0.0
                    features['dstport'] = float(udp_layer.dport) if udp_layer.dport else 0.0
            else:
                features['udp.length'] = 0.0

            # Validate all values are numeric
            for key, value in features.items():
                if not isinstance(value, (int, float)):
                    logger.warning(f"Non-numeric feature {key}: {value} (type: {type(value)})")
                    features[key] = 0.0
                elif np.isnan(value) or np.isinf(value):
                    logger.warning(f"Invalid numeric value for {key}: {value}")
                    features[key] = 0.0

            logger.debug(f"Extracted features: {features}")
            return features

        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            logger.error(f"Packet info: {packet.summary() if hasattr(packet, 'summary') else 'Unknown packet'}")
            return None
        
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

            packets_to_analyze = packets[:200]
            logger.info(f"Analyzing {len(packets_to_analyze)} packets from capture.")

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

                from app.views import perform_detection
                detection_result = perform_detection(feature_list)
                analysis_results['detections'].append(detection_result)
            
                return analysis_results

        except Exception as e:
            logger.error(f"Error analyzing capture file: {e}")
            return None

def chrome_devtools_json(request):
    return JsonResponse({}, status=200)   

network_capture = NetworkTrafficCapture()

# Create API endpoint to start live traffic network monitoring
@csrf_exempt
@require_http_methods(["POST"])
def start_live_monitoring(request):
    global network_capture, connection_status
    try:
        ssh = paramiko.client.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Modify the (HOST, USERNAME, PASSWORD) as needed to connect to the server
        ssh.connect('100.65.52.69', username='ran', password='mmuzte123')
        connection_status = "Connected to 5G Network"

        success = network_capture.start_live_monitoring_only()

        if success:
            return JsonResponse({
                'status': 'success',
                'message': 'Live monitoring started',
                'connection_status': connection_status
            }, status=200)
        
        else:
            return JsonResponse({
                'status': 'error',
                'message': 'Failed to start monitoring',
                'connection_status': connection_status
            }, status=500)

        
    except Exception as e:
        logger.error(f"Error starting live monitoring: {e}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

# Create API endpoint to stop live traffic network monitoring
@csrf_exempt
@require_http_methods(["POST"])
def stop_live_monitoring(request):
    global network_capture, capture_active, connection_status

    try:
        capture_active = False
        if network_capture:
            network_capture.live_monitoring = False
            network_capture.capture_active = False
            connection_status = "Not connected"

        logger.info("Live monitoring stopped successfully")

        return JsonResponse({
            'status': 'success',
            'message': 'Live monitoring stopped',
            'connection_status': connection_status
        })
         
    except Exception as e:
        logger.error(f"Error starting live monitoring: {e}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

# Create API endpoints to get live traffic network flows
@require_http_methods(["GET"])
def get_live_flows(request):
    global live_flows_buffer, flow_stats, connection_status

    try:
        flows_list = list(live_flows_buffer)

        logger.debug(f"[FLOWS API] Request received")
        logger.debug(f"[FLOWS API] Buffer size: {len(flows_list)}")
        logger.debug(f"[FLOWS API] Stats: {flow_stats}")
        logger.debug(f"[FLOWS API] Capture active: {capture_active}")
        logger.debug(f"[FLOWS API] Connection status: {connection_status}")

        # Display most recent 20 flows
        recent_flows = flows_list[-20:] if len(flows_list)>20 else flows_list

        # Revrse to show newest flow first
        recent_flows.reverse()

        if len(recent_flows) > 0:
            logger.info(f"Returning {len(recent_flows)} flows to frontend")
        else:
            logger.warning("No flows available to return")

        response_data = {
                    'status': 'success',
                    'flows': recent_flows,
                    'stats': flow_stats,
                    'total_flows': len(flows_list),
                    'connection_status': connection_status,
                    'capture_active': capture_active,
                    'timestamp': datetime.now().isoformat()
                }

        logger.debug(f"[FLOWS API] Response: {len(recent_flows)} flows, stats={flow_stats}")

        return JsonResponse(response_data)

    except Exception as e:
        logging.error(f"Error fetching live flows: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return JsonResponse({'status': 'error',
                             'message': str(e),
                             'flows': [],
                             'stats': flow_stats,
                             'connection_status': connection_status,
                             'capture_active': False})
    
# Check if network monitoring is active or not
@require_http_methods(["GET"])
def get_flow_status(request):
    global capture_active, network_capture

    return JsonResponse({
        'monitoring_active': capture_active,
        'interface': network_capture.capture_interface if network_capture else 'N/A',
        'capture_file': network_capture.capture_file_path if network_capture else None
    })

# Reset flow statistics
@csrf_exempt
@require_http_methods(["POST"])
def reset_flow_stats(request):
    global flow_stats, live_flows_buffer

    flow_stats = {'benign': 0, 'suspicious': 0, 'malicious': 0}
    live_flows_buffer.clear()

    return JsonResponse({'status': 'success',
                         'message': 'Flow statistics reset'})

# Create API endpoints to receive data from the Open5gs network host
@csrf_exempt
def receive_network_data(request):

    global connection_status

    if request.method == 'POST':
        try:

            ssh = paramiko.client.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Modify the (HOST, USERNAME, PASSWORD) as needed to connect to the server
            ssh.connect('100.80.157.112', username='core', password='mmuzte123', timeout=30)
            _stdin, _stdout, _stderr = ssh.exec_command("service open5gs-amfd status")
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
        # Ensure features is a list of numbers
        if not isinstance(features, (list, tuple, np.ndarray)):
            logger.error(f"Features must be a list/array, got: {type(features)}")
            return {'model': 'Error', 'attack_type': 'Invalid input type', 'severity_level': 'N/A'}
        
        # Convert to float list and ensure we have exactly 14 features
        try:
            feature_list = []
            for i, feature in enumerate(features):
                if i >= 14:  # Only take first 14 features
                    break
                # Convert to float, handle None/string values
                if feature is None:
                    feature_val = 0.0
                elif isinstance(feature, str):
                    try:
                        feature_val = float(feature)
                    except ValueError:
                        feature_val = 0.0
                else:
                    feature_val = float(feature)
                feature_list.append(feature_val)
            
            # Pad with zeros if we don't have enough features
            while len(feature_list) < 14:
                feature_list.append(0.0)
            
            # Take only first 14 features
            feature_list = feature_list[:14]
            
        except Exception as e:
            logger.error(f"Error converting features to float list: {e}")
            return {'model': 'Error', 'attack_type': 'Feature conversion failed', 'severity_level': 'N/A'}
        
        logger.debug(f"Processed feature list: {feature_list}")
        logger.debug(f"Feature list length: {len(feature_list)}")
        
        # Create numpy array with explicit dtype
        data_array = np.array(feature_list, dtype=np.float32).reshape(1, 1, 14)
        logger.debug(f"Data array shape: {data_array.shape}, dtype: {data_array.dtype}")
        
        # Make prediction
        prediction = model.predict(data_array)
        logger.debug(f"Raw prediction: {prediction}")
        logger.debug(f"Prediction shape: {prediction.shape}")
        logger.debug(f"Prediction type: {type(prediction)}")
        
        # Handle different prediction output formats
        if len(prediction.shape) > 1 and prediction.shape[1] > 1:
            # Multi-class output - get the class with highest probability
            predicted_class = np.argmax(prediction, axis=1)
            if isinstance(predicted_class, np.ndarray):
                predicted_class = int(predicted_class[0])
            else:
                predicted_class = int(predicted_class)
        else:
            # Single output - convert directly
            if isinstance(prediction, np.ndarray):
                if prediction.size == 1:
                    predicted_class = int(prediction.item())
                else:
                    predicted_class = int(np.round(prediction.flatten()[0]))
            else:
                predicted_class = int(prediction)
        
        logger.debug(f"Predicted class (int): {predicted_class}")

        # Attack type mapping
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
        
        attack_type = attack_types.get(predicted_class, f"Unknown_{predicted_class}")
        
        # Feature names for severity analysis
        feature_names = [
            "frame.time_relative", "ip.len", "tcp.flags.syn", "tcp.flags.ack",
            "tcp.flags.push", "tcp.flags.fin", "tcp.flags.reset", "ip.proto",
            "ip.ttl", "tcp.window_size_value", "tcp.hdr_len", "udp.length",
            "srcport", "dstport"
        ]

        # Create feature dictionary with proper indexing
        feature_dict = {}
        for i in range(min(len(feature_list), len(feature_names))):
            feature_dict[feature_names[i]] = feature_list[i]
        
        # Add any remaining features with generic names
        for i in range(len(feature_names), len(feature_list)):
            feature_dict[f'feature_{i+1}'] = feature_list[i]

        # Get severity analysis
        severity_level, severity_score, traffic_metrics = severity_analyzer.decide_attack_level(
            attack_type, feature_dict, anomaly_score=0.5
        )

        return {
            'model': 'Model loaded',
            'attack_type': attack_type,
            'severity_level': severity_level,
            'severity_score': severity_score,
            'confidence': float(np.max(prediction)) if hasattr(prediction, 'max') else 0.0
        }
        
    except Exception as e:
        logger.error(f"Detection error: {e}")
        logger.error(f"Error details: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {'model': 'Error', 'attack_type': f'Prediction failed: {str(e)}', 'severity_level': 'N/A'}


# Simulate different types of network attacks by injecting attack into the 5G Network
class AttackSimulator:
    def __init__(self, host, username, password):
        self.host = host or "100.65.52.69"
        self.username = username or "ran"
        self.password = password or "mmuzte123"

    def check_target_connectivity(self, target_ip):
        try:
            result = subprocess.run(['ping', '-c', '1', target_ip], capture_output=True, text=True, timeout=15)

            reachable = result.returncode == 0
            logger.info(f"Target {target_ip} reachability: {'Yes' if reachable else 'No'}")
            return reachable
            
        except Exception as e:
            logger.warning(f"Connectivity check failed: {e}")
            return False

    # Trigger a DoS attack (SYNFlood) on the specified target IP
    def trigger_dos_attack(self, target_ip, attack_type):
        try:
            if not self.check_target_connectivity(target_ip):
                logger.warning(f"Target {target_ip} is not reachable. Aborting attack.")

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.host, username=self.username, password=self.password, timeout=30)

            attack_command = {
                'ICMPFlood': f'timeout 45 sudo hping3 -I --flood --rand-source {target_ip}',
                'HTTPFlood': f'timeout 45 sudo hping3 -1 --flood --rand-source {target_ip}',
                'SYNFlood': f'timeout 45 sudo hping3 -S -p 80 --flood --rand-source {target_ip}',
                'UDPFlood': f'timeout 45 sudo hping3 -2 --flood --rand-source -p 80 {target_ip}',
                'SYNScan': f'timeout 45 sudo nmap -sS {target_ip} -p 1-1000 --max-rate 1000 -T4',
                'TCPConnectScan': f'timeout 45 sudo nmap -sT {target_ip} -p 1-1000 --max-rate 500 -T4',
                'UDPScan': f'timeout 45 sudo nmap -sU {target_ip} -p 1-100 --max-rate 300 -T4',
                'SlowrateDoS': f'timeout 45 python3 slowloris.py {target_ip}'
            }

            command = attack_command.get(attack_type)

            if not command:
                logger.error(f"Unknown attack type: {attack_type}")
                ssh.close()
                return False
            
            logger.info(f"Executing attack command: {command}")

            stdin, stdout, stderr = ssh.exec_command(f'nohup {command} > /dev/null 2>&1 &')

            time.sleep(2)

            logger.info(f"{attack_type} attack triggered on {target_ip}")
            ssh.close()
            return True
        
        except paramiko.AuthenticationException:
            logger.error("SSH Authentication failed.")
            return False
        
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error: {e}")
            return False
        
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

# Mitigation strategies based on attack type
class AIMitigation:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
    
    def apply_mitigation(self, attack_type, target_ip, flow_data=None):
        global mitigation_flows_buffer, mitigation_stats
        
        try:
            # Normalize attack type
            attack_type_normalized = attack_type.replace(' ', '').replace('Attack', '')

            # Create mitigation flow entry (optimistic)
            mitigation_flow = {
                'timestamp': datetime.now().isoformat(),
                'attack_type': attack_type,
                'target_ip': target_ip,
                'status': 'pending',
                'action': 'Applying mitigation...',
                'rule': None,
                'success': False
            }
            
            # Add to buffer immediately
            mitigation_flows_buffer.append(mitigation_flow)
            mitigation_stats['pending'] += 1

            ssh = paramiko.client.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.host, username=self.username, password=self.password)

            mitigation_commands = {
                'HTTPFlood': ("sudo iptables -I INPUT -s 192.168.1.1 -j DROP", "Block IP source temporarily"),
                'ICMPFlood': ("sudo iptables -A INPUT -p icmp --icmp-type echo-request -s 192.168.1.1 -j DROP", "Block ICMP echo requests"),
                'SYNFlood': ("sudo iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -s 192.168.1.1 -j DROP", "Drop all SYN packets"),
                'UDPFlood': ("sudo iptables -I INPUT -p udp -s 192.168.1.1 -j DROP", "Block UDP traffic temporarily"),
                'SYNScan': ("sudo iptables -I INPUT -s 192.168.1.1 -j DROP", "Block scanning source temporarily"),
                'TCPConnectScan': ("sudo iptables -I INPUT -s 192.168.1.1 -j DROP", "Block TCP scanning source temporarily"), 
                'UDPScan': ("sudo iptables -I INPUT -p udp -s 192.168.1.1 -j DROP", "Block UDP scanning source temporarily"),
                'SlowrateDoS': ("sudo iptables -I INPUT -s 192.168.1.1 -m connlimit --connlimit-above 10 -j DROP", "Rate-limited connections")
            }

            command = None
            mitigation = None
            
            # Direct match
            if attack_type_normalized in mitigation_commands:
                command, mitigation = mitigation_commands[attack_type_normalized]
            else:
                # Fuzzy match
                for key in mitigation_commands.keys():
                    if key.lower() in attack_type.lower().replace(' ', ''):
                        command, mitigation = mitigation_commands[key]
                        logger.info(f"Fuzzy matched '{attack_type}' to '{key}'")
                        break

            if not command:
                logger.warning(f"No mitigation strategy found for attack type: {attack_type}")
                mitigation_flow['status'] = 'failed'
                mitigation_flow['action'] = f"No mitigation available for {attack_type}"
                mitigation_stats['pending'] -= 1
                mitigation_stats['failed'] += 1
                ssh.close()
                return f"No mitigation strategy available for {attack_type}"
            
            logger.info(f"Executing mitigation command: {command}")

            transport = ssh.get_transport()
            channel = transport.open_session()
            channel.get_pty()
            channel.exec_command(command)
            
            time.sleep(0.5)
            
            if channel.recv_ready():
                output = channel.recv(1024).decode('utf-8', errors='ignore')
                if '[sudo]' in output or 'password' in output.lower():
                    channel.send(self.password + '\n')
                    time.sleep(1)
            
            output = ""
            error = ""
            
            while True:
                if channel.recv_ready():
                    output += channel.recv(4096).decode('utf-8', errors='ignore')
                if channel.recv_stderr_ready():
                    error += channel.recv_stderr(4096).decode('utf-8', errors='ignore')
                if channel.exit_status_ready():
                    break
                time.sleep(0.1)
            
            exit_status = channel.recv_exit_status()
            channel.close()
            ssh.close()
            
            # Update mitigation flow
            if exit_status == 0:
                logger.info(f"Mitigation applied successfully: {mitigation}")
                mitigation_flow['status'] = 'applied'
                mitigation_flow['action'] = mitigation
                mitigation_flow['rule'] = command
                mitigation_flow['success'] = True
                mitigation_stats['pending'] -= 1
                mitigation_stats['applied'] += 1
                return mitigation
            else:
                logger.error(f"Mitigation command failed: {error}")
                mitigation_flow['status'] = 'failed'
                mitigation_flow['action'] = f"Failed: {error[:50]}"
                mitigation_flow['rule'] = command
                mitigation_stats['pending'] -= 1
                mitigation_stats['failed'] += 1
                return f"Mitigation attempted but failed: {error[:100]}"

        except Exception as e:
            logger.error(f"Mitigation error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            
            # Update flow on exception
            if 'mitigation_flow' in locals():
                mitigation_flow['status'] = 'failed'
                mitigation_flow['action'] = f"Error: {str(e)[:50]}"
                mitigation_stats['pending'] -= 1
                mitigation_stats['failed'] += 1
            
            return f"Mitigation failed: {str(e)}"
    
    # Apply mitigation asynchronously to avoid blocking packet capture
    def _apply_mitigation_async(self, attack_type, target_ip, flow_data):
        try:
            mitigator = AIMitigation(
                host='100.65.52.69',
                username='ran',
                password='mmuzte123'
            )
            mitigation_result = mitigator.apply_mitigation(attack_type, target_ip, flow_data)
            logger.info(f"Mitigation result: {mitigation_result}")
        except Exception as e:
            logger.error(f"Error applying mitigation: {e}")

# Add API endpoint to get mitigation flows
@require_http_methods(["GET"])
def get_mitigation_flows(request):
    global mitigation_flows_buffer, mitigation_stats

    try:
        flows_list = list(mitigation_flows_buffer)
        
        # Most recent 20 flows
        recent_flows = flows_list[-20:] if len(flows_list) > 20 else flows_list
        
        # Reverse to show newest first
        recent_flows.reverse()

        response_data = {
            'status': 'success',
            'flows': recent_flows,
            'stats': mitigation_stats,
            'total_flows': len(flows_list),
            'timestamp': datetime.now().isoformat()
        }

        return JsonResponse(response_data)

    except Exception as e:
        logging.error(f"Error fetching mitigation flows: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return JsonResponse({
            'status': 'error',
            'message': str(e),
            'flows': [],
            'stats': mitigation_stats
        })

# Reset mitigation statistics
@csrf_exempt
@require_http_methods(["POST"])
def reset_mitigation_stats(request):
    global mitigation_stats, mitigation_flows_buffer

    mitigation_stats = {'applied': 0, 'pending': 0, 'failed': 0}
    mitigation_flows_buffer.clear()

    return JsonResponse({
        'status': 'success',
        'message': 'Mitigation statistics reset'
    })
        
def get_automation_status(request):
    if request.method == "GET":
        global automation_manager, detection, attack_level, attack_severity_num, accuracy, mitigation, analysis_report

        status = automation_manager.get_status()
        
        # Check for completed results in cache
        automation_results = cache.get('automation_results', None)
        
        # Include current detection results
        current_results = {
            'detection': detection,
            'attack_level': attack_level,
            'attack_severity_num': attack_severity_num,
            'accuracy': accuracy,
            'mitigation': mitigation,
            'analysis_report': analysis_report
        }
        
        response_data = {
            'status': status,
            'automation': status,
            'current_results': current_results,
            'has_new_results': automation_results is not None
        }
        
        if automation_results:
            response_data['automation_results'] = automation_results
            # Clear the cache after sending results
            cache.delete('automation_results')

        return JsonResponse(response_data)
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

# Start the attack simulation when the start button is clicked
def start_attack(request):
    global target_ip, attack_type, attack_status, network_capture, latest_capture_file
    global model, ml_status, automation_manager, capture_active
    global detection, attack_level, attack_severity_num, analysis_report, mitigation

    detection = None
    attack_level = None
    attack_severity_num = 0
    analysis_report = {}
    mitigation = None

    if request.method == "POST":
        cache.delete('automation_results')
        cache.delete('results_ready')

        attack_type = request.POST.get('attack_type')
        target_ip = request.POST.get('target_ip', '192.168.1.1')

        automation_manager = AutomationManager()
        automation_manager.start_automation(attack_type, target_ip)

        try:
            socket.inet_aton(target_ip)
        except socket.error:
            attack_status = "Invalid target IP address"
            messages.error(request, "Invalid target IP address.")
            return JsonResponse({'status': 'error', 'message': 'Invalid IP address'})

        logger.info(f"Starting attack simulation: {attack_type} on {target_ip}")

        host = RAN5G_CONFIG.get('HOST', '100.65.52.69')
        username = RAN5G_CONFIG.get('USERNAME', 'ran')
        password = RAN5G_CONFIG.get('PASSWORD', 'mmuzte123')
        simulator = AttackSimulator(host, username, password)

        # Check if live monitoring is active
        if capture_active and network_capture.live_monitoring:
            logger.info("Live monitoring is active. Using existing capture session for attack simulation.")

            capture_mode = 'live_monitoring'
            
            # Don't start a new capture, just use the live monitoring
            cache.set('attack_simulation_active', {
                'attack_type': attack_type,
                'target_ip': target_ip,
                'start_time': datetime.now().isoformat(),
                'mode': 'live_monitoring'
            }, timeout=300)
            
            automation_manager.complete_step('packet_capture', {
                'status': 'Using live monitoring',
                'file_path': 'live_monitoring',
                'mode': 'live_monitoring'
            })
            
            # Start attack simulation
            if simulator.trigger_dos_attack(target_ip, attack_type):
                attack_status = f"Attack simulation started. {attack_type} attack injected on {target_ip}"
                automation_manager.complete_step('attack_simulation', {'status': 'success'})
                
                logger.info("Attack injected. Waiting for detection in live monitoring...")
                
                # Schedule ML analysis to run after attack duration
                threading.Thread(
                    target=schedule_ml_automation_from_live,
                    args=(attack_type, target_ip, 60),  # 60 second duration
                    daemon=True
                ).start()

                return JsonResponse({
                    'status': 'success',
                    'message': attack_status,
                    'attack_type': attack_type,
                    'target_ip': target_ip,
                    'mode': 'live_monitoring'
                })
            
            else:
                attack_status = "Failed to inject attack"
                automation_manager.status = "Failed"
                logger.error("Attack simulation failed.")
                return JsonResponse({
                    'status': 'error',
                    'message': attack_status
                })
        
        else:
            # Original behavior: Start dedicated capture for attack
            logger.info("Starting dedicated packet capture for attack simulation...")
            
            capture_mode = 'dedicated_capture'

            capture_success, capture_file = network_capture.start_capture_with_auto_analysis(
                duration=60, 
                attack_type=attack_type, 
                target_ip=target_ip
            )

            if capture_success:
                logger.info("Packet capture thread started.")
                automation_manager.complete_step('packet_capture', {'file_path': capture_file, 'mode': 'dedicated_capture'})
                time.sleep(10)
            
                # Start attack simulation
                if simulator.trigger_dos_attack(target_ip, attack_type):
                    attack_status = f"Attack simulation started. {attack_type} attack injected on {target_ip}"
                    latest_capture_file = capture_file
                    automation_manager.complete_step('attack_simulation', {'status': 'success'})
                    
                    cache.set('latest_capture_info', {
                        'file_path': capture_file,
                        'attack_type': attack_type,
                        'target_ip': target_ip,
                        'timestamp': datetime.now().isoformat(),
                        'automation_id': id(automation_manager.current_task),
                        'mode': 'dedicated_capture'
                    }, timeout=7200)

                    # Schedule ML automation
                    threading.Thread(
                        target=schedule_ml_automation,
                        args=(capture_file, attack_type, target_ip),
                        daemon=True
                    ).start()

                    return JsonResponse({
                        'status': 'success',
                        'message': attack_status,
                        'attack_type': attack_type,
                        'target_ip': target_ip,
                        'capture_file': capture_file,
                        'mode': 'dedicated_capture'
                    })
                
                else:
                    attack_status = "Failed to inject attack"
                    automation_manager.status = "Failed"
                    logger.error("Attack simulation failed.")
                    return JsonResponse({
                        'status': 'error',
                        'message': attack_status
                    })
            else:
                attack_status = "Failed to start packet capture"
                automation_manager.status = "Failed"
                logger.error("Failed to initialize packet capture.")
                return JsonResponse({
                        'status': 'error',
                        'message': attack_status
                    })

    return JsonResponse({
                        'status': 'error',
                        'message': 'nvalid request method'
                    })

# ML automation that works with live monitoring data instead of capture file
def schedule_ml_automation_from_live(attack_type, target_ip, duration):
    global model, ml_status, automation_manager, live_flows_buffer
    global detection, attack_level, attack_severity_num, accuracy, mitigation, analysis_report

    try:
        # Wait for attack to generate traffic
        logger.info(f"Waiting {duration} seconds for attack traffic...")
        time.sleep(duration)
        
        # Check if we're still in attack mode
        attack_info = cache.get('attack_simulation_active')
        if not attack_info:
            logger.warning("Attack simulation info not found in cache")
            return

        # Load ML model if needed
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

        # Analyze flows from live buffer
        logger.info("Analyzing flows from live monitoring buffer...")
        
        # Get flows from the buffer
        flows_to_analyze = list(live_flows_buffer)
        
        if len(flows_to_analyze) == 0:
            logger.warning("No flows available for analysis")
            automation_manager.status = "no_data"
            return
        
        # Filter flows related to attack (suspicious/malicious only)
        attack_flows = [f for f in flows_to_analyze 
                       if f.get('classification') in ['suspicious', 'malicious']]
        
        if len(attack_flows) == 0:
            logger.warning("No suspicious/malicious flows detected during attack")
            # Use any flows for analysis
            attack_flows = flows_to_analyze[-10:]  # Last 10 flows
        
        logger.info(f"Found {len(attack_flows)} attack-related flows for analysis")
        
        # Perform detection on flows
        detection_counts = {}
        severity_scores = []
        
        for flow in attack_flows[:10]:  # Analyze up to 10 flows
            # Extract the attack type detected in real-time
            detected_attack = flow.get('attack_type', 'Unknown')
            detection_counts[detected_attack] = detection_counts.get(detected_attack, 0) + 1
        
        # Use majority vote
        if detection_counts:
            detection = max(detection_counts, key=detection_counts.get)
            confidence = detection_counts[detection] / len(attack_flows[:10])
        else:
            detection = "Unknown"
            confidence = 0.0
        
        # Calculate severity based on flow statistics
        malicious_count = sum(1 for f in attack_flows if f.get('classification') == 'malicious')
        suspicious_count = sum(1 for f in attack_flows if f.get('classification') == 'suspicious')
        
        if malicious_count > 5:
            attack_level = "Critical"
            attack_severity_num = 3
        elif malicious_count > 0 or suspicious_count > 5:
            attack_level = "Major"
            attack_severity_num = 2
        else:
            attack_level = "Minor"
            attack_severity_num = 1
        
        accuracy = "91.01%"
        
        # Mitigation
        if detection == "Benign" or detection == "Normal Traffic":
            mitigation = "No action needed"
        else:
            logger.info(f"Applying mitigation for {detection} on target {target_ip}")
            mitigator = AIMitigation(host='100.65.52.69', username='ran', password='mmuzte123')
            mitigation = mitigator.apply_mitigation(detection, target_ip)
        
        # Prepare analysis report
        analysis_report = {
            'total_flows_analyzed': len(attack_flows),
            'malicious_flows': malicious_count,
            'suspicious_flows': suspicious_count,
            'detection_distribution': detection_counts,
            'confidence': confidence
        }
        
        # Create analysis results
        analysis_results = {
            'detection': detection,
            'attack_level': attack_level,
            'attack_severity_num': attack_severity_num,
            'accuracy': accuracy,
            'mitigation': mitigation,
            'analysis_report': analysis_report,
            'expected_attack': attack_type,
            'target_ip': target_ip,
            'capture_file': 'live_monitoring',
            'total_packets': len(flows_to_analyze),
            'match_expected': detection.replace(' ', '').lower() in attack_type.lower(),
            'confidence': confidence,
            'timestamp': datetime.now().isoformat(),
            'source': 'live_monitoring'
        }
        
        automation_manager.complete_step('data_analysis', analysis_results)
        automation_manager.complete_automation(analysis_results)
        
        # Store results in cache
        cache.set('automation_results', {
            'analysis': analysis_results,
            'capture_file': 'live_monitoring',
            'attack_type': attack_type,
            'target_ip': target_ip,
            'completed_at': datetime.now().isoformat()
        }, timeout=14400)
        
        cache.set('results_ready', True, timeout=14400)
        
        # Clear attack mode flag
        cache.delete('attack_simulation_active')
        
        logger.info(f"Live monitoring analysis completed: {detection} ({attack_level})")
        
    except Exception as e:
        automation_manager.status = "Error"
        logger.error(f"Live monitoring automation error: {e}")
        import traceback
        logger.error(traceback.format_exc())

def schedule_ml_automation(capture_file, attack_type, target_ip):
    global model, ml_status, automation_manager

    try:
        time.sleep(60) # Wait for capture to complete

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

        time.sleep(5) # Ensure file is ready 

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
                }, timeout=7200) # Cache for 2 hours

                # Set a flag that results are ready
                cache.set('results_ready', True, timeout=7200)
            
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
            float(features.get('frame.time_relative', 0.0)),
            float(features.get('ip.len', 0)),
            float(features.get('tcp.flags.syn', 0)),
            float(features.get('tcp.flags.ack', 0)),
            float(features.get('tcp.flags.push', 0)),
            float(features.get('tcp.flags.fin', 0)),
            float(features.get('tcp.flags.reset', 0)),
            float(features.get('ip.proto', 0)),
            float(features.get('ip.ttl', 0)),
            float(features.get('tcp.window_size_value', 0)),
            float(features.get('tcp.hdr_len', 0)),
            float(features.get('udp.length', 0)),
            float(features.get('srcport', 0)),
            float(features.get('dstport', 0))
        ]
        
        logger.info(f"Extracted features: {feature_list}")

        detection_result = perform_detection(feature_list)

        if detection_result['model'] == 'Error':
            logger.error(f"Detection failed: {detection_result['attack_type']}")
            return None
        
        detection = detection_result['attack_type']
        attack_level = detection_result['severity_level']
        attack_severity_num = detection_result['severity_score']
        accuracy = "91.01%"

        # Set attack status and mitigation based on detection results
        if detection == "Benign":
            mitigation = "No action needed"

        else:  
            logger.info(f"Applying mitigation for {detection} on target {target_ip}")
            mitigator = AIMitigation(host='100.65.52.69', username='ran', password='mmuzte123')
            mitigation = mitigator.apply_mitigation(detection, target_ip='192.168.1.1')

        auto_analysis_results = {
            'detection': detection,
            'attack_level': attack_level,
            'attack_severity_num': attack_severity_num,
            'accuracy': accuracy,
            'mitigation': mitigation,
            'analysis_report': detection_result.get('traffic_metrics', {}),
            'expected_attack': attack_type,
            'target_ip': target_ip,
            'capture_file': capture_file,
            'total_packets': len(packets),
            'match_expected': detection == attack_type,
            'confidence': detection_result.get('confidence', 0.0),
            'timestamp': datetime.now().isoformat()
        }

        cache.set('automation_results', {
            'analysis': auto_analysis_results,
            'capture_file': capture_file,
            'attack_type': attack_type,
            'target_ip': target_ip,
            'completed_at': datetime.now().isoformat()
        }, timeout=14400)  # 4 hours

        cache.set('results_ready', True, timeout=14400)

        analysis_report = detection_result.get('traffic_metrics', {})

        logger.info(f"Analysis Results: {auto_analysis_results}")
        return auto_analysis_results
    
    except Exception as e:
        logger.error(f"Error analyzing captured data: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None
    
def get_automation_status(request):
    if request.method == "GET":
        global automation_manager, detection, attack_level, attack_severity_num, accuracy, mitigation, analysis_report
        status = automation_manager.get_status()

        # Check for completed results in cache
        automation_results = cache.get('automation_results', None)
        results_ready = cache.get('results_ready', False)

        current_results = {
            'detection': detection,
            'attack_level': attack_level,
            'attack_severity_num': attack_severity_num,
            'accuracy': accuracy,
            'mitigation': mitigation,
            'analysis_report': analysis_report
        }
        
        response_data = {
            'status': status,
            'automation': status,
            'current_results': current_results,
            'has_new_results': automation_results is not None and results_ready,
            'results_ready': results_ready
        }

        if automation_results:
            response_data['automation_results'] = automation_results

        return JsonResponse(response_data)
    
    return JsonResponse({'status':'error', 'message': 'Invalid request method'})

# New endpoint to acknowledge results received
@csrf_exempt
@require_http_methods(["POST"])
def acknowledge_results(request):
    try:
        cache.delete('automation_results')
        cache.delete('results_ready')
        return JsonResponse({'status': 'success', 'message': 'Results acknowledged'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

# New endpoint to clear automation results
@csrf_exempt
def clear_automation_results(request):
    if request.method == 'POST':
        cache.delete('automation_results')
        cache.delete('results_ready')
        return JsonResponse({'status': 'success', 'message': 'Results cleared'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

def start_ml(request):
    global model, detection, accuracy, ml_status

    model_path = os.path.join(settings.BASE_DIR, 'app','model', 'vanilla_lstm_model.pkl')

    alternative_path = [os.path.join(os.path.dirname(__file__), 'model', 'vanilla_lstm_model.pkl'),
                        '/app/app/model/vanilla_lstm_model.pkl',
                        './app/model/vanilla_lstm_model.pkl',
    ]

    model_file_found = False
    actual_model_path = None

    if os.path.exists(model_path):
        if request.method == "POST":
            model = joblib.load(model_path)
        model_file_found = True
        actual_model_path = model_path

    else:
        for alt_path in alternative_path:
            if os.path.exists(alt_path):
                model_file_found = True
                actual_model_path = alt_path
                break

    if model_file_found and request.method == "POST":
        try:
            model = joblib.load(actual_model_path)
            ml_status = "ML model is available and ready to be used."
            accuracy = "91.01%"
            messages.info(request, "Machine Learning model started and ready.")
        
        except Exception as e:
            ml_status = "ML model failed to start."
            messages.error(request, f"Error starting ML model: {e}")

    elif not model_file_found:
        ml_status = "ML model file not found."
        messages.error(request, "ML model file not found.")

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

    if request.method == 'POST':
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
                    if filename.endswith('.csv'):
                        # Handle JSON format
                        file_content = uploaded_file.read().decode('utf-8')
                        reader = csv.reader(io.StringIO(file_content))

                        first_row = next(reader, None)
                        if first_row:
                            try:
                                data = []
                                for i in range(min(len(first_row), 14)):
                                    try:
                                        value = first_row[i]
                                        data.append(float(value))
                                    except (ValueError, TypeError, IndexError):
                                        logger.warning(f"Invalid value at index method")
                                        data.append(0.0)

                                while len(data) < 14:
                                    data.append(0.0)

                            except Exception as e:
                                logger.error(f"Error parsing first row: {e}")
                                second_row = next(reader, None)

                                if second_row:
                                    data = []
                                    for i in range(min(len(second_row), 14)):
                                        try:
                                            value = second_row[i]
                                            data.append(float(value))
                                        except (ValueError, TypeError, IndexError) as e:
                                            logger.warning(f"Invalid value at index {i}: {e}")
                                            data.append(0.0)

                                    while len(data) < 14:
                                        data.append(0.0)

                                    data = data[:14]
                                
                                else:
                                    raise ValueError("No data rows found in CSV")

                    elif filename.endswith(('.pcap', '.pcapng')):
                        # Handle PCAP format
                        file_content = uploaded_file.read()
                        temp_filename = f"temp_{filename}"
                        temp_path = os.path.join(settings.BASE_DIR, 'temp', temp_filename)

                        os.makedirs(os.path.dirname(temp_path), exist_ok=True)

                        with open(temp_filename, "wb") as f:
                            f.write(file_content)

                        try:

                            packets = rdpcap(temp_path)

                            if not isinstance(packets, (list, scapy.PacketList)):
                                raise ValueError("PCAP file did not return a list of packets.")

                            if len(packets) == 0:
                                detection = "Error: No packets of data found."
                                attack_level = "N/A"
                                accuracy = "N/A"
                                mitigation = "N/A"
                                return render(request, 'index.html', {'form': form, 'detection': detection, 'attack_level': attack_level, 'accuracy': accuracy, 'mitigation': mitigation, 'connection_status': connection_status, 'attack_status': attack_status, 'ml_status': ml_status, 'attack_type': attack_type})
                            
                            packet = packets[0]
                            
                            capture_instance = NetworkTrafficCapture()
                            features = capture_instance.extract_features(packet)

                            if features:
                                data = []
                                feature_keys = [
                                    'frame.time_relative',
                                    'ip.len',
                                    'tcp.flags.syn',
                                    'tcp.flags.ack',
                                    'tcp.flags.push',
                                    'tcp.flags.fin',
                                    'tcp.flags.reset',
                                    'ip.proto',
                                    'ip.ttl',
                                    'tcp.window_size_value',
                                    'tcp.hdr_len',
                                    'udp.length',
                                    'srcport',
                                    'dstport'
                                ]

                                for key in feature_keys:
                                    value = features.get(key, 0.0)
                                    try:
                                        data.append(float(value))
                                    except (ValueError, TypeError):
                                        logger.warning(f"Invalid feature {key}")
                                        data.append(0.0)

                                data = data[:14]
                                while len(data) < 14:
                                    data.append(0.0)
                            else:
                                raise ValueError("Could not extract feature")

                            if os.path.exists(temp_path):
                                os.remove(temp_path)
           
                        except Exception as e:
                            logger.error(f"Error processing PCAP file: {e}")
                            detection = f"Error: Processing file failed - {str(e)}"
                            attack_level = "N/A"
                            accuracy = "N/A"
                            mitigation = "N/A"
                            if os.path.exists(temp_path):
                                os.remove(temp_path)
                            return render(request, 'index.html', {'form': form, 'detection': detection, 'attack_level': attack_level, 'accuracy': accuracy, 'mitigation': mitigation, 'connection_status': connection_status, 'attack_status': attack_status, 'ml_status': ml_status, 'attack_type': attack_type})

                    else:
                        detection = "Error: Unsupported file format!"
                        attack_level = "N/A"
                        accuracy = "N/A"
                        mitigation = "N/A"
                        return render(request, 'index.html', {'form': form, 'detection': detection, 'attack_level': attack_level, 'accuracy': accuracy, 'mitigation': mitigation, 'connection_status': connection_status, 'attack_status': attack_status, 'ml_status': ml_status, 'attack_type': attack_type})

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
                
                for i, val in enumerate(data):
                    if not isinstance(val, (int, float)):
                        logger.error(f"Non-numeric value at index {i}: {val}")
                        data[i] = 0.0

                    elif np.isnan(val) or np.isinf(val):
                        logger.warning(f"Invalid numeric value at index {i}")
                        data[i] = 0.0

                # Reshape the data into 3D array to fit in LSTM input format
                data_array = np.array(data, dtype=np.float32).reshape(1, 1, 14)
                logger.debug(f"Data array shape: {data_array.shape}")
                logger.debug(f"Data array dtype: {data_array.dtype}")

                # Make prediction
                prediction = model.predict(data_array)
                logger.debug(f"Model prediction: {prediction}")

                if len(prediction.shape) > 1:
                    predicted_class = np.argmax(prediction, axis=1)

                    if isinstance(predicted_class, np.ndarray):
                        predicted_class = int(predicted_class[0])
                    else:
                        predicted_class = int(predicted_class)
                else:
                    if isinstance(prediction, np.ndarray):
                        predicted_class = int(prediction[0])
                    else:
                        predicted_class = int(prediction)

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
                        feature_dict[feature_names[i]] = float(value)
                    else:
                        feature_dict[f'feature_{i+1}'] = float(value)

                # Determine attack severity level
                attack_level, attack_severity_num, analysis_report = severity_analyzer.decide_attack_level(detection, feature_dict, anomaly_score=0.5)
                logger.info(f"Attack detected: {detection}, Severity Level: {attack_level}, Severity Num: {attack_severity_num}")

                # Set attack status and mitigation based on detection results
                if detection == "Benign":
                    attack_status = "Safe"
                    mitigation = "No action needed"

                else:  
                    attack_status = "Under Attack!"
                    mitigator = AIMitigation(host='100.65.52.69', username='ran', password='mmuzte123')
                    mitigation = mitigator.apply_mitigation(detection, target_ip='192.168.1.1')

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