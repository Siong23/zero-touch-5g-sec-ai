# Demo workflow

![your-UML-diagram-name](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/Siong23/zero-touch-5g-sec-ai/refs/heads/main/demo/workflow)

# Key Steps in the Workflow
1. Start Scenario
    - User initiates the ICMP flood attack test via the orchestrator.
    - UERANSIM simulates UE behavior to generate high-rate ICMP packets.
2. Traffic Capture
    - Traffic flows between UERANSIM and Open5GS are mirrored and captured using Wireshark or tcpdump.
    - Captured packets are stored as PCAP files.
3. Feature Extraction
    - A feature extractor module processes the PCAP file and converts it into structured flow features (e.g., flow rate, packet size, protocol type).
4. AI-Based Detection
    - The AI Inference Pod loads a trained deep learning model from the model registry (e.g., MLflow).
    - Extracted features are input to the model for anomaly detection.
    - The ICMP flood attack is detected as an anomaly.
5. Mitigation Response
    - The ZTO Orchestrator receives the alert and triggers an automated mitigation.
    - A mitigation module applies a response (e.g., network policy to block ICMP traffic from the source UE) via SDN controller or Kubernetes.
6. Monitoring & Feedback
    - Prometheus continuously collects metrics (e.g., traffic rate, CPU usage, anomaly events).
    - Grafana displays real-time dashboards showing traffic behavior and mitigation status.
    - The user observes attack detection and system response in the visualization dashboard.
