# zero-touch-5g-sec-ai

> **Intelligent, Zero-Touch Security and Management for 5G Networks using Deep Learning**

This project explores the use of cutting-edge machine learning techniques, including ..., to automate anomaly detection in 5G network traffic. It integrates AI models into a zero-touch network management workflow using Kubernetes.

---

## Key Features

- Deep learning–based anomaly detection on 5G traffic
- Dataset support: Simulated testbed traffic + public 5G-NIDD dataset
- Containerized and orchestratable via Kubernetes
- Monitoring and observability with Prometheus & Grafana
- Designed for Zero-Touch Operations (ZTO) in future mobile networks

---

## Architecture
```
+-----------------------------------------------------------------------------------+
|                             OSS/BSS / Service Portal                              |
|      - User Interface for Admin/Operator                                          |
|      - Service Orders, KPI Dashboards, Incident View                              |
+-------------------------------------↑---------------------------------------------+
                                      |
                   TM Forum APIs / Northbound APIs (Intent, Orders, Metrics)
                                      |
+-------------------------------------↓---------------------------------------------+
|                         Orchestration & Policy Management                         |
|  - NFV/CNF Orchestrator (e.g., OSM, k8s)                                          |
|  - SDN Controller (e.g., ONOS/OpenDaylight)                                       |<-----+
|  - Slice Manager (e.g., OpenSlice)                                                |      |
|  - Policy Engine (Intent-to-Action translation)                                   |      |
+-------------------------------------↓---------------------------------------------+      |
                                      |                                                    |
                     Closed-Loop Control Interface (REST/gRPC/NETCONF)                     |
                                      |                                                    |
+-------------------------------------↓---------------------------------------------+      |
|                      AI/ML-Driven Analytics & Decision Engine                     |      |
|  - Data Collector (telemetry, logs, alerts, pcap)                                 |      |
|  - Feature Extractor (e.g., for flow/session/UE behavior)                         |      |
|  - ML Inference Engine (e.g., LSTM, GNN, Autoencoder, XAI)                        |      |
|  - Anomaly & Threat Detector                                                      |      |
|  - Recommender / Actuator module (output intents/actions)                         |      |
|  - TimeSHAP/XAI for explainability & root-cause analysis                          |      |
+-------------------------------------↓---------------------------------------------+      |
                                      |                                                    |
                         Feedback Loop: Mitigation Actions / Scaling                       |
                                      |                                                    |
+-------------------------------------↓---------------------------------------------+      |
|                  Infrastructure Layer (5G Core, RAN, Edge, Transport)             |      |
|  - Open5GS / AMF / UPF                                                            |      |
|  - gNB (srsRAN, OAI, commercial RAN)                                              |      |
|  - UERANSIM / UEs (real or emulated)                                              |      |
|  - Edge Cloud (Kubernetes, CNFs, VNFs)                                            |      |
+-------------------------------------↓---------------------------------------------+      |
                                      |                                                    |
                   Continuous Telemetry / Observability / Event Feeds                      |
                                      ↓                                                    |
+-----------------------------------------------------------------------------------+      |
|                 Monitoring & Logging Systems (e.g., Prometheus, ELK, Grafana)     |      |
|        - Real-time metrics, logs, traces                                          |______|
|        - Alerts trigger ML pipeline updates or orchestrator calls                 |
+-----------------------------------------------------------------------------------+
```






