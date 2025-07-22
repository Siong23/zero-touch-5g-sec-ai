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

![Architecture Diagram](docs/architecture.png)

> **High-level architecture**: Kubernetes → AI Inference (CNF) → Monitoring

---

## Installation
### Clone & Set Up Environment

```bash
git clone https://github.com/yourusername/ZeroTouch5G-AI.git
cd ZeroTouch5G-AI
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Project Structure
```
zero-touch-5g-sec-ai/
├── data/              # Preprocessed datasets and loaders
├── models/            # ML/DL models 
├── orchestrator/      # K8s plugins and CRDs
├── helm/              # Kubernetes Helm charts
├── monitor/           # Prometheus/Grafana config
├── docs/              # Architecture and design docs
├── train.py
├── detect.py
└── README.md
```
---

## Usage

---

## Results


