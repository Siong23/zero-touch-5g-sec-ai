# zero-touch-5g-sec-ai

> **Intelligent, Zero-Touch Security and Management for 5G Networks using Deep Learning and Explainable AI**

This project explores the use of cutting-edge machine learning techniques, including BiLSTM with Attention and TimeSHAP, to automate anomaly detection in 5G network traffic—focusing on fronthaul security. It integrates AI models into a zero-touch network management workflow using Kubernetes and TM Forum-compliant orchestration tools.

---

## ✨ Key Features

- 🔍 Deep learning–based anomaly detection on 5G fronthaul traffic
- 📊 Integration of TimeSHAP for model explainability
- 🔁 Dataset support: Simulated testbed traffic + public 5G-NIDD dataset
- ⚙️ Containerized and orchestratable via Kubernetes/OpenSlice
- 📈 Monitoring and observability with Prometheus & Grafana
- 🤖 Designed for Zero-Touch Operations (ZTO) in future mobile networks

---

## 🧠 Architecture

![Architecture Diagram](docs/architecture.png)

> **High-level architecture**: OSS/BSS → OpenSlice → Kubernetes → AI Inference (CNF) → Monitoring

---

## 📦 Installation

### Clone & Set Up Environment

```bash
git clone https://github.com/yourusername/ZeroTouch5G-AI.git
cd ZeroTouch5G-AI
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
