# Demo workflow

![your-UML-diagram-name](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/Siong23/zero-touch-5g-sec-ai/refs/heads/main/demo/workflow)

# Key Steps in the Workflow
1. User initiates the demo.
2. Traffic Generator produces traffic (simulated + public datasets).
3. Prometheus collects metrics, Grafana displays them.
4. Traffic is sent to an AI Pod inside a Kubernetes environment.
5. The AI model performs deep learning–based anomaly detection.
6. The result is passed to the ZTO (Zero-Touch Operations) controller.
7. If an anomaly is detected, an alert or auto-mitigation is triggered.
8. Otherwise, it continues normal operation.
9. The User observes system behavior in Grafana.
