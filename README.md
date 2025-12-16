# Federated Reinforcement Learning WAF - DEMO v1.1

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-blue)
![Flower](https://img.shields.io/badge/Federated%20Learning-Flower-green)
![RL](https://img.shields.io/badge/Reinforcement%20Learning-PPO-orange)
![Security](https://img.shields.io/badge/Security-ModSecurity-red)

##Overview
This project implements a **Self-Improving Web Application Firewall (WAF)** system using **Federated Reinforcement Learning**.

Unlike traditional WAFs that rely on static signatures, this system employs autonomous RL Agents that collaborate to:
1.  **Minimize False Positives:** By learning from normal traffic on a Production WAF.
2.  **Detect Zero-Day Attacks:** By learning from a specialized Web Honeypot.
3.  **Share Knowledge:** Using Federated Learning (Flower) to aggregate insights without sharing raw sensitive logs.
4.  **Close the Loop:** Automatically generating and applying ModSecurity rules (`SecRule`) in real-time.

##Architecture
The system is fully containerized using **Docker Compose**:

* **Real WAF (Client 1):** Nginx + ModSecurity protecting a vulnerable app (DVWA).
* **Honeypot (Client 2):** Nginx + ModSecurity configured as a trap (High-Interaction).
* **Flower Server:** Aggregates the RL model weights (FedAvg).
* **RL Agent:** Uses `Gymnasium` and `Stable-Baselines3` (PPO) to parse logs and decide actions.

---

## 🧪 Experiments & Simulations
Beyond the live demo, this repository includes scientific simulations to prove scalability and performance.

### 1. Scalability Simulation (Virtual Client Engine)
To demonstrate the system's ability to scale, we implemented a simulation with **10 Virtual Clients** using Non-IID (Non-Identically Distributed) data.
* **Scenario:** 5 Clients specialize in SQL Injection defense, while 5 Clients specialize in XSS defense.
* **Goal:** Prove that the Global Model learns *both* attack vectors effectively.
* **Run:** `python3 src/simulation.py`

### 2. Baseline Comparison
To validate the Reinforcement Learning approach, we compare it against a standard supervised learning baseline (**Logistic Regression**).
* **Metrics:** Accuracy, Log Loss.
* **Comparison:** While the Baseline offers fast convergence for classification, the RL Agent provides actionable decisions (Block IP/URI) and adapts to reward penalties (e.g., avoiding false positives).
* **Run:** `python3 src/baseline.py`

---

## 📸 Proof of Concept (Live Demo)

### 1. Real-Time Defense (Closed Loop)
The Agent detects a Zero-Day attack on the Honeypot and patches the Real WAF instantly.
![Attack Blocked](screenshots/attack_success.png)

### 2. Training Performance
The Reinforcement Learning agent maximizing reward over time (Learning to distinguish attacks vs normal traffic).
![TensorBoard](screenshots/tensorboard_graph.png)

## 🛠 How to Run

### Prerequisites
* Docker & Docker Compose
* Python 3.10+

### Installation
```bash
pip install -r requirements.txt
docker-compose up -d

2. Install Dependencies
pip install -r requirements.txt

3. Run the Federated System
Open 3 terminals:

Terminal 1 (Server):
```
python3 src/flower_server.py
```
Terminal 2 (WAF Agent):
```
python3 src/federated_rl_agent.py 1
```
Terminal 3 (Honeypot Agent):
```
python3 src/federated_rl_agent.py 2
To demonstrate scalability, this project includes a simulation mode that spins up **10 Virtual Clients** with Non-IID data distributions (SQLi Specialists vs XSS Specialists).

Run the simulation:
# Scalability Test (10 Clients)
python3 src/simulation.py
# Baseline Benchmark
python3 src/baseline.py


👨‍💻 Author
LEMONTZOGLOU CHARALAMBOS

This project was developed as part of my Thesis.
