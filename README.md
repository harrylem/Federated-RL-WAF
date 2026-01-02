# Federated Reinforcement Learning WAF - DEMO v1.2

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-blue)
![Flower](https://img.shields.io/badge/Federated%20Learning-Flower-green)
![RL](https://img.shields.io/badge/Reinforcement%20Learning-PPO-orange)
![Security](https://img.shields.io/badge/Security-ModSecurity-red)
![Honeynet](https://img.shields.io/badge/Honeynet-API%20%26%20Admin-purple)

## Overview
This project implements a **Self-Improving Web Application Firewall (WAF)** system using **Federated Reinforcement Learning**.

Unlike traditional WAFs that rely on static signatures, this system employs two autonomous RL Agents that collaborate to:
1.  **Minimize False Positives:** By learning from normal traffic on a Production WAF protecting a DVWA instance.
2.  **Detect Zero-Day Attacks:** By learning from a specialized Web Honeypot.
3.  **Share Knowledge:** Using Federated Learning (Flower) to aggregate insights without sharing raw sensitive logs.
4.  **Close the Loop:** Automatically generating and applying ModSecurity rules (`SecRule`) in real-time upon detecting threats.
1.  **Solve the "Cold Start" Problem:** Using **Hybrid Learning** (Offline Pre-training on CSIC 2010 Dataset + Online Federated Training).

## Architecture
The system is fully containerized using **Docker Compose**:

* **Real WAF (Client 1):** Nginx + ModSecurity protecting a vulnerable app (DVWA).
* **Honeynet System (Client 2):** * **Honeypot:** High-Interaction Nginx + ModSecurity trap.
    * **Honeynet API & Admin:** A centralized interface to manage logs, visualize attack vectors, and monitor the honeypot status.
* **CSIC 2010 Dataset - Optional (Client 3):** Script for pre-training the model with a CSV file containing 61k+ samples of documented traffic 
* **Flower Server:** Aggregates the RL model weights (FedAvg).
* **RL Agent (`federated_rl_agent.py`):** * Updated to parse structured **JSON logs** for precise feature extraction.
    * Interacts with the Honeynet API for real-time data retrieval.
    * Uses `Gymnasium` and `Stable-Baselines3` (PPO) to decide blocking actions.

## Key Features (v1.3 Update)

### Hybrid Learning(v1.3)
To prevent the agent from starting "blind" (Cold Start), the Server offers a **Pre-training Menu**. It trains the model on 61,000+ samples from the CSIC 2010 dataset.

### Enhanced Agent Vision(v1.3)
The Agent's vocabulary has been expanded to **50 features**, allowing it to distinguish between:
* Attack Payloads (`UNION`, `SELECT`, `<script>`)
* WAF Alerts (`SQL Injection detected`, `Inbound Anomaly`)
* Normal Traffic (`/login`, `id`, `200 OK`)

### Real-Time IP Blocking(v1.3)
Upon detecting a threat with high confidence, the Agent injects a dynamic **IP Ban Rule** (`deny`) into the Nginx configuration, instantly cutting off the attacker's access to the entire infrastructure.

### Advanced Honeynet Ecosystem (v1.2)
The logic has been expanded beyond simple log parsing. The system now includes:
* **Honeynet API:** A dedicated API endpoint that captures and serves attack data, allowing the agents to pull structured threat intelligence.
* **Admin Dashboard:** A visual interface for monitoring the Honeynet's status and viewing raw log data.

### Structured Logging & Agent Logic (v1.2)
* **JSON Log Parsing:** The log processing pipeline has been upgraded to handle **JSON files**. This ensures robust parsing of request headers, bodies, and attack signatures.
* **Updated Agent Logic (`federated_rl_agent.py`):** The agent code has been refactored to consume the new JSON format, enabling more accurate state representation for the Reinforcement Learning model.

## Proof of Concept

### 1. Real-Time Defense (Closed Loop)
The Agent detects a Zero-Day attack on the Honeypot and patches the Real WAF instantly.
![Attack Blocked](screenshots/Client2_Live_Training.jpg)
### 2. Training Performance
The Reinforcement Learning agent maximizing reward over time (Learning to distinguish attacks vs normal traffic).
![TensorBoard](screenshots/Tensor_Board_Live_Training_Data.jpg)

## 🛠 How to Run

### Prerequisites
* Docker & Docker Compose
* Python 3.10+
* Package Manager: `uv` (Recommended) or `pip`

### 1. Start the Infrastructure
```
docker-compose up -d```
```
2. Install Dependencies
# Using uv (faster)
uv pip install -r requirements.txt
# OR using pip
pip install -r requirements.txt

3. Run the Federated System
Open 3 terminals:

Terminal 1 (Server):
```bash
python3 src/flower_server.py
```
Terminal 2 (WAF Agent):
```bash
python3 src/federated_rl_agent.py 1
```
Terminal 3 (Honeypot Agent):
```bash
python3 src/federated_rl_agent.py 2
```
Terminal 4 (Dataset Knowledge Injection - Optional) # To pre-train model using 61.000+ records from the CSIC 2010 Dataset!!
```bash
python3 src/dataset_client.py
```

### 4. Scalability Simulation (Virtual Client Engine) and Comparative Analysis
To demonstrate scalability, this project includes a simulation mode that spins up **10 Virtual Clients** with Non-IID data distributions (SQLi Specialists vs XSS Specialists).

Run the simulation:
bash
```
python3 src/simulation.py
```

To compare the RL Agent against a traditional Logistic Regression classifier.
Run the script below:
bash
```
python3 src/baseline.py
```
👨‍💻 Author
LEMONTZOGLOU CHARALAMBOS

This project was developed as part of my Thesis.