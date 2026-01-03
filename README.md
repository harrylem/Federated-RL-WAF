# Federated Reinforcement Learning WAF - DEMO v1.4

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
4.  **Active Defense:** Automatically banning Attacker IPs in real-time (`SecRule ... deny`) across the entire network.
5.  **Solve the "Cold Start" Problem:** Using **Hybrid Learning** (Offline Pre-training on CSIC 2010 Dataset + Online Federated Training).

## Architecture
The system is fully containerized using **Docker Compose**:

### The Network
* **Production WAF (Client 1):** Nginx + ModSecurity protecting a vulnerable app (DVWA).
* **Honeynet System (Client 2):** * **Honeypot:** High-Interaction Nginx + ModSecurity trap.
* **Honeynet API & Admin:** A centralized interface to manage logs, visualize attack vectors, and monitor the honeypot status.

### The Intelligence
* **Federated Server (`flower_server.py`):**
    * **The Brain:** Aggregates RL model weights (FedAvg).
    * **Orchestrator:** Manages the training lifecycle and provides an interactive menu for Pre-training vs Live Mode.
    * **Auto-Attacker:** Integrated stress-testing tool to simulate attacks during training.
* **RL Agent (`federated_rl_agent.py`):**
    * **Direct Docker Vision:** Uses `docker.from_env()` to stream logs directly from the container API, bypassing file permission issues and ensuring zero latency.
    * **Synthetic Injection:** Bridging the gap between offline datasets and live logs by injecting synthetic threat signatures during training.
    * **Action Space:** Binary Decision (Allow / Block IP).

## Key Features (v1.4 Update)

### Hybrid Learning(v1.3) & Synthetic Injection (v1.4)
To prevent the agent from starting "blind" (Cold Start), the Server offers a **Pre-training Menu**. It trains the model on 61,000+ samples from the CSIC 2010 dataset.
* *Innovation:* The system uses **Synthetic Injection** to append ModSecurity keywords to the offline dataset, ensuring the agent recognizes attack patterns immediately in Live Mode.

### 🔌 Direct Docker API Integration (v1.4)
Instead of relying on fragile file-based logging (`error.log`), the Agents now connect directly to the **Docker Daemon**.
* **Benefit:** 100% reliable log reading, zero latency, and immune to Windows/Linux permission conflicts.

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
Training Performance (Oscillating Rewards)
The graph demonstrates the Agent's ability to maintain high rewards over 50 rounds, balancing between blocking thousands of attacks (Honeypot) and allowing normal traffic (WAF).
The Reinforcement Learning agent maximizing reward over time (Learning to distinguish attacks vs normal traffic).
![Trainig Progress](screenshots/Training_Progress.jpg)

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
You will be presented with the following interactive menu:
============================================================
   🛡️  FEDERATED WAF - CONTROL CENTER v1.4  🛡️
============================================================
1. Start Server (Standard Mode)
   -> Use this if you have Pre-trained or want manual testing.
2. Start Server + AUTO-ATTACK Simulation
   -> Automates 'Learning from Scratch'. Attacks Honeypot automatically.
3. Pre-train with Dataset (Warm Start)
   -> Recommended for best performance.
4. Exit

For First Run: Select Option 3 (Pre-train).
For Live Demo: Select Option 2 (Auto-Attack) to see the agents in action.
Terminal 2 (WAF Agent):
```bash
python3 src/federated_rl_agent.py 1
```
Terminal 3 (Honeypot Agent):
```bash
python3 src/federated_rl_agent.py 2
```
Terminal 4 (Dataset Knowledge Injection - Optional but it is now also implemented in server's choice 1!!) # To pre-train model using 61.000+ records from the CSIC 2010 Dataset!!
```bash
python3 src/dataset_client.py
```
### Note!!: You can also run attacker.py as Live Mode is happening to demonstrate log reading and live training of each agent.
```bash
python3 src/attacker.py
```
You will be presented with the following interactive menu:
1. Attack the WAF agent (client 1)
   -> Use this if you want to see how client 1 reacts to attacks.
2. Attack the WAF Honeypot agent (client 2)
   -> Use this if you want to see how client 2 reacts to attacks.

After that you will be prompted to enter number of attacks to be made ( reccomended for better training is >2500 atacks!!)

### 4. Scalability Simulation (Virtual Client Engine) and Comparative Analysis
To demonstrate scalability, this project includes a simulation mode that spins up **10 Virtual Clients** with Non-IID data distributions (SQLi Specialists vs XSS Specialists).

Run the simulation:
```bash
python3 src/simulation.py
```

To compare the RL Agent against a traditional Logistic Regression classifier.
Run the script below:
```bash
python3 src/baseline.py
```
👨‍💻 Author
LEMONTZOGLOU CHARALAMBOS

This project was developed as part of my Thesis.