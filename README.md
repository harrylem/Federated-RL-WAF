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

### Direct Docker API Integration (v1.4)
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

## 🔬 Comparative Experiments & Results
As part of my Thesis validation, extensive experiments were conducted to evaluate different architectures and learning strategies.

### Experiment A: Architecture (PPO vs LSTM)
We compared the standard **Proximal Policy Optimization (PPO)** against a **Recurrent PPO (LSTM)** architecture to test if "memory" improves detection.
* **Findings:** The **Standard PPO** consistently outperformed LSTM for this Real-Time WAF scenario. The LSTM model struggled to converge (Negative Rewards) due to the atomic nature of web attacks, where "context" is less critical than immediate pattern recognition and needed a lot more training to match PPO's perfomance on this data.

<table width="100%">
  <tr>
    <th width="50%">✅ Standard PPO (Success)</th>
    <th width="50%">❌ Recurrent PPO/LSTM (Failure)</th>
  </tr>
  <tr>
    <td><img src="Federated-RL-WAF/screenshots/training_progress_PPO.png" alt="PPO Training Graph" width="100%"></td>
    <td><img src="Federated-RL-WAF/screenshots/training_progress_PPO_Recurrent.png" alt="LSTM Training Graph" width="100%"></td>
  </tr>
  <tr>
    <td align="center"><i>Fast convergence and high positive rewards (~27k).</i></td>
    <td align="center"><i>Failure to converge, stuck at negative rewards.</i></td>
  </tr>
</table>
<br>

* **Decision:** The final system uses **Standard PPO (MlpPolicy)** for maximum stability and speed.

### Experiment B: Solving "Cold Start" (Scratch vs Hybrid)
We compared training from scratch versus using our **Hybrid Learning** approach.
* **Without Pre-training:** The agents required **~32 Rounds** to start effectively blocking attacks (Blind Phase).
* **With Pre-training:** The agents reached optimal performance by **Round 19**.

<table width="100%">
  <tr>
    <th width="50%"> Learning without pretraining</th>
    <th width="50%"> Learning with pretraining</th>
  </tr>
  <tr>
    <td><img src="Federated-RL-WAF/screenshots/training_progress_without_pretraining_PPO.png" alt="PPO Training Graph" width="100%"></td>
    <td><img src="Federated-RL-WAF/screenshots/training_progress_with_pretraining_PPO.png" alt="LSTM Training Graph" width="100%"></td>
  </tr>
  <tr>
    <td align="center"><i>Fast convergence and high positive rewards (~27k).</i></td>
    <td align="center"><i>Failure to converge, stuck at negative rewards.</i></td>
  </tr>
</table>
<br>

* **Result:** Hybrid Learning reduced the vulnerability window by **~40%**, offering a production-ready defense much faster.

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
### Using uv (faster)
uv pip install -r requirements.txt
### OR using pip
pip install -r requirements.txt

3. Run the Federated System
Open 3 terminals:

Terminal 1 (Server):
```bash
python3 src/flower_server.py
```
### You will be presented with the following interactive menu:
============================================================
  # 🛡️  FEDERATED WAF - CONTROL CENTER v1.4  🛡️
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