import docker
import threading
import json
import time
import gymnasium as gym
from gymnasium import spaces
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from stable_baselines3 import PPO
import sys
import torch
import flwr as fl

# --- STEP 1: GLOBAL SETUP ---
WAF_CONTAINER_NAME = "waf_instance1"
HONEYPOT_CONTAINER_NAME = "waf_honeypot"

# Connecting to Docker to access ruleset
client = docker.from_env()
try:
    waf_container = client.containers.get(WAF_CONTAINER_NAME)
except docker.errors.NotFound:
    print(f"FATAL ERROR: No container found!! '{WAF_CONTAINER_NAME}'!")
    sys.exit(1)

# The vectorizer 
vectorizer = TfidfVectorizer(max_features=9) 
vectorizer.fit(["/wp-admin.php", "/vulnerabilities/sqli", "/healthz", "SELECT", "FROM", "script"])

# Mock small scale databases for trial purposes
FAKE_LOG_DB_WAF = [
    {'uri': '/', 'ip': '1.1.1.1', 'source': 'WAF', 'messages': []},
    {'uri': '/healthz', 'ip': '1.1.1.2', 'source': 'WAF', 'messages': []},
    {'uri': '/vulnerabilities/sqli?id=1', 'ip': '2.2.2.2', 'source': 'WAF', 'messages': ['SQL Injection Attack']},
]
FAKE_LOG_DB_HONEYPOT = [
    {'uri': '/wp-admin.php', 'ip': '3.3.3.3', 'source': 'HONEYPOT', 'messages': []},
    {'uri': '/shell.php', 'ip': '4.4.4.4', 'source': 'HONEYPOT', 'messages': []},
    {'uri': '/.env', 'ip': '5.5.5.5', 'source': 'HONEYPOT', 'messages': []}
]

# --- STEP 2: THE MAIN ENVIROMNMENT (Gym Env) ---
class WafEnv(gym.Env):
    def __init__(self, db_source): 
        super(WafEnv, self).__init__()
        self.action_space = spaces.Discrete(3)
        self.observation_space = spaces.Box(low=0, high=1, shape=(9,), dtype=np.float32)
        self.FAKE_LOG_DB = db_source
        self.max_steps = 1000
        self.current_step = 0

    def _get_observation(self, log_data):

        if 'transaction' in log_data:
        # Real log from Live Mode
            uri = log_data['transaction']['request']['uri']
        else:
        # Fake log from FAKE_LOG_DB (Training)
            uri = log_data.get('uri', '/') 

        vector = vectorizer.transform([uri]).toarray().flatten()
        return vector

    def _get_reward(self, log_data, action):
        uri = log_data.get('uri', '/') 
        source = log_data.get('source', 'WAF') 

        if uri == "/healthz" and (action == 1 or action == 2): return -100
        if source == 'HONEYPOT':
            if action == 1 or action == 2: return 100
            if action == 0: return -50
        if source == 'WAF' and log_data.get('messages'):
            if action == 1 or action == 2: return 10
            if action == 0: return 0
        if source == 'WAF' and not log_data.get('messages') and action == 0:
             return 5
        return -1

    def step(self, action):
        log_data = self.FAKE_LOG_DB[np.random.randint(len(self.FAKE_LOG_DB))]
        reward = self._get_reward(log_data, action)
        observation = self._get_observation(log_data)
        self.current_step += 1
        done = (self.current_step >= self.max_steps)
        return observation, reward, done, False, {}

    def reset(self, seed=None):
        self.current_step = 0
        log_data = self.FAKE_LOG_DB[np.random.randint(len(self.FAKE_LOG_DB))]
        return self._get_observation(log_data), {}

# --- STEP 3: THE "LIVE" AGENT 

blocked_uris = set()
blocked_ips = set()
rule_id_counter = 9000001 # Setting a high counter to avoid potential conflicts

def apply_rule_to_waf(action, log_data):
    """
    'waf_instance1' rule function
    """
    global rule_id_counter
    uri_to_block = log_data['transaction']['request']['uri']
    ip_to_block = log_data['transaction']['client_ip']
    rule_string = ""

    if action == 1 and uri_to_block not in blocked_uris:
        print(f"  [LIVE ACTION] DESICION: URI BLOCKED: {uri_to_block}")
        rule_string = f'SecRule REQUEST_URI "@streq {uri_to_block}" "id:{rule_id_counter},phase:1,deny,status:403,msg:\'Blocked by Federated RL Agent (URI)\'"'
        blocked_uris.add(uri_to_block)
            
    elif action == 2 and ip_to_block not in blocked_ips:
        print(f"  [LIVE ACTION] DECISION: IP BLOCKED: {ip_to_block}")
        rule_string = f'SecRule REMOTE_ADDR "@streq {ip_to_block}" "id:{rule_id_counter},phase:1,deny,status:403,msg:\'Blocked by Federated RL Agent (IP)\'"'
        blocked_ips.add(ip_to_block)
    
    else: # Action == 0 (Do Nothing)
        print(f"  [LIVE ACTION] DECISION: IGNORED.")
        return 

    try:
        cmd_write = f"sh -c \"echo '{rule_string}' >> /etc/nginx/dynamic_rules.conf\""
        waf_container.exec_run(cmd_write)
        waf_container.exec_run("nginx -s reload")
        print(f"  [SUCCESS] THE RULE {rule_id_counter} WAS APPLIED TO THE WAF!")
        rule_id_counter += 1
    except Exception as e:
        print(f"  [ERROR] FAILED TO APPLY THE RULE: {e}")

def live_log_parser(container_name, model):
    """
    Read the logs and use the Federated "Brain" to make decisions
    """
    print(f"[Live Listener] Connection (Live) to: {container_name}")
    try:
        container = client.containers.get(container_name)
        for line in container.logs(stream=True, follow=True, since=int(time.time())):
            log_entry = line.decode('utf-8').strip()
            
            if log_entry.startswith('{"transaction":'):
                try:
                    json_data = json.loads(log_entry)
                    json_data['source'] = 'WAF' if container_name == WAF_CONTAINER_NAME else 'HONEYPOT'
                    print("\n" + "="*20 + f" LIVE LOG ΑΠΟ [{container_name}] " + "="*20)
                    
                    # 1. Visualising the log
                    observation = WafEnv(db_source=[])._get_observation(json_data) 
                    
                    # 2. "Asking" the federated "brain" for advice
                    action, _states = model.predict(observation, deterministic=True)
                    
                    # 3. Write the rule
                    apply_rule_to_waf(action, json_data)
                    
                except json.JSONDecodeError:
                    pass
    except docker.errors.NotFound:
        print(f"[ERROR] The 'live' container '{container_name}' wasn't found!")

# --- STEP 4: THE FLOWER CLIENT 
class FlowerRLClient(fl.client.NumPyClient):
    def __init__(self, client_id):
        self.client_id = client_id
        if self.client_id == "1":
            print("[Client 1] I am the WAF AGENT (False Poitives). Loading WAF logs.")
            db = FAKE_LOG_DB_WAF
        else:
            print("[Client 2] I am the HONEYPOT AGENT (Zero-Day). Loading Honeypot logs.")
            db = FAKE_LOG_DB_HONEYPOT
            
        self.env = WafEnv(db_source=db)
        self.model = PPO("MlpPolicy", self.env, verbose=0) # Every client has its own PPO model

    def get_parameters(self, config):
        print(f"[Client {self.client_id}] Providing my brain...")
        return [param.detach().cpu().numpy() for param in self.model.policy.parameters()]

    def set_parameters(self, parameters):
        print(f"[Client {self.client_id}] Updated with new federated brain'!")
        params_dict = zip(self.model.policy.state_dict().keys(), parameters)
        state_dict = {k: torch.tensor(v) for k, v in params_dict}
        self.model.policy.load_state_dict(state_dict, strict=True)

    def fit(self, parameters, config):
        print(f"[Client {self.client_id}] Beginning local training (fit)...")
        self.set_parameters(parameters)
        self.model.learn(total_timesteps=1000) # Fast learning
        print(f"[Client {self.client_id}] Training finished.")
        return self.get_parameters(config={}), self.env.max_steps, {}

    def evaluate(self, parameters, config):
        return 0.0, 1, {}

# --- STEP 5: FINAL PROGRAMM ---
if __name__ == "__main__":
    
    # 1. Get the ID (1 or 2)
    client_id = sys.argv[1] if len(sys.argv) > 1 else "1"
    
    # 2. Creating the client
    client_object = FlowerRLClient(client_id=client_id)
    
    # --- Phase 1: Federation (Training) ---
    print(f"--- [CLIENT {client_id}] Phase 1: Coonectiing to Server for Federation ---")
    
    fl.client.start_numpy_client(
        server_address="127.0.0.1:8090", 
        client=client_object
    )
    
    # --- Phase 2: "CLOSED LOOP" (LIVE MODE) ---
    # (This will run only after the server finalises the 'Federation')
    
    print("\n" + "="*50)
    print(f"--- [CLIENT {client_id}] Phase 2: Federation is over! ---")
    print(f"--- Starting 'CLOSED LOOP' (LIVE MODE) ---")
    print(f"--- I use the final 'Federated Brain' ---")
    print("="*50 + "\n")
    
    # The final version of the federated super-brain
    final_model = client_object.model 
    
    if client_id == "1":
        #  Agent 1 listens to the real WAF
        target_container = WAF_CONTAINER_NAME
    else:
        # Ο Agent 2 listens to the trapped one (Honeypot)
        target_container = HONEYPOT_CONTAINER_NAME

    # Begin with "Live" listener and keep the script alive
    try:
        live_log_parser(target_container, final_model)
    except KeyboardInterrupt:
        print(f"\n[Client {client_id}] Stopping...these are the rules learned!!:")
        print(f"Blocked URIs: {blocked_uris}")
        print(f"Blocked IPs: {blocked_ips}")
