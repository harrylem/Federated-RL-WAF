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
import os

# --- STEP 1: GLOBAL SETUP ---
WAF_CONTAINER_NAME = "waf_instance1"
HONEYPOT_CONTAINER_NAME = "waf_honeypot"
CURSOR_STATE_FILE = "agent_log_state.json" # To keep track of log reading positions
# Global blocking lists (defined here to be accessible by all functions)
blocked_uris = set()
blocked_ips = set()
rule_id_counter = 9000001 

# Connecting to Docker to access ruleset
try:
    client = docker.from_env()
    # Check if WAF container exists (only critical if we are Agent 1, but good to check)
    try:
        waf_container = client.containers.get(WAF_CONTAINER_NAME)
    except docker.errors.NotFound:
        print(f"[WARN] Container '{WAF_CONTAINER_NAME}' not found. Live rules might fail if you are Agent 1.")
        waf_container = None
except Exception as e:
    print(f"FATAL ERROR: Could not connect to Docker Daemon. Is it running? {e}")
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

# --- STEP 2: THE MAIN ENVIRONMENT (Gym Env) ---
class WafEnv(gym.Env):
    def __init__(self, db_source): 
        super(WafEnv, self).__init__()
        self.action_space = spaces.Discrete(3) # 0: Pass, 1: Block URI, 2: Block IP
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

        # Reward Logic
        if uri == "/healthz" and (action == 1 or action == 2): return -100
        if source == 'HONEYPOT':
            if action == 1 or action == 2: return 100
            if action == 0: return -50
        if source == 'WAF' and log_data.get('messages'): # Attack detected by WAF signature
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

# --- STEP 3: THE "LIVE" AGENT LOGIC ---

def apply_rule_to_waf(action, log_data):
    """
    Applies the decision to the 'waf_instance1' container.
    """
    global rule_id_counter
    
    # Safety check
    if waf_container is None:
        return

    try:
        uri_to_block = log_data['transaction']['request']['uri']
        ip_to_block = log_data['transaction']['client_ip']
    except KeyError:
        return # Malformed log

    rule_string = ""

    if action == 1 and uri_to_block not in blocked_uris:
        print(f"  [LIVE ACTION] DECISION: URI BLOCKED: {uri_to_block}")
        rule_string = f'SecRule REQUEST_URI "@streq {uri_to_block}" "id:{rule_id_counter},phase:1,deny,status:403,msg:\'Blocked by Federated RL Agent (URI)\'"'
        blocked_uris.add(uri_to_block)
            
    elif action == 2 and ip_to_block not in blocked_ips:
        print(f"  [LIVE ACTION] DECISION: IP BLOCKED: {ip_to_block}")
        rule_string = f'SecRule REMOTE_ADDR "@streq {ip_to_block}" "id:{rule_id_counter},phase:1,deny,status:403,msg:\'Blocked by Federated RL Agent (IP)\'"'
        blocked_ips.add(ip_to_block)
    
    else: # Action == 0 (Do Nothing)
        print(f"  [LIVE ACTION] DECISION: IGNORED.")
        return 

    # Write rule to container
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
    print(f"[Live Listener] Connecting (Live) to: {container_name}")
    try:
        container = client.containers.get(container_name)
        # Follow the logs (blocking loop)
        for line in container.logs(stream=True, follow=True, since=int(time.time())):
            log_entry = line.decode('utf-8').strip()
            
            # We look for ModSecurity JSON logs
            if log_entry.startswith('{"transaction":'):
                try:
                    json_data = json.loads(log_entry)
                    json_data['source'] = 'WAF' if container_name == WAF_CONTAINER_NAME else 'HONEYPOT'
                    print("\n" + "="*20 + f" LIVE LOG FROM [{container_name}] " + "="*20)
                    
                    # 1. Transform log to observation vector
                    # Note: We instantiate a temporary Env just to use the helper method _get_observation
                    observation = WafEnv(db_source=[])._get_observation(json_data) 
                    
                    # 2. "Asking" the federated "brain" for advice
                    action, _states = model.predict(observation, deterministic=True)
                    
                    # 3. Apply the rule (if needed)
                    apply_rule_to_waf(action, json_data)
                    
                except json.JSONDecodeError:
                    pass
    except docker.errors.NotFound:
        print(f"[ERROR] The 'live' container '{container_name}' wasn't found!")
    except Exception as e:
        print(f"[ERROR] Live parser stream interrupted: {e}")

# --- STEP 4: THE FLOWER CLIENT ---
class FlowerRLClient(fl.client.NumPyClient):
    def __init__(self, client_id):
        self.client_id = client_id
        self.log_cursors = {} # Keep track of file reading positions
        # Load previous cursor state if exists
        self.load_cursor_state()
        if self.client_id == "1":
            print("[Client 1] I am the WAF AGENT (False Positives). Loading WAF logs.")
            db = FAKE_LOG_DB_WAF
        elif self.client_id == "2":
            print("[Client 2] I am the HONEYPOT AGENT (Zero-Day). Loading Honeypot logs.")
            db = FAKE_LOG_DB_HONEYPOT
        else:
            print(f"[Client {self.client_id}] Unknown client ID! Exiting.")
            sys.exit(1)
            
        self.env = WafEnv(db_source=db)
        self.model = PPO("MlpPolicy", self.env, verbose=0) # Every client has its own PPO model
    
    def load_cursor_state(self):
        # Load the cursor positions from a file if it exists
        if os.path.exists(CURSOR_STATE_FILE):
            try:
                with open(CURSOR_STATE_FILE, 'r') as f:
                    self.log_cursors = json.load(f)
                print(f"[SYSTEM] Loaded log reading state from {CURSOR_STATE_FILE}")
            except Exception:
                print("[WARN] Corrupted state file. Starting fresh.")
                self.log_cursors = {}
        else:
            self.log_cursors = {}
    def save_cursor_state(self):
       # Save the current cursor positions to a file
        try:
            with open(CURSOR_STATE_FILE, 'w') as f:
                json.dump(self.log_cursors, f)
        except Exception as e:
            print(f"[WARN] Could not save cursor state: {e}")

    def get_parameters(self, config):
        print(f"[Client {self.client_id}] Providing my brain parameters...")
        return [param.detach().cpu().numpy() for param in self.model.policy.parameters()]

    def set_parameters(self, parameters):
        print(f"[Client {self.client_id}] Updated with new 'Federated Brain'!")
        params_dict = zip(self.model.policy.state_dict().keys(), parameters)
        state_dict = {k: torch.tensor(v) for k, v in params_dict}
        self.model.policy.load_state_dict(state_dict, strict=True)

    def load_honeypot_logs(self):
        # Dynamic path resolution relative to this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir) # Adjust if your folder structure differs
        configs_root = os.path.join(project_root, "honeynet_configs")
        
        log_files_to_scan = []
        if os.path.exists(configs_root):
            for root, dirs, files in os.walk(configs_root):
                if "error.log" in files:
                    log_files_to_scan.append(os.path.join(root, "error.log"))
        
        total_new_attacks = 0

        for log_path in log_files_to_scan:
            try:
                folder_name = os.path.basename(os.path.dirname(log_path)).upper()
            except:
                folder_name = "UNKNOWN"
            
            # Initialize cursor if new file
            if log_path not in self.log_cursors:
                self.log_cursors[log_path] = 0
            
            # Read logs
            if os.path.exists(log_path):
                current_file_size = os.path.getsize(log_path)
                saved_cursor = self.log_cursors.get(log_path, 0)
                # Handle log rotation - Ιf file size is smaller than saved cursor, reset cursor
                if current_file_size < saved_cursor:
                    print(f"[INFO] Log rotation detected for {folder_name}. Resetting cursor.")
                    saved_cursor = 0
                try:
                    with open(log_path, 'r') as f:
                        f.seek(self.log_cursors[log_path])
                        new_lines = f.readlines()
                        # Update cursor position
                        self.log_cursors[log_path] = f.tell()

                        attacks_in_file = 0
                        for line in new_lines:
                            # Simple heuristic for ModSecurity blocks
                            if "ModSecurity" in line and "Access denied" in line:
                                attacks_in_file += 1
                        
                        if attacks_in_file > 0:
                            print(f"[ALERT] Found {attacks_in_file} new attacks in: {folder_name}")
                            total_new_attacks += attacks_in_file
            
                except Exception as e:
                    print(f"[ERROR] Could not read {folder_name}: {e}")              
        self.save_cursor_state()          
        return total_new_attacks

    def fit(self, parameters, config):
        print(f"[Client {self.client_id}] Beginning local training (fit)...")
        
        # Default training steps
        training_steps = 1000
        
        # If I am client 2 (Honeypot), I check the logs to boost training
        if str(self.client_id) == "2":
            print(f"[Client {self.client_id}] Checking honeypot logs for Zero-Day patterns...")
            new_attacks = self.load_honeypot_logs()
            
            if new_attacks > 0:
                boost = new_attacks * 2000
                training_steps += boost
                print(f"Training will be intensified due to {new_attacks} new attacks! (Total Steps: {training_steps})")
            else:
                # No new attacks, keep standard training
                training_steps = 1000

        # Update local model with global parameters
        self.set_parameters(parameters)
        
        # Train
        self.model.learn(total_timesteps=training_steps)
        print(f"[Client {self.client_id}] Training finished.")
        
        return self.get_parameters(config={}), self.env.max_steps, {}

    def evaluate(self, parameters, config):
        return 0.0, 1, {}

# --- STEP 5: FINAL PROGRAM ---
if __name__ == "__main__":
    
    # 1. Get the ID (1 or 2)
    client_id = sys.argv[1] if len(sys.argv) > 1 else "1"
    
    # 2. Create the client
    client_object = FlowerRLClient(client_id=client_id)
    
    # --- Phase 1: Federation (Training) ---
    print(f"--- [CLIENT {client_id}] Phase 1: Connecting to Server for Federation ---")
    
    # This blocks until training rounds are done
    fl.client.start_numpy_client(
        server_address="127.0.0.1:8090", 
        client=client_object
    )
    
    # --- Phase 2: "CLOSED LOOP" (LIVE MODE) ---
    print("\n" + "="*50)
    print(f"--- [CLIENT {client_id}] Phase 2: Federation is over! ---")
    print(f"--- Starting 'CLOSED LOOP' (LIVE MODE) ---")
    print(f"--- I use the final 'Federated Brain' ---")
    print("="*50 + "\n")
    
    # Get the trained model
    final_model = client_object.model 
    
    if client_id == "1":
        # Agent 1 listens to the real WAF
        target_container = WAF_CONTAINER_NAME
    else:
        # Agent 2 listens to the trapped one (Honeypot)
        target_container = HONEYPOT_CONTAINER_NAME

    # Begin "Live" listener
    try:
        live_log_parser(target_container, final_model)
    except KeyboardInterrupt:
        print(f"\n[Client {client_id}] Stopping... Rules learned during this session:")
        print(f"Blocked URIs: {blocked_uris}")
        print(f"Blocked IPs: {blocked_ips}")