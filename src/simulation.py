import flwr as fl
from flwr.server.strategy import FedAvg, FedMedian
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from stable_baselines3 import PPO
import gymnasium as gym
from gymnasium import spaces 
import torch

# --- 1. SIMULATION CONFIGURATION---
NUM_CLIENTS = 10        # Total number of clients
CLIENTS_PER_ROUND = 5   # How many will be trained each round?
NUM_ROUNDS = 5          # How many rounds?

# --- 2. THE DATA(Expanded Dataset) ---
# We create a bigger pool of data
LOGS_SQLI = [
    {'uri': '/vulnerabilities/sqli?id=1', 'type': 'SQLi', 'messages': ['SQL Injection']},
    {'uri': '/product?id=1 OR 1=1', 'type': 'SQLi', 'messages': ['SQL Injection']},
    {'uri': '/login?user=\' OR \'1\'=\'1', 'type': 'SQLi', 'messages': ['SQL Injection']},
]
LOGS_XSS = [
    {'uri': '/search?q=<script>alert(1)</script>', 'type': 'XSS', 'messages': ['XSS Attack']},
    {'uri': '/comment?msg=<img src=x onerror=alert(1)>', 'type': 'XSS', 'messages': ['XSS Attack']},
    {'uri': '/profile?name=<svg/onload=alert(1)>', 'type': 'XSS', 'messages': ['XSS Attack']},
]
LOGS_BENIGN = [
    {'uri': '/', 'type': 'Normal', 'messages': []},
    {'uri': '/healthz', 'type': 'Normal', 'messages': []},
    {'uri': '/about', 'type': 'Normal', 'messages': []},
    {'uri': '/contact', 'type': 'Normal', 'messages': []},
]

# Vectorizer 
vectorizer = TfidfVectorizer(max_features=9)
all_uris = [l['uri'] for l in LOGS_SQLI + LOGS_XSS + LOGS_BENIGN]
vectorizer.fit(all_uris)

# --- 3. THE ENVIRONMENT (Gym Env - Simplified) ---
class SimWafEnv(gym.Env):
    def __init__(self, local_data):
        super(SimWafEnv, self).__init__()
        self.action_space = spaces.Discrete(3)
        self.observation_space = spaces.Box(low=0, high=1, shape=(9,), dtype=np.float32)
        self.data = local_data
        self.max_steps = 50 # Smaller steps for a quick simulation
        self.current_step = 0

    def _get_obs(self, log):
        return vectorizer.transform([log['uri']]).toarray().flatten().astype(np.float32)

    def _get_reward(self, log, action):
        # Simple Reward Logic for Simulation
        is_attack = (log['type'] in ['SQLi', 'XSS'])
        if is_attack:
            # Correct Reaction: Block (1 ή 2) -> +10, Wrong Reaction: Ignore (0) -> -10
            return 10 if action > 0 else -10
        else:
            # Correct Reaction: Ignore (0) -> +5, Wrong Reaction: Block -> -20 (False Positive)
            return 5 if action == 0 else -20

    def step(self, action):
        log = self.data[np.random.randint(len(self.data))]
        obs = self._get_obs(log)
        reward = self._get_reward(log, action)
        self.current_step += 1
        done = self.current_step >= self.max_steps
        return obs, reward, done, False, {}

    def reset(self, seed=None):
        self.current_step = 0
        log = self.data[np.random.randint(len(self.data))]
        return self._get_obs(log), {}

# --- 4. THE FLOWER CLIENT ---
class SimClient(fl.client.NumPyClient):
    def __init__(self, cid):
        self.cid = int(cid)
        
        # --- NON-IID DATA PARTITIONING ---
        # Clients 0-4: They basicly see SQLi + Normal
        # Clients 5-9: They basicly XSS + Normal
        if self.cid < 5:
            self.local_data = LOGS_SQLI * 4 + LOGS_XSS * 1 + LOGS_BENIGN * 5
            print(f"[Client {cid}] I am an SQLi Expert!")
        else:
            self.local_data = LOGS_XSS * 4 + LOGS_SQLI * 1 + LOGS_BENIGN * 5
            print(f"[Client {cid}] I am an XSS Expert!")
            
        self.env = SimWafEnv(self.local_data)
        self.model = PPO("MlpPolicy", self.env, verbose=0)

    def get_parameters(self, config):
        return [param.detach().cpu().numpy() for param in self.model.policy.parameters()]

    def fit(self, parameters, config):
        # Weight Loading
        params_dict = zip(self.model.policy.state_dict().keys(), parameters)
        state_dict = {k: torch.tensor(v) for k, v in params_dict}
        self.model.policy.load_state_dict(state_dict, strict=True)
        
        # Training
        self.model.learn(total_timesteps=200) # Quick training
        
        # Return of new weights
        return self.get_parameters(config={}), len(self.local_data), {}

    def evaluate(self, parameters, config):
        return 0.0, len(self.local_data), {"accuracy": 0.0} # Dummy eval

# --- 5. CLIENT GENERATING FUNCTION ---
def client_fn(cid: str):
    return SimClient(cid).to_client()

# --- 6. MAIN PROGRAMM (SIMULATION) ---
if __name__ == "__main__":
    print(f"Beginning Simulation with {NUM_CLIENTS} Clients (Non-IID)...")
    
    # Choose strategy: 1) FedAvg Or 2) FedMedian
    # We define a strategy (Server)
    # strategy = fl.server.strategy.FedAvg(
    #    fraction_fit=CLIENTS_PER_ROUND / NUM_CLIENTS, # Choosing 50% of clients
    #    fraction_evaluate=0.0, # No global evaluation 
    #    min_fit_clients=CLIENTS_PER_ROUND,
    #    min_available_clients=NUM_CLIENTS,
    #)
    
    # FedMedian is a more resilient strategy on "poisoned" updates from clients!!!
    strategy = fl.server.strategy.FedMedian(
        fraction_fit=CLIENTS_PER_ROUND / NUM_CLIENTS,
        fraction_evaluate=0.0,
        min_fit_clients=CLIENTS_PER_ROUND,
        min_available_clients=NUM_CLIENTS,
     )
    
    # We run the simulation!
    # Flower Simulation - Virtual Client Engine.
    fl.simulation.start_simulation(
        client_fn=client_fn,
        num_clients=NUM_CLIENTS,
        config=fl.server.ServerConfig(num_rounds=NUM_ROUNDS),
        strategy=strategy,
        client_resources={"num_cpus": 1} 
    )