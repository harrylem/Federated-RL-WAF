import flwr as fl
import gymnasium as gym
from gymnasium import spaces
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from stable_baselines3 import PPO
import sys
import torch 

# --- STEP 1:Vectorization ---
vectorizer = TfidfVectorizer(max_features=9) 
vectorizer.fit(["/wp-admin.php", "/vulnerabilities/sqli", "/healthz", "SELECT", "FROM", "script"])

# --- STEP 2: DATA 

# DATA FROM THE WAF (False Positives + Known Threats)
FAKE_LOG_DB_WAF = [
    {'uri': '/', 'ip': '1.1.1.1', 'source': 'WAF', 'messages': []},
    {'uri': '/healthz', 'ip': '1.1.1.2', 'source': 'WAF', 'messages': []},
    {'uri': '/vulnerabilities/sqli?id=1', 'ip': '2.2.2.2', 'source': 'WAF', 'messages': ['SQL Injection Attack']},
]

# DATA FROM THE Honeypot (Zero-DayThreats) 
FAKE_LOG_DB_HONEYPOT = [
    {'uri': '/wp-admin.php', 'ip': '3.3.3.3', 'source': 'HONEYPOT', 'messages': []},
    {'uri': '/shell.php', 'ip': '4.4.4.4', 'source': 'HONEYPOT', 'messages': []},
    {'uri': '/.env', 'ip': '5.5.5.5', 'source': 'HONEYPOT', 'messages': []}
]

# --- STEP 3: Gym Environment ---
class WafEnv(gym.Env):
    def __init__(self, db_source): 
        super(WafEnv, self).__init__()
        
        self.action_space = spaces.Discrete(3)
        self.observation_space = spaces.Box(low=0, high=1, shape=(9,), dtype=np.float32) # 9 features!
        
        self.FAKE_LOG_DB = db_source 
        
        self.max_steps = 1000 # Max steps *per round*
        self.current_step = 0

    def _get_observation(self, log_data):
        uri = log_data['uri']
        vector = vectorizer.transform([uri]).toarray().flatten()
        return vector

    def _get_reward(self, log_data, action):
        uri = log_data['uri']
        source = log_data['source']

        if uri == "/healthz" and (action == 1 or action == 2): return -100
        if source == 'HONEYPOT':
            if action == 1 or action == 2: return 100
            if action == 0: return -50
        if source == 'WAF' and log_data['messages']:
            if action == 1 or action == 2: return 10
            if action == 0: return 0
        if source == 'WAF' and not log_data['messages'] and action == 0:
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

# --- STEP 4: Ο FLOWER RL CLIENT ---
class FlowerRLClient(fl.client.NumPyClient):
    def __init__(self, client_id):
        self.client_id = client_id
        
        # --- EVERY CLIENT MAKES IT'S OWN ENVIRONMENT! ---
        if self.client_id == "1":
            print("[Client 1] I am the WAF AGENT. Loading WAF logs.")
            db = FAKE_LOG_DB_WAF
        else:
            print("[Client 2] I am the HONEYPOT AGENT. Loading Honeypot logs.")
            db = FAKE_LOG_DB_HONEYPOT
            
        self.env = WafEnv(db_source=db)
        
        # Every client utilizes its own PPO model.
        self.model = PPO("MlpPolicy", self.env, verbose=0)

    def get_parameters(self, config):
        # neural network weights.
        print(f"[Client {self.client_id}] Sending my 'brain' to Server...")
        # Modyfying the Pytorch model to a lit Flower understands.
        return [param.detach().cpu().numpy() for param in self.model.policy.parameters()]

    def set_parameters(self, parameters):
        print(f"[Client {self.client_id}] Retrieved new 'Super-brain'!")
        # Loading the list of the Pytorch model.
        params_dict = zip(self.model.policy.state_dict().keys(), parameters)
        state_dict = {k: torch.tensor(v) for k, v in params_dict}
        self.model.policy.load_state_dict(state_dict, strict=True)

    def fit(self, parameters, config):
        # Training!!!
        print(f"[Client {self.client_id}] Beginning local training (fit)...")
        
        # 1.Getting the new "brain" from the server.
        self.set_parameters(parameters)
        
        # 2. Training based on it.
        self.model.learn(total_timesteps=1000)
        
        # 3. Sending the newly trained brain back.
        print(f"[Client {self.client_id}] Training finished.")
        return self.get_parameters(config={}), self.env.max_steps, {}

    def evaluate(self, parameters, config):
        return 0.0, 1, {}

# --- STEP 5: CLIENT RUNNING ---
if __name__ == "__main__":
    
    # Receive the ID (1 or 2)
    client_id = sys.argv[1] if len(sys.argv) > 1 else "1"
    
    # Creating the write client (WAF or Honeypot)
    client = FlowerRLClient(client_id=client_id)
    
    print(f"Ξεκινάω τον Flower RL Client {client_id} (v1.7)...")
    fl.client.start_numpy_client(
        server_address="127.0.0.1:8090", 
        client=client
    )
