import flwr as fl
import gymnasium as gym
from gymnasium import spaces
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from stable_baselines3 import PPO
import sys
import torch 

# --- ΒΗΜΑ 1: Ο "ΜΕΤΑΦΡΑΣΤΗΣ" (Vectorization) ---
vectorizer = TfidfVectorizer(max_features=9) 
vectorizer.fit(["/wp-admin.php", "/vulnerabilities/sqli", "/healthz", "SELECT", "FROM", "script"])

# --- ΒΗΜΑ 2: ΤΑ ΔΕΔΟΜΕΝΑ 

# Δεδομένα ΜΟΝΟ από το WAF (False Positives + Γνωστές Απειλές)
FAKE_LOG_DB_WAF = [
    {'uri': '/', 'ip': '1.1.1.1', 'source': 'WAF', 'messages': []},
    {'uri': '/healthz', 'ip': '1.1.1.2', 'source': 'WAF', 'messages': []},
    {'uri': '/vulnerabilities/sqli?id=1', 'ip': '2.2.2.2', 'source': 'WAF', 'messages': ['SQL Injection Attack']},
]

# Δεδομένα ΜΟΝΟ από το Honeypot (Zero-Day Απειλές)
FAKE_LOG_DB_HONEYPOT = [
    {'uri': '/wp-admin.php', 'ip': '3.3.3.3', 'source': 'HONEYPOT', 'messages': []},
    {'uri': '/shell.php', 'ip': '4.4.4.4', 'source': 'HONEYPOT', 'messages': []},
    {'uri': '/.env', 'ip': '5.5.5.5', 'source': 'HONEYPOT', 'messages': []}
]

# --- ΒΗΜΑ 3: ΤΟ "ΠΕΡΙΒΑΛΛΟΝ" (Gym Environment) ---
class WafEnv(gym.Env):
    def __init__(self, db_source): 
        super(WafEnv, self).__init__()
        
        self.action_space = spaces.Discrete(3)
        self.observation_space = spaces.Box(low=0, high=1, shape=(9,), dtype=np.float32) # 9 features!
        
        self.FAKE_LOG_DB = db_source 
        
        self.max_steps = 1000 # Max steps *ανά γύρο*
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

# --- ΒΗΜΑ 4: Ο FLOWER RL CLIENT ---
class FlowerRLClient(fl.client.NumPyClient):
    def __init__(self, client_id):
        self.client_id = client_id
        
        # --- ΚΑΘΕ CLIENT ΦΤΙΑΧΝΕΙ ΤΟ ΔΙΚΟ ΤΟΥ ΠΕΡΙΒΑΛΛΟΝ! ---
        if self.client_id == "1":
            print("[Client 1] Εγώ είμαι ο WAF AGENT (Προσεκτικός). Φορτώνω WAF logs.")
            db = FAKE_LOG_DB_WAF
        else:
            print("[Client 2] Εγώ είμαι ο HONEYPOT AGENT (Επιθετικός). Φορτώνω Honeypot logs.")
            db = FAKE_LOG_DB_HONEYPOT
            
        self.env = WafEnv(db_source=db)
        
        # Κάθε client έχει το δικό του PPO model
        self.model = PPO("MlpPolicy", self.env, verbose=0)

    def get_parameters(self, config):
        # (τα weights του νευρωνικού δικτύου)
        print(f"[Client {self.client_id}] Στέλνω το 'μυαλό' μου στον Server...")
        # (Αυτό μετατρέπει το Pytorch model σε λίστα που καταλαβαίνει το Flower)
        return [param.detach().cpu().numpy() for param in self.model.policy.parameters()]

    def set_parameters(self, parameters):
        print(f"[Client {self.client_id}] Πήρα νέο 'Super-μυαλό'!")
        # (Αυτό φορτώνει τη λίστα στο Pytorch model)
        params_dict = zip(self.model.policy.state_dict().keys(), parameters)
        state_dict = {k: torch.tensor(v) for k, v in params_dict}
        self.model.policy.load_state_dict(state_dict, strict=True)

    def fit(self, parameters, config):
        # "Ώρα για εκπαίδευση!"
        print(f"[Client {self.client_id}] Ξεκινάω τοπική εκπαίδευση (fit)...")
        
        # 1. Παίρνω το νέο "μυαλό" από τον server
        self.set_parameters(parameters)
        
        # 2. Εκπαιδεύσμαι πάνω σε αυτό 
        self.model.learn(total_timesteps=1000)
        
        # 3. Στέλνω το *νέο, βελτιωμένο* "μυαλό" πίσω
        print(f"[Client {self.client_id}] Η εκπαίδευση τελείωσε.")
        return self.get_parameters(config={}), self.env.max_steps, {}

    def evaluate(self, parameters, config):
        return 0.0, 1, {}

# --- ΒΗΜΑ 5: ΞΕΚΙΝΑΕΙ Ο CLIENT ---
if __name__ == "__main__":
    
    # Παίρνω το ID (1 ή 2) από την εντολή
    client_id = sys.argv[1] if len(sys.argv) > 1 else "1"
    
    # Φτιάχνω τον σωστό Client (WAF ή Honeypot)
    client = FlowerRLClient(client_id=client_id)
    
    print(f"Ξεκινάω τον Flower RL Client {client_id} (v1.7)...")
    fl.client.start_numpy_client(
        server_address="127.0.0.1:8090", 
        client=client
    )
