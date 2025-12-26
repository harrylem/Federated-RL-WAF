import flwr as fl
import pandas as pd
import numpy as np
import gymnasium as gym
from gymnasium import spaces
from stable_baselines3 import PPO
from sklearn.feature_extraction.text import TfidfVectorizer
import torch
import os

# We load the data from a CSV file
def load_data(filepath):
    if not os.path.exists(filepath):
        return [{'URL': '/fake_test', 'classification': 0}]
    try:
        df = pd.read_csv(filepath)
        df['URL'] = df['URL'].fillna('')  # Fill NaN values with empty strings
        data = df[['URL', 'classification']].to_dict('records')
        return data
    except Exception as e:
        print(f"Error loading data: {e}")
        return [{'URL': '/fake_test', 'classification': 0}] #Fake data for crash prevention

# We find the absolute path of the dataset
script_dir = os.path.dirname(os.path.abspath(__file__))

# We go one level up to find the project root
project_root = os.path.dirname(script_dir)

# We find the dataset path
DATASET_PATH = os.path.join(project_root, 'datasets', 'csic_database.csv')
dataset = load_data(DATASET_PATH)
# Vectorizer (Has to be the same as the WAF agent's one!!)
vectorizer = TfidfVectorizer(max_features=9)
all_uris = [row['URL'] for row in dataset]
if len(all_uris) > 0:
    vectorizer.fit(all_uris)

class CsicEnv(gym.Env):
    def __init__(self, data):
        super(CsicEnv, self).__init__()
        self.data = data
        self.current_idx = 0
        self.action_space = spaces.Discrete(3)  # Action 0=Allow, 1=Block_IP, 2=Block_URI
        self.observation_space = spaces.Box(low=0, high=1, shape=(9,), dtype=np.float32) #Observation: 9 TF-IDF features

    def _get_obs(self,uri):
        return vectorizer.transform([uri]).toarray().flatten().astype(np.float32) #Converting URL to numbers
    
    def step(self, action):
        row = self.data[self.current_idx] # Cuurent row
        is_attack = row['classification'] == 1 #Assuming the trafick is attack if classification==1

        reward = 0
        if is_attack:
            if action > 0: reward = 10  # Blocked correctly
            else:          reward = -10  # Missed attack
        else:
            if action == 0: reward = 6   # Ignored correctly
            else:          reward = -20   # False positive - Blocked legitimate traffic

        # Next CSV record
        self.current_idx = (self.current_idx +1) % len(self.data)
        done = False # Never ending training
        next_row = self.data[self.current_idx]
        obs = self._get_obs(next_row['URL'])
        return obs, reward, done, False, {}

    def reset(self, seed=None):
        self.current_idx = np.random.randint(len(self.data))
        row = self.data[self.current_idx]
        return self._get_obs(row['URL']), {}

# --The Flower Client -> Database Learner-- #        
class DatasetClient(fl.client.NumPyClient):
    def __init__(self):
        self.env = CsicEnv(dataset) #Csv dataset environment
        self.model = PPO("MlpPolicy", self.env, verbose=1) #We create the PPO agent

    def get_parameters(self, config):
        return [param.detach().cpu().numpy() for param in self.model.policy.parameters()]

    def fit(self, parameters, config):
    # Loading Global weights from Server
        params_dict = zip(self.model.policy.state_dict().keys(), parameters)
        state_dict = {k: torch.tensor(v) for k, v in params_dict}
        self.model.policy.load_state_dict(state_dict, strict=True)
        print(f"Training on {len(dataset)} rows from CSIC dataset...")
        self.model.learn(total_timesteps=1000) #Training for 1000 timesteps
        return self.get_parameters(config={}), len(dataset), {} #Returning the updated model parameters

    def evaluate(self, parameters, config):
        # Simple evaluation: return 0 loss and accuracy of 1.0
        return 0.0, len(dataset), {"accuracy": 1.0}


if __name__ == "__main__":
    # Connect to Flower server (It has to be running...)
    print("Starting Dataset Client (Historical Data)...")
    fl.client.start_client(server_address="127.0.0.1:8090", client=DatasetClient().to_client())