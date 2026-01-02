import flwr as fl
import numpy as np
import os
import pandas as pd
import matplotlib.pyplot as plt
from typing import List, Tuple, Dict, Optional
from flwr.common import Metrics

# Machine Learning Imports
from stable_baselines3 import PPO
import gymnasium as gym
from gymnasium import spaces
from sklearn.feature_extraction.text import TfidfVectorizer

# --- Dynamic Path Configuration for Model Persistence ---
# Get the absolute directory where this script is located (portable path)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Define the 'saved_models' directory relative to this script
SAVE_DIR = os.path.join(SCRIPT_DIR, "saved_models")
# We search for the dataset where the dataset_client.py sets it ( At dataset/csic_database.csv )
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR) # We go one level up to 'src' parent
DATASET_PATH = os.path.join(PROJECT_ROOT, 'datasets', 'csic_database.csv')
# Ensure the directory exists, if not create it.
if not os.path.exists(DATASET_PATH):
    DATASET_PATH = os.path.join(SCRIPT_DIR, "dataset.csv")
    print(f"[SYSTEM] Dataset not found at {DATASET_PATH}. Using fallback.")

if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)
    print(f"[SYSTEM] Created directory for models at: {SAVE_DIR}")

# File paths for the persistent model (brain) and the visualization plot.
MODEL_FILE = os.path.join(SAVE_DIR, "global_federated_model.npz")
PLOT_FILE = os.path.join(SAVE_DIR, "training_progress.png")
print(f"[SYSTEM] Dynamic Path Configured. Saving data to:\n   {SAVE_DIR}")

#--- Shared Vectorizer for all clients ---
def get_shared_vectorizer():
    vec = TfidfVectorizer(max_features=50)
    vec.fit([
     # ModSecurity Keywords (Critical for Live Mode)
        "SQL Injection", "XSS", "Cross-site Scripting", "Remote Command Execution",
        "Scanner", "Crawler", "Bot", "Denied", "Access denied", "Forbidden",
        "PHP Injection", "Anomaly", "Score Exceeded", "Inbound Anomaly",
        
        # Attack Payloads
        "SELECT", "UNION", "AND", "OR", "1=1", "ALERT", "SCRIPT", "IFRAME",
        "etc/passwd", "cmd.exe", "bin/sh", "wget", "curl",
        
        # Common URI parts (Για να μη βγαίνει BLIND το Honeypot)
        "/", "index", "php", "html", "login", "admin", "dashboard",
        "/wp-admin", "/vulnerabilities", "id", "search", "query",
        
        # User Agents & Headers
        "Mozilla", "Chrome", "Safari", "Gecko", "Postman", "Python"
    ])
    return vec
#--- Custom Gym Environment for Dataset (Logic implemented from dataset_client.py) ---
class DatasetEnv(gym.Env):
    """
    A custom environment that reads line-by-line from a CSV and trains the agent.
    """
    def __init__(self, dataframe, vectorizer):
        super(DatasetEnv, self).__init__()
        self.data = dataframe.to_dict('records')
        self.vectorizer = vectorizer
        self.current_idx = 0
        
        # Action Space: 0=Allow, 1=Block
        self.action_space = spaces.Discrete(2)
        
        # Observation: The 9-feature vector from the TF-IDF Vectorizer
        self.observation_space = spaces.Box(low=0, high=10, shape=(50,), dtype=np.float32)
        
        self.current_step = 0

    def _get_obs(self, uri):
        # Exactly the same as in dataset_client.py but with shared vectorizer
        return self.vectorizer.transform([str(uri)]).toarray().flatten().astype(np.float32)
    
    def step(self, action):
        row = self.data[self.current_idx]
        
        # Logic from dataset_client.py: classification 1 == Attack
        is_attack = row['classification'] == 1 

        # Reward Logic (The same as in dataset_client.py but adjusted for 2 actions)
        reward = 0
        if is_attack:
            if action == 1: # Blocked Attack
                reward = 10 
            else:           # Missed Attack
                reward = -10
        else: # Normal Traffic
            if action == 0: # Allowed Normal
                reward = 6 
            else:           # False Positive (Blocked Normal)
                reward = -20

        # Next record
        self.current_idx = (self.current_idx + 1) % len(self.data)
        done = self.current_idx == 0 # It ends when the loop starts over
        
        next_row = self.data[self.current_idx]
        obs = self._get_obs(next_row['URL'])
        
        return obs, reward, done, False, {}
    
    def reset(self, seed=None):
            self.current_idx = 0
            row = self.data[self.current_idx]
            return self._get_obs(row['URL']), {}

    # -- PRE-TRAINING LOGIC -- 
def pretrain_with_dataset():
    print(f"\n📚 [PRE-TRAINING] Looking for dataset at: {DATASET_PATH}")
        
        # Load Dataset
    try:
        if os.path.exists(DATASET_PATH):
            df = pd.read_csv(DATASET_PATH)
            df['URL'] = df['URL'].fillna('') # Fix NaN values
            print(f"   ✅ Loaded {len(df)} samples from CSIC Database.")
        else:
            print(" Dataset file not found! Generating dummy data for demonstration...")
            df = pd.DataFrame({
                    'URL': ['/index.php'] * 500 + ['/admin.php?id=1 UNION SELECT'] * 500,
                    'classification': [0] * 500 + [1] * 500
                })
                
            # Shuffle the dataset
            df = df.sample(frac=1).reset_index(drop=True)

    except Exception as e:
        print(f"Error loading dataset: {e}")
        return

    # Prepare Vectorizer
    print(" Initializing Shared Vocabulary (Live + Dataset)...")
    vectorizer = get_shared_vectorizer()
        
    # Training
    env = DatasetEnv(df, vectorizer)
    model = PPO("MlpPolicy", env, verbose=1)
        
    print(" Starting Offline Training (PPO)...")
    # We train for as many timesteps as there are samples in the dataset
    model.learn(total_timesteps=len(df)) 
        
    # Save the pre-trained model to disk
    print("[PRE-TRAINING] Finished! Saving Knowledge...")
    params = model.get_parameters()
    # Convert PyTorch tensors to Numpy arrays for the Flower Server
    params_numpy = [val.cpu().numpy() for key, val in params['policy'].items()]
        
    try:
        np.savez(MODEL_FILE, *params_numpy)
        print(f"   Saved Initial Brain to: {MODEL_FILE}\n")
    except Exception as e:
        print(f"   ❌ Failed to save model: {e}")

        # -- Main menu --
def main_menu():
        while True:
            print("\n" + "="*60)
            print(" FEDERATED WAF - HYBRID LEARNING CONTROL CENTER ")
            print("="*60)
            print("1.Start Federated Server (Live Mode)")
            print("2.Pre-train with Dataset (Offline Mode - CSIC 2010)")
            print(f"Looks for file at: {DATASET_PATH}")
            print("3.Exit...")
            
            choice = input("\nSelect Option (1-3): ")
                
            if choice == '1':
                return
            elif choice == '2':
                pretrain_with_dataset()
                input("Press ENTER to return to menu...")
            elif choice == '3':
                exit()
            else:
                print("Invalid selection!!")

 # --- 1. Custom Strategy for saving stats of the model after each training ---
class SaveModelStrategy(fl.server.strategy.FedAvg):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.best_reward = -float('inf')
        self.reward_history = []  # To store (round, avg_reward) tuples for plotting

    # Override aggregate_fit to save the model if it improves at the end of each round
    def aggregate_fit(
        self,
        server_round: int,
        results: List[Tuple[fl.server.client_proxy.ClientProxy, fl.common.FitRes]],
        failures: List[BaseException],
    ) -> Tuple[Optional[fl.common.Parameters], Dict[str, fl.common.Scalar]]:
        # This method aggregates the model weights received from all clients.
        # It calculates the new 'Global Brain' and saves it to the disk.
        # Perform standard aggregation (calculate average weights)
        aggregated_parameters, aggregated_metrics = super().aggregate_fit(server_round, results, failures)

        if aggregated_parameters is not None:
            print(f"[Round {server_round}] Saving new global model to '{MODEL_FILE}'...")
            # Convert Parameters to ndarrays and save as .npz file
            aggregated_ndarrays = fl.common.parameters_to_ndarrays(aggregated_parameters)
            # Save to the dynamic path
            try:
                np.savez(MODEL_FILE, *aggregated_ndarrays)
                print(f"   Saved to: {MODEL_FILE}")
            except Exception as e:
                print(f"   [ERROR] Failed to save model: {e}")

        return aggregated_parameters, aggregated_metrics
    
    # Metrics aggregation after evaluation
    def aggregate_evaluate(
        self,
        server_round: int,
        results: List[Tuple[fl.server.client_proxy.ClientProxy, fl.common.EvaluateRes]],
        failures: List[BaseException],
    ) -> Tuple[Optional[fl.common.Parameters], Dict[str, fl.common.Scalar]]:
        # This method aggregates the evaluation metrics (specifically 'mean_reward')
        # received from the clients. It helps to understand if the AI is getting smarter.

        if not results:
            return None, {}
        # The mean reward across all clients is collected
        rewards = []
        for _, eval_res in results:
            if "mean_reward" in eval_res.metrics:
                rewards.append(eval_res.metrics["mean_reward"])

        # Calculate the Global Average Reward for this round
        if rewards:
            avg_reward = sum(rewards) / len(rewards)
            # Store this data point for the final plot
            self.reward_history.append((server_round, avg_reward))
            print(f"\n [STATS - Round {server_round}] Global Average Reward: {avg_reward:.4f}")
            print(f"  (Based on feedback from {len(rewards)} clients)\n")
            # Update the plot live!
            generate_training_plot(self.reward_history)
            return avg_reward, {"mean_reward": avg_reward}
        
        return super().aggregate_evaluate(server_round, results, failures)
            
    # --- 2. Helper for loading the old model ---

def generate_training_plot(history): # Generates and saves a plot of training progress ~ X-axis: Rounds, Y-axis: Average Reward 
    if not history:
        print("[WARN] No training history found. Skipping plot generation.")
        return

    print("\nGenerating Visualization Plot...")
    rounds = [x[0] for x in history]
    rewards = [x[1] for x in history]

    plt.figure(figsize=(10, 6))
    plt.plot(rounds, rewards, marker='o', linestyle='-', color='b', label='Global Model Performance')
    
    plt.title('Federated Reinforcement Learning: Training Progress', fontsize=14)
    plt.xlabel('Federation Rounds', fontsize=12)
    plt.ylabel('Average Reward', fontsize=12)
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.legend()
    
    # Save the plot to the dynamic path
    try:
        plt.savefig(PLOT_FILE)
        print(f"[VISUALIZATION] Plot saved successfully at:\n   {PLOT_FILE}")
    except Exception as e:
        print(f"   [ERROR] Failed to save plot: {e}")
def load_initial_parameters(): # Checks if a saved model exists on the disk (Dynamic Path). If found, loads and returns it to continue training from previous state.
        if os.path.exists(MODEL_FILE):
            print(f"[Server]Found existing brain from '{MODEL_FILE}'Loading previous knowledge...")
            data = np.load(MODEL_FILE)
            # All the arrays are loaded into a list from the .npz file
            params_list = [data[key] for key in data.files]
            return fl.common.ndarrays_to_parameters(params_list)
        else:
            print("\n[Server] No existing brain found. Starting training from scratch.")
            return None
        
if __name__ == "__main__":
    print("[Server] Beginning Federated RL Server...")
    # UI menu
    main_menu()

    # Load previous model if exists
    print("[Server] Initializing Federated Environment...")
    initial_params = load_initial_parameters()

    # Define the custom strategy
    strategy = SaveModelStrategy(
        fraction_fit = 1.0, # All clients must participate in training
        fraction_evaluate = 1.0, # All clients must participate in evaluation
        min_fit_clients=2, # Wait for at least 2 clients to train
        min_evaluate_clients=2, # Wait for at least 2 clients to be online
        initial_parameters=initial_params # Load previous model if exists
    )

    ROUNDS = 50
    print(f"[Server] Configured for {ROUNDS} rounds. Waiting for agents...")

    # Server starts at port 8090
    fl.server.start_server(
        server_address="0.0.0.0:8090", 
        config=fl.server.ServerConfig(num_rounds=ROUNDS), # 50 Federation rounds
        strategy=strategy
    )
    # After training is complete, generate final plot
    generate_training_plot(strategy.reward_history)

    print("\n" + "="*40)
    print("[SERVER] Training completed after {} rounds.".format(ROUNDS))
    print("[SERVER] Federated RL Server has shut down.")
    print("[SERVER] The global model is distributed to all agents.")
    print(f"[SERVER] Global model saved at '{MODEL_FILE}'.")
    print("="*40)


