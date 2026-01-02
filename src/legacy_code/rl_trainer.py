import gymnasium as gym
from gymnasium import spaces
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env 

# --- STEP 1: Vectorization ---
vectorizer = TfidfVectorizer(max_features=100)
# Teaching some basic keywords
vectorizer.fit(["/wp-admin.php", "/vulnerabilities/sqli", "/healthz", "SELECT", "FROM", "script"])

# --- Simulating our logs---
FAKE_LOG_DB = [
    # "Innocent" logs (Has to ignore them!! - Action 0)
    {'uri': '/', 'ip': '1.1.1.1', 'source': 'WAF', 'messages': []},
    {'uri': '/healthz', 'ip': '1.1.1.2', 'source': 'WAF', 'messages': []},
    # "Known threats" Logs (Has to block them!! - Action 1 ή 2)
    {'uri': '/vulnerabilities/sqli?id=1', 'ip': '2.2.2.2', 'source': 'WAF', 'messages': ['SQL Injection Attack']},
    # "Zero-Day threats" Logs (Has to block them!! - Action 1 ή 2)
    {'uri': '/wp-admin.php', 'ip': '3.3.3.3', 'source': 'HONEYPOT', 'messages': []},
    {'uri': '/shell.php', 'ip': '4.4.4.4', 'source': 'HONEYPOT', 'messages': []}
]

# --- STEP 2: Gym Environment ---
class WafEnv(gym.Env):
    def __init__(self):
        super(WafEnv, self).__init__()
        
        self.action_space = spaces.Discrete(3) # 0:Ignore, 1:Block URI, 2:Block IP
        # 2. What it "sees" (Observation/State);
    # It sees a "vector" of 9 numbers (vectorizer found 9 features)
        self.observation_space = spaces.Box(low=0, high=1, shape=(9,), dtype=np.float32)
        
        self.blocked_uris = set()
        self.blocked_ips = set()
        
        # Agent lives for 1000 "steps" (logs)
        self.max_steps = 1000
        self.current_step = 0

    def _get_observation(self, log_data):
        uri = log_data['uri']
        vector = vectorizer.transform([uri]).toarray().flatten()
        return vector

    def _get_reward(self, log_data, action):
        uri = log_data['uri']
        source = log_data['source']

        # 1. PUNISHMENT FOR FALSE POSITIVES
        if uri == "/healthz" and (action == 1 or action == 2):
            return -100 # Μεγάλη τιμωρία

        # 2. REWARD FOR THREAT DETECTION (Honeypot = 100% THREAT)
        if source == 'HONEYPOT':
            if action == 1 or action == 2: # Block URI or IP
                return 100 # BIG REWARD
            if action == 0: # DO NOTHING
                return -50 # PUNISHMENT

        # 3. REWARD FOR KNOWN THREATS (WAF)
        if source == 'WAF' and log_data['messages']:
            if action == 1 or action == 2: # Block URI or IP
                return 10
            if action == 0:
                return 0 

        # 4. INNOCENT TRAFFIC IGNORED (Best senario)
        if source == 'WAF' and not log_data['messages'] and action == 0:
             return 5 # Small reward for ignoring innocent traffic

        return -1 # Small punishment for wrong decisions

    def step(self, action):
        # 1. Random database log
        log_data = FAKE_LOG_DB[np.random.randint(len(FAKE_LOG_DB))]
        
        # 2. Receives the reward for the action the ai model chose
        reward = self._get_reward(log_data, action)
        
        # 3. Doing the action
        if action == 1:
            self.blocked_uris.add(log_data['uri'])
        elif action == 2:
            self.blocked_ips.add(log_data['ip'])

        # 4. Geeting next observation
        observation = self._get_observation(log_data)
        
        self.current_step += 1
        
        # 5. Checks if game is over
        done = (self.current_step >= self.max_steps)
        return observation, reward, done, False, {}

    def reset(self, seed=None):
        # Start over
        self.current_step = 0
        self.blocked_uris = set()
        self.blocked_ips = set()
        # Returns a random log
        log_data = FAKE_LOG_DB[np.random.randint(len(FAKE_LOG_DB))]
        return self._get_observation(log_data), {}

# --- STEP 3: AGENT TRAINING---
if __name__ == "__main__":
    # Graph folder
    TENSORBOARD_LOG_DIR = "./waf_tensorboard_logs/"
    env = WafEnv()
    
    # 2.Loading AI algorithm (PPO)
    print("="*30)
    print("BEGIN TRAINING (with logging in TensorBoard)...")
    print("="*30)
    
    model = PPO("MlpPolicy", env, verbose=1, tensorboard_log=TENSORBOARD_LOG_DIR)
    
    # 3. TRAINING (For example, for 10,000 "steps")
    model.learn(total_timesteps=10000, tb_log_name="PPO_Agent_v1")
    
    print("="*30)
    print("TARINING IS OVER!")
    print("="*30)
    
    # 4. Saving the "Brain"
    model.save("waf_rl_agent")
    
    print("Trained model was saved as 'waf_rl_agent.zip'")
    # 5. Trial!!
    print("\n--- Trial of trained agent ---")
    obs, _ = env.reset()
    for _ in range(10): # Try 30 times
        # Now the action is well thought of
        action, _states = model.predict(obs, deterministic=True)
        
        # Decision
        if action == 1:
            print("  [AI] ΑΠΟΦΑΣΗ: Μπλοκάρισμα URI")
        elif action == 2:
            print("  [AI] ΑΠΟΦΑΣΗ: Μπλοκάρισμα IP")
        else:
            print("  [AI] ΑΠΟΦΑΣΗ: Αγνοήθηκε.")
            
        obs, reward, done, _, _ = env.step(action)
        print(f"  [AI] Ανταμοιβή: {reward}\n")
