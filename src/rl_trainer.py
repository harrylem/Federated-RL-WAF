import gymnasium as gym
from gymnasium import spaces
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env # Τώρα θα το χρειαστούμε!

# --- ΒΗΜΑ 1: Ο "ΜΕΤΑΦΡΑΣΤΗΣ" (Vectorization) ---
vectorizer = TfidfVectorizer(max_features=100)
# Του "διδάσκουμε" κάποιες βασικές λέξεις-κλειδιά
vectorizer.fit(["/wp-admin.php", "/vulnerabilities/sqli", "/healthz", "SELECT", "FROM", "script"])

# --- Προσομοίωση των "Logs" μας ---
FAKE_LOG_DB = [
    # "Αθώα" Logs (Πρέπει να τα αγνοήσει - Action 0)
    {'uri': '/', 'ip': '1.1.1.1', 'source': 'WAF', 'messages': []},
    {'uri': '/healthz', 'ip': '1.1.1.2', 'source': 'WAF', 'messages': []},
    # "Γνωστή Απειλή" Logs (Πρέπει να τα μπλοκάρει - Action 1 ή 2)
    {'uri': '/vulnerabilities/sqli?id=1', 'ip': '2.2.2.2', 'source': 'WAF', 'messages': ['SQL Injection Attack']},
    # "Zero-Day Απειλή" Logs (Πρέπει να τα μπλοκάρει - Action 1 ή 2)
    {'uri': '/wp-admin.php', 'ip': '3.3.3.3', 'source': 'HONEYPOT', 'messages': []},
    {'uri': '/shell.php', 'ip': '4.4.4.4', 'source': 'HONEYPOT', 'messages': []}
]

# --- ΒΗΜΑ 2: ΤΟ "ΠΕΡΙΒΑΛΛΟΝ" (Gym Environment) ---
class WafEnv(gym.Env):
    def __init__(self):
        super(WafEnv, self).__init__()
        
        self.action_space = spaces.Discrete(3) # 0:Ignore, 1:Block URI, 2:Block IP
        # 2. Τι "Βλέπει" (Observation/State);
    # Βλέπει ένα "vector" 9 αριθμών (αφού ο vectorizer βρήκε 9 features)
        self.observation_space = spaces.Box(low=0, high=1, shape=(9,), dtype=np.float32)
        
        self.blocked_uris = set()
        self.blocked_ips = set()
        
        # Ο Agent θα ζήσει για 1000 "βήματα" (logs)
        self.max_steps = 1000
        self.current_step = 0

    def _get_observation(self, log_data):
        uri = log_data['uri']
        vector = vectorizer.transform([uri]).toarray().flatten()
        return vector

    def _get_reward(self, log_data, action):
        uri = log_data['uri']
        source = log_data['source']

        # 1. ΤΙΜΩΡΙΑ ΓΙΑ FALSE POSITIVES
        if uri == "/healthz" and (action == 1 or action == 2):
            return -100 # Μεγάλη τιμωρία

        # 2. ΑΝΤΑΜΟΙΒΗ ΓΙΑ ΑΠΕΙΛΕΣ (Honeypot = 100% απειλή)
        if source == 'HONEYPOT':
            if action == 1 or action == 2: # Block URI or IP
                return 100 # Μεγάλη ανταμοιβή
            if action == 0: # Do Nothing
                return -50 # Τιμωρία

        # 3. ΑΝΤΑΜΟΙΒΗ ΓΙΑ ΓΝΩΣΤΕΣ ΑΠΕΙΛΕΣ (WAF)
        if source == 'WAF' and log_data['messages']:
            if action == 1 or action == 2: # Block URI or IP
                return 10
            if action == 0:
                return 0 

        # 4. ΑΘΩΑ ΚΙΝΗΣΗ ΠΟΥ ΑΓΝΟΗΘΗΚΕ (Το καλύτερο σενάριο)
        if source == 'WAF' and not log_data['messages'] and action == 0:
             return 5 # Μικρή ανταμοιβή που αγνόησε αθώα κίνηση

        return -1 # Μικρή τιμωρία για άλλες λάθος αποφάσεις

    def step(self, action):
        # 1. Τυχαίο log από τη "Βάση"
        log_data = FAKE_LOG_DB[np.random.randint(len(FAKE_LOG_DB))]
        
        # 2. Παίρνει την ανταμοιβή (Reward) για τη δράση (action) που επέλεξε η AI
        reward = self._get_reward(log_data, action)
        
        # 3. Εφαρμόζει τη δράση 
        if action == 1:
            self.blocked_uris.add(log_data['uri'])
        elif action == 2:
            self.blocked_ips.add(log_data['ip'])

        # 4. Παίρνει την επόμενη παρατήρηση 
        observation = self._get_observation(log_data)
        
        self.current_step += 1
        
        # 5. Ελέγχει αν το παιχνίδι τελείωσε
        done = (self.current_step >= self.max_steps)
        
        # Το step πρέπει να επιστρέφει αυτά τα παρακάτω 
        return observation, reward, done, False, {}

    def reset(self, seed=None):
        # Ξεκινά από την αρχή
        self.current_step = 0
        self.blocked_uris = set()
        self.blocked_ips = set()
        # Επιστρέφει την "πρώτη εικόνα" (ένα τυχαίο log)
        log_data = FAKE_LOG_DB[np.random.randint(len(FAKE_LOG_DB))]
        return self._get_observation(log_data), {}

# --- ΒΗΜΑ 3: ΕΚΠΑΙΔΕΥΣΗ ΤΟΥ AGENT ---
if __name__ == "__main__":
    # Ο φάκελος όπου θα σωθούν τα γραφήματα
    TENSORBOARD_LOG_DIR = "./waf_tensorboard_logs/"
    env = WafEnv()
    
    # 2. Φορτώνω τον Αλγόριθμο AI (PPO)
    print("="*30)
    print("ΞΕΚΙΝΑΩ ΕΚΠΑΙΔΕΥΣΗ (με logging στο TensorBoard)...")
    print("="*30)
    
    model = PPO("MlpPolicy", env, verbose=1, tensorboard_log=TENSORBOARD_LOG_DIR)
    
    # 3. ΕΚΠΑΙΔΕΥΣΗ (π.χ., για 10,000 "βήματα")
    model.learn(total_timesteps=10000, tb_log_name="PPO_Agent_v1")
    
    print("="*30)
    print("Η ΕΚΠΑΙΔΕΥΣΗ ΤΕΛΕΙΩΣΕ!")
    print("="*30)
    
    # 4. Αποθήκευση του "Μυαλού"
    model.save("waf_rl_agent")
    
    print("Το εκπαιδευμένο μοντέλο αποθηκεύτηκε ως 'waf_rl_agent.zip'")
    # 5. Δοκιμή!!!
    print("\n--- Δοκιμή του εκπαιδευμένου Agent ---")
    obs, _ = env.reset()
    for _ in range(10): # Δοκίμασέ τον 10 φορές
        # Τώρα η απόφαση (action) ΔΕΝ είναι τυχαία!
        action, _states = model.predict(obs, deterministic=True)
        
        # Απόφαση
        if action == 1:
            print("  [AI] ΑΠΟΦΑΣΗ: Μπλοκάρισμα URI")
        elif action == 2:
            print("  [AI] ΑΠΟΦΑΣΗ: Μπλοκάρισμα IP")
        else:
            print("  [AI] ΑΠΟΦΑΣΗ: Αγνοήθηκε.")
            
        obs, reward, done, _, _ = env.step(action)
        print(f"  [AI] Ανταμοιβή: {reward}\n")
