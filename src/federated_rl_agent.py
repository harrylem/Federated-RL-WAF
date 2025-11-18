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

# --- ΒΗΜΑ 1: GLOBAL SETUP ---
WAF_CONTAINER_NAME = "waf_instance1"
HONEYPOT_CONTAINER_NAME = "waf_honeypot"

# "Χέρια": Σύνδεση με το Docker για να γράφουμε κανόνες
client = docker.from_env()
try:
    waf_container = client.containers.get(WAF_CONTAINER_NAME)
except docker.errors.NotFound:
    print(f"FATAL ERROR: Δεν βρέθηκε το container '{WAF_CONTAINER_NAME}'!")
    sys.exit(1)

# "Μεταφραστής": Ο ίδιος Vectorizer
vectorizer = TfidfVectorizer(max_features=9) 
vectorizer.fit(["/wp-admin.php", "/vulnerabilities/sqli", "/healthz", "SELECT", "FROM", "script"])

# "Δεδομένα": Οι δύο "λίμνες"
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

# --- ΒΗΜΑ 2: ΤΟ "ΠΕΡΙΒΑΛΛΟΝ" (Gym Env) ---
# (Ακριβώς το ίδιο WafEnv που φτιάξαμε, δεν αλλάζει τίποτα)
class WafEnv(gym.Env):
    def __init__(self, db_source): 
        super(WafEnv, self).__init__()
        self.action_space = spaces.Discrete(3)
        self.observation_space = spaces.Box(low=0, high=1, shape=(9,), dtype=np.float32)
        self.FAKE_LOG_DB = db_source
        self.max_steps = 1000
        self.current_step = 0

    def _get_observation(self, log_data):

    # --- ΑΥΤΗ ΕΙΝΑΙ Η ΔΙΟΡΘΩΣΗ ---
    # Ελέγχει αν το log είναι "αληθινό" (nested) ή "ψεύτικο" (flat)

        if 'transaction' in log_data:
        # Είναι "ΑΛΗΘΙΝΟ" log από το Live Mode
            uri = log_data['transaction']['request']['uri']
        else:
        # Είναι "ΨΕΥΤΙΚΟ" log από το FAKE_LOG_DB (Εκπαίδευση)
            uri = log_data.get('uri', '/') # Χρησιμοποίησε .get() για ασφάλεια

    # -----------------------------

        vector = vectorizer.transform([uri]).toarray().flatten()
        return vector

    def _get_reward(self, log_data, action):
        uri = log_data.get('uri', '/') # Ασφάλεια
        source = log_data.get('source', 'WAF') # Ασφάλεια

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

# --- ΒΗΜΑ 3: Ο "LIVE" AGENT (Τα "Χέρια" και τα "Μάτια") ---
# (Αυτές είναι οι λειτουργίες από το 'rl_agent.py')

blocked_uris = set()
blocked_ips = set()
rule_id_counter = 9000001 # Ξεκινάμε από ψηλά για να μην έχουμε conflicts

def apply_rule_to_waf(action, log_data):
    """
    Αυτή η συνάρτηση γράφει τον κανόνα στον 'waf_instance1'
    """
    global rule_id_counter
    uri_to_block = log_data['transaction']['request']['uri']
    ip_to_block = log_data['transaction']['client_ip']
    rule_string = ""

    if action == 1 and uri_to_block not in blocked_uris:
        print(f"  [LIVE ACTION] ΑΠΟΦΑΣΗ: Μπλοκάρισμα URI: {uri_to_block}")
        rule_string = f'SecRule REQUEST_URI "@streq {uri_to_block}" "id:{rule_id_counter},phase:1,deny,status:403,msg:\'Blocked by Federated RL Agent (URI)\'"'
        blocked_uris.add(uri_to_block)
            
    elif action == 2 and ip_to_block not in blocked_ips:
        print(f"  [LIVE ACTION] ΑΠΟΦΑΣΗ: Μπλοκάρισμα IP: {ip_to_block}")
        rule_string = f'SecRule REMOTE_ADDR "@streq {ip_to_block}" "id:{rule_id_counter},phase:1,deny,status:403,msg:\'Blocked by Federated RL Agent (IP)\'"'
        blocked_ips.add(ip_to_block)
    
    else: # Action == 0 (Do Nothing)
        print(f"  [LIVE ACTION] ΑΠΟΦΑΣΗ: Αγνοήθηκε.")
        return 

    try:
        cmd_write = f"sh -c \"echo '{rule_string}' >> /etc/nginx/dynamic_rules.conf\""
        waf_container.exec_run(cmd_write)
        waf_container.exec_run("nginx -s reload")
        print(f"  [SUCCESS] Ο ΚΑΝΟΝΑΣ {rule_id_counter} ΕΦΑΡΜΟΣΤΗΚΕ ΣΤΟ WAF!")
        rule_id_counter += 1
    except Exception as e:
        print(f"  [ERROR] Απέτυχα να εφαρμόσω τον κανόνα: {e}")

def live_log_parser(container_name, model):
    """
    Αυτό είναι το "ζωντανό αυτί" που ακούει τα logs
    και χρησιμοποιεί το "Super-Μυαλό" (model) για να πάρει αποφάσεις.
    """
    print(f"[Live Listener] ΣΥΝΔΕΣΗ (Live) στον: {container_name}")
    try:
        container = client.containers.get(container_name)
        for line in container.logs(stream=True, follow=True, since=int(time.time())):
            log_entry = line.decode('utf-8').strip()
            
            if log_entry.startswith('{"transaction":'):
                try:
                    json_data = json.loads(log_entry)
                    json_data['source'] = 'WAF' if container_name == WAF_CONTAINER_NAME else 'HONEYPOT'
                    print("\n" + "="*20 + f" LIVE LOG ΑΠΟ [{container_name}] " + "="*20)
                    
                    # --- Η "Στιγμή της Αλήθειας" ---
                    # 1. "Μετάφρασε" το log σε "εικόνα"
                    observation = WafEnv(db_source=[])._get_observation(json_data) # (Hack: φτιάχνουμε ένα ψεύτικο env για να πάρουμε τη συνάρτηση)
                    
                    # 2. "Ρώτα" το "Super-Μυαλό" τι να κάνει
                    action, _states = model.predict(observation, deterministic=True)
                    
                    # 3. "Δράσε" (Γράψε τον κανόνα!)
                    apply_rule_to_waf(action, json_data)
                    
                except json.JSONDecodeError:
                    pass
    except docker.errors.NotFound:
        print(f"[ERROR] Το 'live' container '{container_name}' δεν βρέθηκε!")

# --- ΒΗΜΑ 4: Ο FLOWER CLIENT (που συνδυάζει τα πάντα) ---
class FlowerRLClient(fl.client.NumPyClient):
    def __init__(self, client_id):
        self.client_id = client_id
        if self.client_id == "1":
            print("[Client 1] Εγώ είμαι ο WAF AGENT (Προσεκτικός). Φορτώνω WAF logs.")
            db = FAKE_LOG_DB_WAF
        else:
            print("[Client 2] Εγώ είμαι ο HONEYPOT AGENT (Επιθετικός). Φορτώνω Honeypot logs.")
            db = FAKE_LOG_DB_HONEYPOT
            
        self.env = WafEnv(db_source=db)
        self.model = PPO("MlpPolicy", self.env, verbose=0) # Κάθε client έχει το δικό του PPO model

    def get_parameters(self, config):
        print(f"[Client {self.client_id}] Στέλνω το 'μυαλό' μου...")
        return [param.detach().cpu().numpy() for param in self.model.policy.parameters()]

    def set_parameters(self, parameters):
        print(f"[Client {self.client_id}] Πήρα νέο 'Super-μυαλό'!")
        params_dict = zip(self.model.policy.state_dict().keys(), parameters)
        state_dict = {k: torch.tensor(v) for k, v in params_dict}
        self.model.policy.load_state_dict(state_dict, strict=True)

    def fit(self, parameters, config):
        print(f"[Client {self.client_id}] Ξεκινάω τοπική εκπαίδευση (fit)...")
        self.set_parameters(parameters)
        self.model.learn(total_timesteps=1000) # Γρήγορη εκπαίδευση
        print(f"[Client {self.client_id}] Η εκπαίδευση τελείωσε.")
        return self.get_parameters(config={}), self.env.max_steps, {}

    def evaluate(self, parameters, config):
        return 0.0, 1, {}

# --- ΒΗΜΑ 5: ΤΟ ΤΕΛΙΚΟ ΠΡΟΓΡΑΜΜΑ ---
if __name__ == "__main__":
    
    # 1. Πάρε το ID (1 ή 2) από την εντολή
    client_id = sys.argv[1] if len(sys.argv) > 1 else "1"
    
    # 2. Φτιάξε τον Client
    client_object = FlowerRLClient(client_id=client_id)
    
    # --- ΦΑΣΗ 1: ΟΜΟΣΠΟΝΔΙΑ (ΕΚΠΑΙΔΕΥΣΗ) ---
    print(f"--- [CLIENT {client_id}] ΦΑΣΗ 1: Σύνδεση στον Server για Ομοσπονδία ---")
    
    fl.client.start_numpy_client(
        server_address="127.0.0.1:8090", 
        client=client_object
    )
    
    # --- ΦΑΣΗ 2: "ΚΛΕΙΣΤΟΣ ΒΡΟΧΟΣ" (LIVE MODE) ---
    # (Αυτό θα τρέξει ΜΟΝΟ ΑΦΟΥ ο server κλείσει την 'Ομοσπονδία')
    
    print("\n" + "="*50)
    print(f"--- [CLIENT {client_id}] ΦΑΣΗ 2: Η Ομοσπονδία τελείωσε! ---")
    print(f"--- ΞΕΚΙΝΑΩ 'ΚΛΕΙΣΤΟ ΒΡΟΧΟ' (LIVE MODE) ---")
    print(f"--- Χρησιμοποιώ το τελικό 'Super-Μυαλό' ---")
    print("="*50 + "\n")
    
    # Πάρε το "Super-Μυαλό" που έμεινε από την εκπαίδευση
    final_model = client_object.model 
    
    # Διάλεξε ποιο log θα ακούει ο καθένας
    if client_id == "1":
        # Ο Agent 1 ακούει τον "πραγματικό" WAF
        target_container = WAF_CONTAINER_NAME
    else:
        # Ο Agent 2 ακούει την "παγίδα"
        target_container = HONEYPOT_CONTAINER_NAME

    # Ξεκίνα τον "Live" listener και κράτα το script ζωντανό
    try:
        live_log_parser(target_container, final_model)
    except KeyboardInterrupt:
        print(f"\n[Client {client_id}] Σταματάω... Αυτοί είναι οι κανόνες που έμαθα:")
        print(f"Blocked URIs: {blocked_uris}")
        print(f"Blocked IPs: {blocked_ips}")