import flwr as fl 
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import log_loss

# --- 1. THE DATA ---
LOGS_SQLI = [
    {'uri': '/vulnerabilities/sqli?id=1', 'label': 1}, # 1 = Attack
    {'uri': '/product?id=1 OR 1=1', 'label': 1},
    {'uri': '/login?user=\' OR \'1\'=\'1', 'label': 1},
]
LOGS_XSS = [
    {'uri': '/search?q=<script>alert(1)</script>', 'label': 1},
    {'uri': '/comment?msg=<img src=x onerror=alert(1)>', 'label': 1},
    {'uri': '/profile?name=<svg/onload=alert(1)>', 'label': 1},
]
LOGS_BENIGN = [
    {'uri': '/', 'label': 0}, # 0 = Benign
    {'uri': '/healthz', 'label': 0},
    {'uri': '/about', 'label': 0},
    {'uri': '/contact', 'label': 0},
]

# Vectorizer 
vectorizer = TfidfVectorizer(max_features=9)
all_uris = [l['uri'] for l in LOGS_SQLI + LOGS_XSS + LOGS_BENIGN]
vectorizer.fit(all_uris)

def get_data(client_id):
    """It returns X (features) and y (labels) depending on the client"""
    cid = int(client_id)
    if cid < 5:
        # SQLi Expert
        local_logs = LOGS_SQLI * 4 + LOGS_XSS * 1 + LOGS_BENIGN * 5
    else:
        # XSS Expert
        local_logs = LOGS_XSS * 4 + LOGS_SQLI * 1 + LOGS_BENIGN * 5
    
    # Converion to vectors
    X = vectorizer.transform([l['uri'] for l in local_logs]).toarray()
    y = np.array([l['label'] for l in local_logs])
    return X, y

# --- 2. THE FLOWER CLIENT ---
class BaselineClient(fl.client.NumPyClient):
    def __init__(self, client_id):
        self.X, self.y = get_data(client_id)
        # We use simple Logistic Regression
        self.model = LogisticRegression(warm_start=True, max_iter=1)

    def get_parameters(self, config):
        # We return the weights of Logistic Regression
        # (coef_ και intercept_)
        if hasattr(self.model, "coef_"):
            return [self.model.coef_, self.model.intercept_]
        else:
            # Initialization in case , no training has taken place
            return [np.zeros((1, 9)), np.zeros((1,))]

    def set_parameters(self, parameters):
        self.model.coef_ = parameters[0]
        self.model.intercept_ = parameters[1]
        self.model.classes_ = np.array([0, 1])

    def fit(self, parameters, config):
        self.set_parameters(parameters)
        # Training
        self.model.fit(self.X, self.y)
        return self.get_parameters(config={}), len(self.X), {}

    def evaluate(self, parameters, config):
        self.set_parameters(parameters)
        # Calculation of Accuracy
        loss = log_loss(self.y, self.model.predict_proba(self.X))
        accuracy = self.model.score(self.X, self.y)
        return float(loss), len(self.X), {"accuracy": float(accuracy)}

def client_fn(cid: str):
    return BaselineClient(cid).to_client()

# --- 3.BASELINE SIMULATION ---
if __name__ == "__main__":
    print(" Beginning BASELINE Simulation (Logistic Regression)...")
    
    # Evaluation strategy
    strategy = fl.server.strategy.FedAvg(
        fraction_fit=0.5,
        fraction_evaluate=0.5,
        min_fit_clients=5,
        min_available_clients=10,
    )

    fl.simulation.start_simulation(
        client_fn=client_fn,
        num_clients=10,
        config=fl.server.ServerConfig(num_rounds=5),
        strategy=strategy,
        client_resources={"num_cpus": 1}
    )