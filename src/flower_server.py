import flwr as fl

if __name__ == "__main__":
    print("[Server] Beginning Federated RL Server (v1.7)...")
    
   
    strategy = fl.server.strategy.FedAvg(
        min_fit_clients=2,
        min_available_clients=2
    )
    
    # Server starts at port 8090
    fl.server.start_server(
        server_address="0.0.0.0:8090", 
        config=fl.server.ServerConfig(num_rounds=3), # 3 Federation rounds"
        strategy=strategy
    )
