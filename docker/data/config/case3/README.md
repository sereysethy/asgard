# BATCH_SIZE is the number of transitions sampled from the replay buffer
# GAMMA is the discount factor as mentioned in the previous section
# EPS_START is the starting value of epsilon
# EPS_END is the final value of epsilon
# EPS_DECAY controls the rate of exponential decay of epsilon, higher means a slower decay
# TAU is the update rate of the target network
# LR is the learning rate of the ``AdamW`` optimizer
total_timesteps: int = 10000
learning_rate: float = 1e-4
buffer_size: int = 10000
gamma: float = 0.99
tau: float = 0.0004 # 1 if train_frequency is large like 10 ?
target_network_frequency: int = 100
batch_size: int = 128
start_e: float = 0.9
end_e: float = 0.05
exploration_fraction: float = 0.4
learning_starts: int = 200
train_frequency: int = 10