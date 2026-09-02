from smartproxy.learning.model import LinearApproximator
import torch
import torch.nn as nn

model = LinearApproximator(input_dim, output_dim)
learning_rate = 0.01
criterion = nn.MSELoss()
optimizer = torch.optim.SGD(model.parameters(), lr=learning_rate)

# sample action
action = model.getAction()

# get a reward r
obs, reward, done, info = env.step(action)

# calculate td_error
q_hat = model(obs_action)
loss = criterion(reward, q_hat)

# calculate gradient
loss.backward()

# update parameter
optimizer.step()
