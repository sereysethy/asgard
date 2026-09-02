# ML library
import torch
from torch import Tensor
import torch.nn as nn
import torch.nn.functional as F

class DQN(torch.nn.Module):
    """
    Neural network class used in in the DQN algorithm implementation 
    is taken from `PyTorch tutorial 
    <https://pytorch.org/tutorials/intermediate/reinforcement_q_learning.html>`_.

    Args:
        n_observations : The number of feature contained in the state observation
        n_actions : The number of possible actions.
        n_hidden_layer : The number of neurons of the hidden layer.
    """

    def __init__(self, n_observations:int, n_actions:int, n_hidden_layer:int):
        super().__init__() # type: ignore
        self.layer1 = nn.Linear(n_observations, n_hidden_layer)
        self.layer2 = nn.Linear(n_hidden_layer, n_hidden_layer)
        self.layer3 = nn.Linear(n_hidden_layer, n_actions)

    def forward(self, x:Tensor):
        """
        Perform a forward pass through the network. The output functions are
        :math:`relu`.
        
        Args:
            x (Tensor): Input value to the network
            
        Returns:
            Output values (:math:`Q`-values) of the network corresponding to 
            the number of actions
        """

        x = F.relu(self.layer1(x))
        x = F.relu(self.layer2(x))
        return self.layer3(x)

class QNetwork(nn.Module):
    """
    Another neural network class used in in the DQN algorithm implementation 
    is taken from 
    `CleanRL <https://github.com/vwxyzjn/cleanrl/blob/master/cleanrl/dqn.py>`_.

    Args:
        n_observations : The number of feature contained in the state observation
        n_actions : The number of possible actions.
        n_hidden_layer : The number of neurons of the hidden layer.
    """
    def __init__(self, n_observations:int, n_actions:int, n_hidden_layer):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(n_observations, n_hidden_layer),
            nn.ReLU(),
            nn.Linear(n_hidden_layer, n_hidden_layer),
            nn.ReLU(),
            nn.Linear(n_hidden_layer, n_actions),
        )

    def forward(self, x):
        """
        Perform a forward pass through the network.
        
        Args:
            x (Tensor): Input value to the network
            
        Returns:
            Output values (:math:`Q`-values) of the network corresponding to 
            the number of actions
        """
        return self.network(x)
