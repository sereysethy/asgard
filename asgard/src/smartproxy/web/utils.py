from typing import Dict

import json

from cowrie.core.config import CowrieConfig

from smartproxy.learning.rl.dqnlearner import DQNLearner
from smartproxy.learning.environment.roberta_web import RobertaEnvV10Web

def loadAgentConfig()->Dict:
    """
    Read the file containing the hyper-parameters for this agent
    """
    filename = CowrieConfig.get("rl", "config_agent_filename")
    with open(filename, "r") as infile:
        o = json.load(infile)
    return o

def loadEnvConfig()->Dict:
    """
    Read the file containing the hyper-parameters for this agent
    """
    filename = CowrieConfig.get("rl", "config_env_filename")
    with open(filename, "r") as infile:
        o = json.load(infile)
    return o

def createRobertaEnv()->RobertaEnvV10Web:
    """
    Called to create a roberta environment, it will also create an automated
    risk assessment model.

    Returns
    -------
        env (roberta.RobertaEnvV10Web):
    """

    config = loadEnvConfig()
    embedding_size = config["input_size"]
    action_size = config["output_size"]
    env = RobertaEnvV10Web(embedding_size, action_size, config)

    return env

def createDQNlearner(numFeatures: int, numActions: int, config: Dict)->DQNLearner:
    """
    Create DQNLearner agent

    Params
    ------
        numFeatures (int): number of features as input to the agent
        numActions (int): number of actions
        config (dict): dictionary containing hyper-parameters and other parameters
            that an agent needs
    Returns
    -------
        agent (Class DQNLearner): the created agent.
    """

    cuda = config['cuda']
    agent = DQNLearner(numFeatures=numFeatures,
                       numActions=numActions,
                       cuda=cuda)

    agent.total_timesteps = config['total_timesteps']
    agent.learning_rate = config['learning_rate']
    agent.buffer_size = config['buffer_size']
    agent.gamma = config['gamma']
    agent.tau = config['tau']
    agent.target_network_frequency = config['target_network_frequency']
    agent.batch_size = config['batch_size']
    agent.start_e = config['init_epsilon']
    agent.end_e = config['min_epsilon']
    agent.exploration_fraction = config['exploration_fraction']
    agent.learning_starts = config['learning_starts']
    agent.train_frequency = config['train_frequency']

    agent.createMemory()

    return agent