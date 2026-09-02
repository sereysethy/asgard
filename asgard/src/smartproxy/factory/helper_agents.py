def createAgent(name: str, numFeatures: int, numActions: int, config: dict):
    """
    factory to create an agent.

    Args:
        name (str): name of the learning agent
        numFeatures (int): number of features as input to the agent
        numActions (int): number of actions
        config (dict): dictionary containing hyper-parameters and other parameters
            that an agent needs
    Returns:
        agent (Class BaseLearner): the created agent.
    """

    if name == "QLearner":
        agent = createQLearner(numFeatures, numActions, config)
    elif name == "QLinearFALearner":
        agent = createQLinearFALearner(numFeatures, numActions, config)
    elif name == "DQNLearner":
        agent = createDQNlearner(numFeatures, numActions, config)
    elif name == "CleanDQNLearner":
        agent = createCleanDQNLearner(numFeatures, numActions, config)
    else:
        raise Exception("No agent found")

    return agent

def createQLearner(numFeatures:int, numActions:int, config: dict):
    """
    Create QLearner agent

    Args:
        numFeatures (int): number of features as input to the agent
        numActions (int): number of actions
        config (dict): dictionary containing hyper-parameters and other parameters
            that an agent needs
    Returns:
        agent (Class QLearner): the created agent.
    """
    from smartproxy.learning.rl.valuebase import QLearner
    agent = QLearner(numActions=numActions, numFeatures=numFeatures)
    agent.initEpsilon = config["init_epsilon"]
    agent.minEpsilon = config["min_epsilon"]
    agent.epsilonDecay = config["epsilon_decay"]

    agent.initLearningRate = config["init_lr_rate"]
    agent.minLearningRate = config["min_lr"]
    agent.learningRateDecay = config["learning_rate_decay"]

    agent.discount = config["discount"]

    return agent

def createQLinearFALearner(numFeatures: int, numActions: int, config: dict):
    """
    Create QLinearFALearner agent

    Args:
        numFeatures (int): number of features as input to the agent
        numActions (int): number of actions
        config (dict): dictionary containing hyper-parameters and other parameters
            that an agent needs
    Returns:
        agent (Class QLinearFALearner): the created agent.
    """
    from smartproxy.learning.rl.fa import QLinearFALearner
    initLearningRate = config["init_lr_rate"]
    # reproductibility random state
    agentRandomState = CowrieConfig.getint("rl", "agent_random_state", fallback=42)
    # verbosity level
    agentVerbosityLevel = CowrieConfig.getint("rl", "agent_verbosity_level", fallback=0)
    agent = QLinearFALearner(numFeatures=numFeatures,
                             numActions=numActions,
                             learningRate=initLearningRate,
                             randomState=agentRandomState,
                             verbose=agentVerbosityLevel)

    agent.initEpsilon = config["init_epsilon"]
    agent.minEpsilon = config["min_epsilon"]
    agent.epsilonDecay = config["epsilon_decay"]

    # these are not used since these parammeters are managed/stored
    # in the SGDRegressor of the learning model.
    agent.initLearningRate = config["init_lr_rate"]
    agent.minLearningRate = config["min_lr"]
    agent.learningRateDecay = config["learning_rate_decay"]

    agent.discount = config["discount"]

    return agent

def createDQNlearner(numFeatures:int, numActions:int, config: dict):
    """
    Create DQNLearner agent

    Args:
        numFeatures (int): number of features as input to the agent
        numActions (int): number of actions
        config (dict): dictionary containing hyper-parameters and other parameters
            that an agent needs
    Returns:
        agent (Class DQNLearner): the created agent.
    """

    from smartproxy.learning.rl.dqnlearner import DQNLearner
    cuda = config['cuda']
    model_dir = config["model_dir"]
    tensorboard_dir = config["tensorboard_dir"]
    debug = config['agent_debug']
    agent = DQNLearner(numFeatures=numFeatures,
                       numActions=numActions,
                       model_dir=model_dir,
                       tensorboard_dir=tensorboard_dir,
                       cuda=cuda,
                       debug=debug)

    # hyper-parameters
    agent.total_timesteps = config['total_timesteps']
    agent.learning_rate = config['learning_rate']
    agent.buffer_size = config['buffer_size']
    agent.gamma = config['gamma']
    agent.tau = config['tau']
    agent.target_network_frequency = config['target_network_frequency']
    agent.batch_size = config['batch_size']
    agent.start_e = config['init_epsilon']
    agent.end_e = config['min_epsilon']
    agent.epsilon_decay = config['epsilon_decay']
    agent.learning_starts = config['learning_starts']
    agent.train_frequency = config['train_frequency']

    agent.hidden_layer = config['hidden_layer']

    # backup and logging
    agent.save_every = config['save_every']
    agent.log_every = config['log_every']

    agent.createMemory()

    agent.createMetriclogger(tensorboard_dir)

    return agent

def createCleanDQNLearner(numFeatures:int, numActions:int, config: dict):
    """
    Create DQNLearner agent

    Args:
        numFeatures (int): number of features as input to the agent
        numActions (int): number of actions
        config (dict): dictionary containing hyper-parameters and other parameters
            that an agent needs
    Returns:
        agent (Class DQNLearner): the created agent.
    """

    from smartproxy.learning.rl.cleandqnlearner import CleanDQNLearner
    cuda = config['cuda']
    model_dir = config["model_dir"]
    tensorboard_dir = config["tensorboard_dir"]
    debug = config['agent_debug']
    agent = CleanDQNLearner(numFeatures=numFeatures,
                       numActions=numActions,
                       model_dir=model_dir,
                       tensorboard_dir=tensorboard_dir,
                       cuda=cuda,
                       debug=debug)

    # hyper-parameters
    agent.total_timesteps = config['total_timesteps']
    agent.learning_rate = config['learning_rate']
    agent.buffer_size = config['buffer_size']
    agent.gamma = config['gamma']
    agent.tau = config['tau']
    agent.target_network_frequency = config['target_network_frequency']
    agent.batch_size = config['batch_size']
    agent.start_e = config['init_epsilon']
    agent.end_e = config['min_epsilon']
    agent.epsilon_decay = config['epsilon_decay']
    agent.learning_starts = config['learning_starts']
    agent.train_frequency = config['train_frequency']

    agent.hidden_layer = config['hidden_layer']

    # backup and logging
    agent.save_every = config['save_every']
    agent.log_every = config['log_every']

    agent.createMemory()

    agent.createMetriclogger(tensorboard_dir)

    return agent