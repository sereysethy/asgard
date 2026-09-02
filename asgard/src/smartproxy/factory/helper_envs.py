import json

from cowrie.core.config import CowrieConfig

from smartproxy.learning.environment import env

def createEnv(name: str)->env.BaseEnv:
    """
    This will create an environment as specified in the configuration file.

    Args:
        name (str): name of the environment to create

    Returns:
        A new environment as specified in the configuration file under
            rl - environment.
    """

    env = None
    if name == "SimpleAttackerEnvV12":
        from smartproxy.learning.environment import simple
        env = simple.SimpleAtackerEnvV12()
    elif name == "MidgardEnv":
        from smartproxy.learning.environment import midgard
        env = midgard.MidgardEnv()
    elif name == "OneHotVectorEnvCase23":
        from smartproxy.learning.environment import onehotvector
        env = onehotvector.OneHotVectorEnvCase23()
    elif name == "RobertaEnvV10":
        env = createRobertaEnv()
    elif name == "RobertaEnvWebV10":
        env = createRobertaWebEnv()
    else:
        raise Exception("No environment found")

    return env

def loadEnvConfig()->dict:
    """
    Read the file containing the hyper-parameters for this agent

    Returns:
        dictionary containing environment parameters.
    """

    filename = CowrieConfig.get("rl", "config_env_filename")
    with open(filename, "r") as infile:
        o = json.load(infile)
    return o

def createRobertaEnv():
    """
    Called to create a roberta environment, it will also create an automated
    risk assessment model.

    Returns:
        env (roberta.RobertaEnvV10):
    """

    from smartproxy.learning.environment import roberta
    config = loadEnvConfig()
    embedding_size = config["input_size"]
    action_size = config["output_size"]
    env = roberta.RobertaEnvV10(embedding_size, action_size, config)

    return env

def createRobertaWebEnv():
    """
    Called to create a roberta environment, it will also create an automated
    risk assessment model.

    Returns:
        env (roberta.RobertaEnvV10):
    """

    from smartproxy.learning.environment import roberta_web
    config = loadEnvConfig()
    embedding_size = config["input_size"]
    action_size = config["output_size"]
    env = roberta_web.RobertaEnvWebV10(embedding_size, action_size, config)

    return env
