import logging

from typing import Union

from fastapi import FastAPI

from cowrie.core.config import CowrieConfig

# BEGIN: SMP
from datetime import datetime
# from smartproxy.utils import utils

from smartproxy.learning.rl.dqnlearner import DQNLearner

from .cmd import Payload
from . import utils

env = utils.createRobertaEnv()

# check if cuda is enabled
config = utils.loadAgentConfig()
config['cuda'] = CowrieConfig.getboolean("rl", "cuda", fallback=False)

agentName = CowrieConfig.get("rl", "agent")
# log.msg("Load agent name: {}".format(self.agentName))

numActions = env.action_space.n

# check if there is a shape then it is a box
if env.observation_space.shape:
    numFeatures, _ = env.observation_space.shape
else:
    # otherwise it is a discrete
    numFeatures = env.observation_space.n

agent: DQNLearner = utils.createDQNlearner(numFeatures, numActions, config)
app = FastAPI()

@app.put("/get_action")
def get_action(payload: Payload):
    raw_cmd = payload.raw_cmd
    basename = payload.basename
    exec_cmd = payload.exec_cmd
    cmd_exec_state = payload.cmd_exec_state

    # transform cmd to obs
    obs = env.makeObs(raw_cmd, basename, exec_cmd, cmd_exec_state)

    exploration = cmd.exploration
    mask = cmd.mask
    action = agent.getAction(obs, exploration, mask)

    # call agent to get action
    return {"action": action.item()}

@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.put("/take_action")
def take_action():
    # status of the follower after taking the action
    # action = body.action
    # follower_status = body.status
    # follower_distance = body.distance
    # follower_avg_distance = body.avg_distance

    # prepare the observation
    # obs = np.array([follower_distance, follower_avg_distance])
    # asgard is taking a step which will eventually trigger training
    # status = asgard.take_action(action, obs, follower_status)

    # TODO: based on the status, we can know what Asgard is doing
    return {}