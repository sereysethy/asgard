import argparse

import os
import json

from twisted.python.logfile import DailyLogFile
from twisted.logger import Logger
from twisted.logger import textFileLogObserver
from twisted.logger import globalLogPublisher
from twisted.python import log

from cowrie.core.config import CowrieConfig

from smartproxy.ssh.factory import SSHClientFactory
from smartproxy.command.shell import Shell

from smartproxy.learning import env

from ray.rllib.env.policy_client import PolicyClient

logfile = DailyLogFile("simulated_test.log", "var/log/cowrie")
globalLogPublisher.addObserver(textFileLogObserver(logfile))

parser = argparse.ArgumentParser()
parser.add_argument("--inference-mode", type=str, required=False, default="local")

args = parser.parse_args()

honeypot_sessions = []

policyClient = PolicyClient(address="http://localhost:9900", inference_mode=args.inference_mode)

env = env.SimulatedBotEnv1(action_size=2, observation_size=1)

command_to_ix = env.command_to_ix

for key in command_to_ix:
    ix = command_to_ix[key]
    env.setExeccmd(key)
    obs = env.makeObs()
    episode_id = policyClient.start_episode(training_enabled=False)
    res = policyClient.get_action(episode_id, obs)
    print('command:', key, 'action:', res)
    episode_id = policyClient.end_episode(episode_id, obs)

test_cases = [{"case": "test_1", "cmds": ["cat", "grep", "wc", "echo", "echo", "rm", "cat", "cat", "free", "grep", "awk", "ls", "which", "crontab", "w", "uname", "cat", "grep", "grep", "wc", "top", "uname", "uname", "lscpu", "echo", "rm"]}]

for i in range(len(test_cases)):
    case = test_cases[i]
    print("case: ", case['case'])
    cmds = case['cmds']
    episode_id = policyClient.start_episode(training_enabled=False)

    for j in range(len(cmds)):
        c = cmds[j]
        env.setExeccmd(c)
        obs = env.makeObs()
        res = policyClient.get_action(episode_id, obs)
        print('command:', c, 'action:', res)

    episode_id = policyClient.end_episode(episode_id, obs)
