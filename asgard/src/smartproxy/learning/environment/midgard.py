"""
This environment only depends on the state environment.

It is used as a benchmark for other use cases.
Environemnt:
    * state: command only

Action set:
    * allow
    * block
    * substitute

Reward:
    * 1: attacker transitions to a download command
    * -1: attacker transitions to a custom command
    * 0: otherwise
"""

from typing import Tuple
from twisted.python import log
import gymnasium as gym
from smartproxy.learning.environment import env
from smartproxy.utils import common

from smartproxy.learning.preprocess import load_all_commands

class MidgardEnv(env.BaseEnv):
    # different actions available
    ACTION_ALLOW      = 0
    ACTION_BLOCK      = 1
    ACTION_SUBSTITUTE = 2

    def __init__(self):
        self.prepare_command_list()
        observation_size = len(self.ALL_COMMANDS)
        action_size = 3
        self._insult_string = None
        super().__init__(action_size=action_size,
                                            observation_size=observation_size,
                                            name="MidgardEnv-v0")

    @property
    def observation_space(self):
        return gym.spaces.Discrete(self.observation_size)

    @property
    def action_space(self):
        return gym.spaces.Discrete(self.action_size)

    def prepare_command_list(self):
        """Load commands from files and initialise command list and command ix."""

        if not self.call_once:
            self.call_once = True
        else:
            log.msg("prepare_command_list can only be called once.")
            return

        except_cmd = []
        self.command_list = []
        self.command_list += load_all_commands(except_cmd)
        self.COMMANDS = self.command_list
        # self.COMMANDS += self.STATE_COMMAND_TYPE
        self.COMMAND_TO_IX = {word: i for i, word in enumerate(self.COMMANDS)}

        last = len(self.COMMANDS)
        self.EMPTY_COMMAND_IX = last
        self.CUSTOM_COMMAND_IX = last + 1
        self.UNKNOWN_COMMAND_IX = last + 2

        self.ALL_COMMANDS = self.COMMANDS

        self.ALL_COMMANDS.append(self.MARKOV_STATE_EMPTY)
        self.ALL_COMMANDS.append(self.MARKOV_STATE_CUSTOM)
        self.ALL_COMMANDS.append(self.MARKOV_STATE_UNKNOWN)

    def makeObs(self, basename: str, execCmd: str) -> int:
        """construct an observation.

        execcmd: command to use in an observation
        cmdState: a letter representing command state
        """
        command_ix = self.commandNameToCommandIndex(basename, execCmd)
        return command_ix

    def getActionName(self, action):
        if action == self.ACTION_ALLOW:
            return "ACTION_ALLOW"
        elif action == self.ACTION_BLOCK:
            return "ACTION_BLOCK"
        elif action == self.ACTION_SUBSTITUTE:
            return "ACTION_SUBSTITUTE"

    def step(self, obs, action:int) -> Tuple[float, bool, dict]:
        """
        Return a reward given a current state of the observation.

        Reward system:
        - -1 : when a custom command is tried, for any actions
        - 1: when a download command is tried, for any actions
        - 0: any other commands
        """

        done   = False
        reward = 0.0
        info   = {}

        cmdIndex = obs
        cmdName = self.ALL_COMMANDS[cmdIndex]
        markoveState = self.commandIndexToMarkovState(cmdIndex)
        # print(f"name: {cmdName}, cmd ix: {cmdIndex} to markoveState: {markoveState}")

        # Action: allow
        if action == self.ACTION_ALLOW:
            info['status'] = self.BASH_STATUS_OK

        # Action: block
        if action == self.ACTION_BLOCK:
            info['status'] = self.BASH_STATUS_CMD_NOT_FOUND

        # Action: substitute
        if action == self.ACTION_SUBSTITUTE:
            info['status'] = self.BASH_STATUS_OK

        # reward setting for each attacker input
        if markoveState == self.MARKOV_STATE_CUSTOM:
            reward = -1
        elif markoveState == self.MARKOV_STATE_COMMAND:
            if cmdName in common.DOWNLOAD_COMMANDS:
                reward = 1
        elif markoveState in self.MARKOV_STATE_TERMINAL:
            done = True

        return reward, done, info