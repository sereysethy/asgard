from typing import Tuple
from twisted.python import log
import gymnasium as gym
from Levenshtein import distance
from smartproxy.learning.environment import env
from smartproxy.utils import common

from smartproxy.learning.preprocess import load_all_commands, load_user_commands

class HelizaEnv(env.BaseEnv):
    # different actions available
    ACTION_ALLOW      = 0
    ACTION_BLOCK       = 1
    ACTION_SUBSTITUTE = 2
    ACTION_INSULT     = 3

    INSULT_COMMANDS = ['insult']

    MARKOV_STATE_INSULT = "__MARKOV_STATE_INSULT__"

    def __init__(self):
        self.prepare_command_list()
        observation_size = len(self.ALL_COMMANDS)
        action_size = 4
        self._insult_string = None
        super(HelizaEnv, self).__init__(action_size=action_size,
                                            observation_size=observation_size,
                                            name="HelizaEnv-v0")

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
        self.INSULT_COMMAND_IX = last + 3

        self.ALL_COMMANDS = self.COMMANDS

        self.ALL_COMMANDS.append(self.MARKOV_STATE_EMPTY)
        self.ALL_COMMANDS.append(self.MARKOV_STATE_CUSTOM)
        self.ALL_COMMANDS.append(self.MARKOV_STATE_UNKNOWN)
        self.ALL_COMMANDS.append(self.MARKOV_STATE_INSULT)

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
        elif action == self.ACTION_INSULT:
            return "ACTION_INSULT"

    def commandNameToCommandIndex(self, basename:str, execCmd:str):
        """Return index which corresponds to the cmd name.

        Parameters:
            basename string: name no path 'command'
            execCmd string: name including path if any '/path/to/command'
        """

        if basename in self.COMMAND_TO_IX:
            return self.COMMAND_TO_IX[basename]

        # this is a mild assumption that all custom commands in this form
        # ./, we can turn it to else part, to treat everything else as custom
        if len(execCmd) >= 3 and execCmd[0] == '.' and execCmd[1] == '/':
            return self.CUSTOM_COMMAND_IX

        if len(execCmd) >= 3 and execCmd[0] == '/' and basename not in self.COMMAND_TO_IX:
            return self.CUSTOM_COMMAND_IX

        if basename == "exit_":
            return self.COMMAND_TO_IX["exit"]

        log.msg('Insult command: {}, exec cmd: {}'.format(basename, execCmd))
        self._insult_string = execCmd
        return self.INSULT_COMMAND_IX

    def commandIndexToMarkovState(self, cmdIndex:int):
        """Map a command index to its name."""

        if cmdIndex == self.CUSTOM_COMMAND_IX:
            cmdName = "custom"
        elif cmdIndex == self.INSULT_COMMAND_IX:
            cmdName = "insult"
        else:
            # if it is a normal command, return its name
            cmdName = self.COMMANDS[cmdIndex]

        # print(f"cmdName: {cmdName}/{cmdIndex}")

        return self.commandNameToMarkovState(cmdName)

    def commandNameToMarkovState(self, basename:str):
        """Map command index to its Markov state.

        Input:
            basename (str): is the command name, no path
        """

        if basename in self.COMMAND_TO_IX and \
            basename not in self.TERMINAL_COMMANDS and \
                basename not in self.CUSTOM_COMMANDS:
            return self.MARKOV_STATE_COMMAND
        elif basename in self.TERMINAL_COMMANDS:
            return self.MARKOV_STATE_TERMINAL
        elif basename in self.CUSTOM_COMMANDS:
            return self.MARKOV_STATE_CUSTOM
        else:
            log.msg('insult command: ', basename)
            return self.MARKOV_STATE_INSULT

    def calculateNormalizedLevenshteinDistance(self, cmdName):
        minDistance = []
        sumDistances = 0
        for cmd in self.COMMAND_TO_IX:
            d = distance(cmdName, cmd)
            minDistance.append(d)
            sumDistances += d

        normalizedDistance = min(minDistance) / sumDistances

        return normalizedDistance

    def step(self, obs, action:int) -> Tuple[float, bool, dict]:
        """Return a reward given a current state of the observation.

        Reward system:
        - 1 : when a custom command is tried, regardless of actions taken
        - min(l(cmd, x)) x \in {all commands}
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

        if action == self.ACTION_INSULT:
            info['status'] = self.BASH_STATUS_CMD_NOT_FOUND

        # reward setting for each attacker input
        if markoveState == self.MARKOV_STATE_CUSTOM:
            reward = 1
        elif markoveState == self.MARKOV_STATE_INSULT:
            reward = self.calculateNormalizedLevenshteinDistance(self._insult_string)
            self._insult_string = None
        elif markoveState == self.MARKOV_STATE_COMMAND:
            reward = 0.0
        elif markoveState in self.MARKOV_STATE_TERMINAL:
            done = True

        return reward, done, info

class HelizaEnvNoInsult(env.BaseEnv):
    # different actions available
    ACTION_ALLOW      = 0
    ACTION_BLOCK       = 1
    ACTION_SUBSTITUTE = 2

    INSULT_COMMANDS = ['insult']

    MARKOV_STATE_INSULT = "__MARKOV_STATE_INSULT__"

    def __init__(self):
        self.prepare_command_list()
        observation_size = len(self.ALL_COMMANDS)
        action_size = 3
        self._insult_string = None
        super().__init__(action_size=action_size,
                                            observation_size=observation_size,
                                            name="HelizaEnv-v1")

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
            else:
                reward = 0.0
        elif markoveState in self.MARKOV_STATE_TERMINAL:
            done = True

        return reward, done, info