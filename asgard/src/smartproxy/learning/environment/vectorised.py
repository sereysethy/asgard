from typing import Tuple
import numpy as np
import gymnasium as gym
from smartproxy.learning.environment import env
from smartproxy.utils import common
from sklearn.preprocessing import Normalizer
from smartproxy.learning.environment import attack_patterns

class AtackerEnvCase21(env.BaseEnv):
    """
    Case: 2.1

    The observation contains only a single command and it is represented by
    a one-hot-vector.

    The idea is to use it to test if we can get the same result as we use a
    tabular one.

    Observation
    -----------
    -  command

    Observation representation
    --------------------------
    - one-hot-vector

    Actions
    -------
        allow
        block
        substitute

    Rewards
    -------
        -1: when a custom command is allowed.
        1 : when a custom command is blocked or substituted
        1: when a download command is allowed
        0: any other commands
    """

    # different actions available
    ACTION_ALLOW        = 0
    ACTION_BLOCK        = 1
    ACTION_SUBSTITUTE   = 2

    def __init__(self):
        self.prepare_command_list()
        observation_size = len(self.ALL_COMMANDS)
        action_size = 3

        super().__init__(action_size=action_size,
                         observation_size=observation_size,
                         name="AtackerEnvCase21")

    @property
    def observation_space(self):
        return gym.spaces.Box(low=0, high=np.inf, shape=(self.observation_size, 1))

    @property
    def action_space(self):
        return gym.spaces.Discrete(self.action_size)

    def makeObs(self, basename: str, execCmd: str) -> np.array:
        """construct an observation.

        Params
            basename: (str) only command name
            execCmd: (str) a full path to command name
        Return
            a one-hot-vector of the command to be executed.
        """
        _cmdIndex = self.commandNameToCommandIndex(basename, execCmd)
        _obs = np.zeros(self.observation_space.shape[0])
        _obs[_cmdIndex] = 1

        # save information about command for later use
        self.cmdIndex = _cmdIndex
        self.basename = basename
        self.execCmd = execCmd
        return _obs

    def makeObsFromCommandIndex(self, cmdIndex) -> np.array:
        """construct an observation directly from a command index.

        It is more like a helper class. It should produce the exact observation
        as in the method @makeObs().

        Params
        ------
        cmdIndex: (int) command index

        Return
        ------
        obs: (np.array) a one-hot vector containing an index of command index
        """

        _obs = np.zeros(self.observation_space.shape[0])
        _obs[cmdIndex] = 1
        return _obs

    def getActionName(self, action):
        if action == self.ACTION_ALLOW:
            return "ACTION_ALLOW"
        elif action == self.ACTION_BLOCK:
            return "ACTION_BLOCK"
        elif action == self.ACTION_SUBSTITUTE:
            return "ACTION_SUBSTITUTE"

    def step(self, obs, action:int) -> Tuple[float, bool, dict]:
        """Return a reward given a current state of the observation.

        Reward system:
        - -1: when a custom command is allowed.
        - 1 : when a custom command is blocked or substituted
        - 1: when a download command is allowed
        - 0: any other commands
        """

        done   = False
        reward = 0.0
        info   = {}

        cmdIndex = self.cmdIndex
        cmdName = self.ALL_COMMANDS[cmdIndex]
        markoveState = self.commandIndexToMarkovState(cmdIndex)
        # print(f"cmd ix: {cmdIndex} to markoveState: {markoveState}")

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
            if  action == self.ACTION_ALLOW:
                reward = -1.0
            else:
                reward = 1
        elif markoveState == self.MARKOV_STATE_COMMAND:
            if cmdName in common.DOWNLOAD_COMMANDS:
                if action == self.ACTION_ALLOW:
                    reward = 1
            else:
                reward = 0.0
        elif markoveState in self.MARKOV_STATE_TERMINAL:
            done = True

        return reward, done, info

class AtackerEnvCase22(env.BaseEnv):
    """
    Case: 2.2

    The observation contains more observations.

    Observation
    -----------
        command
        number of commands executed
        number of each time that each command is executed

    Observation representation
    --------------------------
        command: a one-hot-vector
        total number of commands executed: another column to the one-hot-vector
        frequency of each executed command: a vector of the length equal to the
        number of commands

    Action
    ------
        allow
        block
        substitute

    Rewards
    -------
        -1: when a custom command is allowed.
        1 : when a custom command is blocked or substituted
        1: when a download command is allowed
        0: any other commands

    Normalisation
    -------------
        total number and frequency of each executed command are normalised
    """

    # different actions available
    ACTION_ALLOW        = 0
    ACTION_BLOCK        = 1
    ACTION_SUBSTITUTE   = 2

    def __init__(self):
        self.prepare_command_list()

        # one-hot-vector
        self._NUMBER_COMMANDS = len(self.ALL_COMMANDS)
        observation_size = self._NUMBER_COMMANDS

        # number of commands executed
        observation_size += 1

        # number of times that each commands executed
        observation_size += self._NUMBER_COMMANDS

        action_size = 3

        # total number of commands executed
        self.stateTotalNumCmdExe = np.zeros(1)
        # frequency of each command executed
        self.stateFreqCmdExe = np.zeros(self._NUMBER_COMMANDS)

        # normaliser
        self.transformer = Normalizer(norm="max")

        super().__init__(action_size=action_size,
                                            observation_size=observation_size,
                                            name="AtackerEnvCase22")

    def normalise(self, x):
        """Normalise vector x to a unit norm vector.

        We test a max norm.

        The MAX_BOUND is set to 89, why 89 because that was the max number
        of commands found in the dataset.

        params
        ------
            x: a vector
        returns
        -------
            a unit vector
        """

        MIN_BOUND = 0
        MAX_BOUND = 89
        _tmp = np.concatenate((x, [MAX_BOUND]))
        _norm = self.transformer.transform([_tmp])

        return _norm[0][0:-1]

    def makeObs(self, basename: str, execCmd: str) -> np.array:
        """construct an observation.

        Params
            basename: (str) only command name
            execCmd: (str) a full path to command name
        Return
            a one-hot-vector of the command to be executed.
        """
        _cmdIndex = self.commandNameToCommandIndex(basename, execCmd)
        _cmdToExec = np.zeros(self._NUMBER_COMMANDS)

        _cmdToExec[_cmdIndex] = 1
        self.stateTotalNumCmdExe += 1
        self.stateFreqCmdExe[_cmdIndex] += 1

        # save information about command for later use
        self.cmdIndex = _cmdIndex
        self.basename = basename
        self.execCmd = execCmd

        # normalise data
        normTotalNumCmdExec = self.normalise(self.stateTotalNumCmdExe)
        normFreqCmdExe = self.normalise(self.stateFreqCmdExe)

        _obs = np.concatenate((_cmdToExec,
                                normTotalNumCmdExec,
                                normFreqCmdExe))
        return _obs

    def makeObsFromCommandIndex(self, cmdIndex) -> np.array:
        """construct an observation directly from a command index.

        It is more like a helper class. It should produce the exact observation
        as in the method @makeObs(). But this command will not alter the
        state of the environment, specifically the total number of commands
        executed and the frequency of each executed command.

        Params
        ------
        cmdIndex: (int) command index

        Return
        ------
        obs: (np.array) a one-hot vector containing an index of command index
        """

        _cmdToExec = np.zeros(self._NUMBER_COMMANDS)
        _cmdToExec[cmdIndex] = 1

        # normalise data
        normTotalNumCmdExec = self.normalise(self.stateTotalNumCmdExe)
        normFreqCmdExe = self.normalise(self.stateFreqCmdExe)

        _obs = np.concatenate((_cmdToExec,
                                normTotalNumCmdExec,
                                normFreqCmdExe))

        return _obs

    def getActionName(self, action):
        if action == self.ACTION_ALLOW:
            return "ACTION_ALLOW"
        elif action == self.ACTION_BLOCK:
            return "ACTION_BLOCK"
        elif action == self.ACTION_SUBSTITUTE:
            return "ACTION_SUBSTITUTE"

    def reset(self)-> np.array:
        """Reset some state variables."""

        # total number of commands executed
        self.stateTotalNumCmdExe = np.zeros(1)
        # frequency of each command executed
        self.stateFreqCmdExe = np.zeros(self._NUMBER_COMMANDS)

        return np.array([])

    def step(self, obs, action:int) -> Tuple[float, bool, dict]:
        """Return a reward given a current state of the observation.

        Reward system:
        - -1: when a custom command is allowed.
        - 1 : when a custom command is blocked or substituted
        - 1: when a download command is allowed
        - 0: any other commands
        """

        done   = False
        reward = 0.0
        info   = {}

        cmdIndex = self.cmdIndex
        cmdName = self.ALL_COMMANDS[cmdIndex]
        markoveState = self.commandIndexToMarkovState(cmdIndex)
        # print(f"cmd ix: {cmdIndex} to markoveState: {markoveState}")

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
            if  action == self.ACTION_ALLOW:
                reward = -1.0
            else:
                reward = 1
        elif markoveState == self.MARKOV_STATE_COMMAND:
            if cmdName in common.DOWNLOAD_COMMANDS:
                if action == self.ACTION_ALLOW:
                    reward = 1
            else:
                reward = 0.0
        elif markoveState in self.MARKOV_STATE_TERMINAL:
            done = True

        return reward, done, info

class AtackerEnvCase23(env.BaseEnv):
    """
    Case: 2.3

    The observation contains more observations.

    Observation
    -----------
        command
        number of commands executed
        number of each time that each command is executed

    Observation representation
    --------------------------
        command: a one-hot-vector
        total number of commands executed: another column to the one-hot-vector
        frequency of each executed command: a vector of the length equal to the
        number of commands

    Action
    ------
        allow
        block
        substitute

    Rewards
    -------
        -1: when a custom command is allowed
        1: when a custom command is blocked or substituted
        1: when a download command is allowed
        0: any other commands
        -1: when a known malicious attack pattern is allowed

    Normalisation
    -------------
        total number and frequency of each executed command are normalised
    """

    # different actions available
    ACTION_ALLOW        = 0
    ACTION_BLOCK        = 1
    ACTION_SUBSTITUTE   = 2

    def __init__(self):
        self.prepare_command_list()

        # one-hot-vector
        self._NUMBER_COMMANDS = len(self.ALL_COMMANDS)
        observation_size = self._NUMBER_COMMANDS

        # number of commands executed
        observation_size += 1

        # number of times that each commands executed
        observation_size += self._NUMBER_COMMANDS

        action_size = 3

        # total number of commands executed
        self.stateTotalNumCmdExe = np.zeros(1)
        # frequency of each command executed
        self.stateFreqCmdExe = np.zeros(self._NUMBER_COMMANDS)

        # normaliser
        self.transformer = Normalizer()

        self.attackPattern = attack_patterns.AttackPatterns()

        super().__init__(action_size=action_size,
                                            observation_size=observation_size,
                                            name="AtackerEnvCase23")

    def normalise(self, x):
        MIN_BOUND = 0
        MAX_BOUND = 89
        _tmp = np.concatenate((x, [MAX_BOUND]))
        _norm = self.transformer.transform([_tmp])

        return _norm[0][0:-1]

    def makeObs(self, basename: str, execCmd: str) -> np.array:
        """construct an observation.

        Params
        ------
            basename: (str) only command name
            execCmd: (str) a full path to command name
        Return
        ------
            a one-hot-vector of the command to be executed.
        """
        _cmdIndex = self.commandNameToCommandIndex(basename, execCmd)
        _cmdToExec = np.zeros(self._NUMBER_COMMANDS)

        _cmdToExec[_cmdIndex] = 1
        self.stateTotalNumCmdExe += 1
        self.stateFreqCmdExe[_cmdIndex] += 1

        # save information about command for later use
        self.cmdIndex = _cmdIndex
        self.basename = basename
        self.execCmd = execCmd

        # normalise data
        normTotalNumCmdExec = self.normalise(self.stateTotalNumCmdExe)
        normFreqCmdExe = self.normalise(self.stateFreqCmdExe)

        _obs = np.concatenate((_cmdToExec,
                                normTotalNumCmdExec,
                                normFreqCmdExe))
        return _obs

    def makeObsFromCommandIndex(self, cmdIndex) -> np.array:
        """construct an observation directly from a command index.

        It is more like a helper class. It should produce the exact observation
        as in the method @makeObs(). But this command will not alter the
        state of the environment, specifically the total number of commands
        executed and the frequency of each executed command.

        Params
        ------
        cmdIndex: (int) command index

        Return
        ------
        obs: (np.array) a one-hot vector containing an index of command index
        """

        _cmdToExec = np.zeros(self._NUMBER_COMMANDS)
        _cmdToExec[cmdIndex] = 1

        # normalise data
        normTotalNumCmdExec = self.normalise(self.stateTotalNumCmdExe)
        normFreqCmdExe = self.normalise(self.stateFreqCmdExe)

        _obs = np.concatenate((_cmdToExec,
                                normTotalNumCmdExec,
                                normFreqCmdExe))

        return _obs

    def getActionName(self, action):
        if action == self.ACTION_ALLOW:
            return "ACTION_ALLOW"
        elif action == self.ACTION_BLOCK:
            return "ACTION_BLOCK"
        elif action == self.ACTION_SUBSTITUTE:
            return "ACTION_SUBSTITUTE"

    def reset(self)-> np.array:
        """Reset some state variables."""

        # total number of commands executed
        self.stateTotalNumCmdExe = np.zeros(1)
        # frequency of each command executed
        self.stateFreqCmdExe = np.zeros(self._NUMBER_COMMANDS)

        # reset attack pattern
        self.attackPattern.reset()

        return np.array([])

    def step(self, obs, action:int) -> Tuple[float, bool, dict]:
        """Return a reward given a current state of the observation.

        Rewards
        -------
            -1: when a custom command is allowed
            1: when a custom command is blocked or substituted
            1: when a download command is allowed
            0: any other commands
            -1: when a known malicious attack pattern is allowed
        """

        done   = False
        reward = 0.0
        info   = {}

        cmdIndex = self.cmdIndex
        cmdName = self.ALL_COMMANDS[cmdIndex]
        markoveState = self.commandIndexToMarkovState(cmdIndex)
        attackPatternStates  = self.attackPattern.transition(cmdName)
        # print(f"cmd ix: {cmdIndex} to markoveState: {markoveState}")

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
            if  action == self.ACTION_ALLOW:
                reward = -1.0
            else:
                reward = 1
        elif markoveState == self.MARKOV_STATE_COMMAND:
            if cmdName in common.DOWNLOAD_COMMANDS:
                if action == self.ACTION_ALLOW:
                    reward = 1
            else:
                reward = 0.0
        elif markoveState in self.MARKOV_STATE_TERMINAL:
            done = True
        elif attackPatternStates["pattern2"]:
            if action == self.ACTION_ALLOW:
                reward = -1
        elif attackPatternStates["pattern3"]:
            if action == self.ACTION_ALLOW:
                reward == -1
        elif attackPatternStates["pattern4"]:
            if action == self.ACTION_ALLOW:
                reward == -1

        return reward, done, info