from typing import Tuple
import gymnasium as gym
from smartproxy.learning.environment import env
from smartproxy.utils import common
from smartproxy.learning.environment import attack_patterns

class SimpleAtackerEnv(env.BaseEnv):
    """
    This environment returns the reward as follows:

    Observation
    -----------
        - command

    Observation representation
    --------------------------
        - command: its index

    Actions
    -------
        - allow
        - block
        - substitute
    Rewards
    -------
        - -1: when a custom command is executed.
        - 1 : when a custom command is blocked or substituted
        - 1: when a download command is executed
        - 0: any other commands
    """

    # different actions available
    ACTION_ALLOW        = 0
    ACTION_BLOCK         = 1
    ACTION_SUBSTITUTE   = 2

    def __init__(self):
        self.prepare_command_list()
        observation_size = len(self.ALL_COMMANDS)
        action_size = 3
        super(SimpleAtackerEnv, self).__init__(action_size=action_size,
                                            observation_size=observation_size,
                                            name="SimpleAtackerEnv-v0")

    @property
    def observation_space(self):
        return gym.spaces.Discrete(self.observation_size)

    @property
    def action_space(self):
        return gym.spaces.Discrete(self.action_size)

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
        """Return a reward given a current state of the observation.

        Reward system:
        - -1: when a custom command is executed.
        - 1 : when a custom command is blocked or substituted
        - 1: when a download command is executed
        - 0: any other commands
        """

        done   = False
        reward = 0.0
        info   = {}

        cmdIndex = obs
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

class SimpleAtackerEnvV11(env.BaseEnv):
    """
    Case: 1.1

    The observation contains only a command name represented by its index.

    Observation
    -----------
        command

    Observation representation
    --------------------------
        command: its index

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
    """
    # different actions available
    ACTION_ALLOW        = 0
    ACTION_BLOCK        = 1
    ACTION_SUBSTITUTE   = 2

    def __init__(self):
        self.prepare_command_list()
        observation_size = len(self.ALL_COMMANDS)
        action_size = 3

        self.attackPattern = attack_patterns.AttackPatterns()

        super(SimpleAtackerEnvV11, self).__init__(action_size=action_size,
                                            observation_size=observation_size,
                                            name="SimpleAtackerEnv-v1.1")

    @property
    def observation_space(self):
        return gym.spaces.Discrete(self.observation_size)

    @property
    def action_space(self):
        return gym.spaces.Discrete(self.action_size)

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

    def reset(self):
        self.attackPattern.reset()

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

        cmdIndex = obs
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

class SimpleAtackerEnvV12(env.BaseEnv):
    """
    This class constitute a simple environment representing the Asgard1.0.

    Its state observation only relies on a `command` name which is represented
    by its `command index`.

    Actions:
        - allow
        - block
        - substitute

    Rewards:
        - :math:`-1`: when a custom command is allowed.
        - :math:`1`: when a download command is allowed.
        - :math:`0`: any other commands
    """

    # different actions available
    ACTION_ALLOW        = 0
    ACTION_BLOCK         = 1
    ACTION_SUBSTITUTE   = 2

    def __init__(self):
        self.prepare_command_list()
        observation_size = len(self.ALL_COMMANDS)
        action_size = 3
        super(SimpleAtackerEnvV12, self).__init__(action_size=action_size,
                                            observation_size=observation_size,
                                            name="SimpleAtackerEnv-v12")

    @property
    def observation_space(self):
        return gym.spaces.Discrete(self.observation_size)

    @property
    def action_space(self):
        return gym.spaces.Discrete(self.action_size)

    def makeObs(self, basename: str, execCmd: str) -> int:
        """construct an observation.

        Args:
            basename (str): command to use in an observation
            execCmd (str): original command

        Returns:
            command index
        """
        command_ix = self.commandNameToCommandIndex(basename, execCmd)
        return command_ix

    def getActionName(self, action: int) -> str:
        """
        Return the action name corresponding to the action index.

        Args:
            action: action index
        Returns:
            action name
        """
        if action == self.ACTION_ALLOW:
            return "ACTION_ALLOW"
        elif action == self.ACTION_BLOCK:
            return "ACTION_BLOCK"
        elif action == self.ACTION_SUBSTITUTE:
            return "ACTION_SUBSTITUTE"

    def step(self, obs: int, action:int) -> Tuple[float, bool, dict]:
        """Return a reward given a current state of the observation.

        Args:
            obs: index of the command name
            action: action index taken for this state observation index

        Returns:
            tuple: A tuple of the following items:
                - reward (float): a reward observed after taking the action on the current state obs.
                - done (bool): a boolean indicating whether the next state is terminal
                - info (dict): a dictionary of information.
        """

        done   = False
        reward = 0.0
        info   = {}

        cmdIndex = obs
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
        elif markoveState == self.MARKOV_STATE_COMMAND:
            if cmdName in common.DOWNLOAD_COMMANDS:
                if action == self.ACTION_ALLOW:
                    reward = 1
        elif markoveState in self.MARKOV_STATE_TERMINAL:
            done = True

        return reward, done, info