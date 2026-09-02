# type checking
from typing import Tuple

# libraries
import numpy as np
import gymnasium as gym
# from twisted.python import log

# Cowrie module
from cowrie.core.config import CowrieConfig

# our modules
from smartproxy import log
from smartproxy.learning.environment import env
from smartproxy.utils import common
from smartproxy.monitor.monitorstats import MonitorStats as Monitor

class OneHotVectorEnvCase23(env.BaseEnv):
    """
    Case: 2.3

    The state observation contains a single command and the state of the
    target system used as honeypot which consists of CPU and Memory.

    The idea is to use it to test if we can get the same result as we use a
    tabular one.

    Observation
    -----------
        command: name of attacker command
        state: indicate the state of the command, a command can be in a running
            state or is prepared to run.
        average cpu usage: average cpu usage of the target system
        average memory usage : average memory usage of the target system

    State observation representation
    --------------------------
        command: one-hot-vector
        state: boolean, 1 indicates if the command is running otherwise 0.
        avgCpuUsage: float
        avgMemoryUsage: float

    Actions
    -------
        allow: allow a command execution
        block: block a command execution
        substitute: substitute a command execution
        terminate: terminate a running command
        nop: take no action

    Rewards
    -------
        1: when a download command is allowed
        1: when a custom command is allowed and the p <= p0
        1: when a custom command is blocked or substituted and p > p0,
        independently of its running status
        0: any other commands

        p0 is a threashold parameter that indicates a current state of the
        target system.
    """

    # different actions available
    ACTION_ALLOW        = 0
    ACTION_BLOCK        = 1
    ACTION_SUBSTITUTE   = 2
    ACTION_TERMINATE    = 3
    ACTION_NOP          = 4

    # C indicates that a command is not yet executed
    COMMAND_EXEC_STATE_START = 'C'
    COMMAND_EXEC_STATE_START_VALUE = 0
    # R indicates that a command is running
    COMMAND_EXEC_STATE_RUNNING = 'R'
    COMMAND_EXEC_STATE_RUNNING_VALUE = 1

    def __init__(self):
        self.prepare_command_list()

        self.cmdVectorSize = len(self.ALL_COMMANDS)
        action_size = 5

        # number of observation
        observation_size = self.cmdVectorSize + 3

        # we have access to the target system stats, the target system is
        # defined in the configuration file.
        self.monitor = Monitor()

        # init the performance index threshold
        self.perfThreshold = CowrieConfig.getfloat("rl", "performance_threshold")

        super().__init__(action_size=action_size,
                         observation_size=observation_size,
                         name="EnvOneHotVector2.3")

    @property
    def observation_space(self):
        return gym.spaces.Box(low=0, high=np.inf, shape=(self.observation_size, 1))

    @property
    def action_space(self):
        return gym.spaces.Discrete(self.action_size)

    def makeObs(self, basename: str, execCmd: str, cmdExecState: str) -> Tuple[np.array, int]:
        """construct an observation.

        Params
        ------
            basename (str): the command name
            execCmd (str): the command name in its path
            cmdExecState (str): the state of the command, it can be 'R' or other.
            'R' means that the commmand is in a running state.

        Returns
        -------
            A Numpy array containing:
            - a one-hot-vector of the command to be executed
            - cmdExecStateValue (boolean): the running state of the command
            - avgCpuUsage: normalised average CPU usage in between 0 and 1
            - avgMemUsage: normalised average Memory usage in between 0 and 1
        """
        cmdIndex = self.commandNameToCommandIndex(basename, execCmd)
        onehotCmd = np.zeros(self.cmdVectorSize)
        onehotCmd[cmdIndex] = 1

        if cmdExecState == self.COMMAND_EXEC_STATE_START:
            cmdExecStateValue = 0
        else:
            cmdExecStateValue = 1

        cpuUsageIndex, memUsageIndex = self.getTargetSystemState()

        # concatenate the vector and other state observation
        obs = np.concatenate((onehotCmd, [
                                    cmdExecStateValue,
                                    cpuUsageIndex,
                                    memUsageIndex]))
        return (obs, cmdIndex)

    def getTargetSystemState(self)->tuple:
        """
        Return the current available state of the target system.

        Its values are updated on a regular interval, maybe we should average
        them for the last t second????

        Params
        ------
            None

        Returns
        -------
            A tuple of parameters indicating the index of the target system.
        """
        # average CPU, Memory usage in percentage, we normalise them to be in [0,1]
        avgCpuUsageIndex = self.monitor.getAvgCPUUsagePercentage() / 100
        avgMemUsageIndex = self.monitor.getAvgMemoryUsagePercentage() / 100

        return (avgCpuUsageIndex, avgMemUsageIndex)

    def getActionName(self, action: int) -> str:
        """Return the name of action based on its index name.

        Params
        ------
            action (str): index of the action

        Returns
        -------
            name of the action
        """

        if action == self.ACTION_ALLOW:
            return "ACTION_ALLOW"
        elif action == self.ACTION_BLOCK:
            return "ACTION_BLOCK"
        elif action == self.ACTION_SUBSTITUTE:
            return "ACTION_SUBSTITUTE"
        elif action == self.ACTION_TERMINATE:
            return "ACTION_TERMINATE"
        elif action == self.ACTION_NOP:
            return "ACTION_NOP"
        else:
            return "ACTION_UNKNOWN"

    def getPerformanceIndex(self, avgCpuUsageNorm: float, avgMemUsageNorm: float):
        """
        Calculate the performance based on the input parameters.

        TODO: Maybe we need some more sophisticated function!

        Params
        ------
            avgCpuUsageNorm (float): a normalised value between 0 and 1
            avgMemUsageNorm (float): a normalised value between 0 and 1

        Returns
        -------
            maximum of the cpuUsage and memUsage
        """

        return np.max(np.clip([avgCpuUsageNorm, avgMemUsageNorm], 0, 1))

    def step(self, obs, cmdIndex, action:int) -> Tuple[float, bool, dict]:
        """Return a reward vector given a current state of the observation.

        The reward vector has two components: (1) the 1st component corresponds
        to the reward obtained by correctly choosing the correct action for the
        command alone; (2) the 2nd component correspond to the rewards which
        indicates the state of the target system. If the state is within the
        threashold p0, the reward will be 0, otherwise it will be set to -1.

        Rewards
        -------
            1: when a download command is allowed
            (p0 - p)/p0: when a custom command is allowed and the p <= p0, this
                value is positive but when it is allowed and p > p0, it will
                become negative.
            0: any other commands

            p0 is a threashold parameter that indicates a current state of the
            target system.

        Params
        ------

        Returns
        -------
            reward (float): reward for taking this action
            done (boolean): True if we transition to the final state (exit)
            info (dict): information
        """

        # init
        done   = False
        # reward vector: at index 0 is for the command
        reward = [0.0, 0.0]
        info   = {}

        # perf0 threshold, set by the constant
        perfThreshold = self.perfThreshold

        # get the current state of the environment from the observation
        cmdExecStateValue = obs[self.cmdVectorSize] # first to cmdVectorSize if cmd
        avgCpuUsageNorm = obs[self.cmdVectorSize + 1]
        avgMemUsageNorm = obs[self.cmdVectorSize + 2]

        # get performance index from the passed values
        log.info("avgCpuUsageNorm: {cpu}, avgMemUsageNorm: {mem}", cpu=avgCpuUsageNorm, mem=avgMemUsageNorm)
        perf = self.getPerformanceIndex(avgCpuUsageNorm, avgMemUsageNorm)

        # get the name of the command from the command index
        cmdName = self.ALL_COMMANDS[cmdIndex]
        # get the Markov state corresponding to the command index
        markovState = self.commandIndexToMarkovState(cmdIndex)

        # we return the status for each action taken, not status for the other
        # action such as "TERMINATE" and "NOP"
        if action == self.ACTION_ALLOW:
            info['status'] = self.BASH_STATUS_OK
        elif action == self.ACTION_BLOCK:
            info['status'] = self.BASH_STATUS_CMD_NOT_FOUND
        elif action == self.ACTION_SUBSTITUTE:
            info['status'] = self.BASH_STATUS_OK

        # reward setting for each attacker input
        curPerfIdx = (perfThreshold - perf) / perfThreshold
        log.info(f"perf. threshold: {perfThreshold}, perf: {perf}, current perf. index: {curPerfIdx}")

        # command is not yet executed
        if cmdExecStateValue == self.COMMAND_EXEC_STATE_START_VALUE:
            if markovState == self.MARKOV_STATE_CUSTOM:
                if  action == self.ACTION_ALLOW:
                    # if the current perf is less than perf0.
                    if curPerfIdx >= 0:
                        # the reward is between [0,1]
                        reward[0] = max(0, curPerfIdx)
                    # if the current perf is greater than perf0
                    else:
                        # the reward is between [-1,0), if the current
                        # perf is greater than the set perf0.
                        reward[0] = min(curPerfIdx, 0)
                else:
                    reward[0] = 0
            elif markovState == self.MARKOV_STATE_COMMAND:
                if cmdName in common.DOWNLOAD_COMMANDS:
                    if action == self.ACTION_ALLOW:
                        reward[0] = 1.0
                else:
                    reward[0] = 0.0
            elif markovState in self.MARKOV_STATE_TERMINAL:
                done = True

        # the command is already executed, it becomes a process
        if cmdExecStateValue == self.COMMAND_EXEC_STATE_RUNNING_VALUE:
            if markovState == self.MARKOV_STATE_CUSTOM:
                # if the current perf is less than (<) perf0
                if curPerfIdx >= 0:
                    if action == self.ACTION_NOP:
                        reward[1] = max(0, curPerfIdx)
                    elif action == self.ACTION_TERMINATE:
                        reward[1] = -max(0, curPerfIdx)
                # if the current perf is greater than (>) perf0
                else:
                    if action == self.ACTION_NOP:
                        reward[1] = min(curPerfIdx, 0)
                    elif action == self.ACTION_TERMINATE:
                        reward[1] = -min(curPerfIdx, 0)

        return reward, done, info
