from typing import Tuple
import numpy as np
import gym
from smartproxy.learning.environment import env
from smartproxy.utils import common
from sklearn.preprocessing import Normalizer
from smartproxy.learning.environment import attack_patterns
from smartproxy.monitor.monitorstats import MonitorStats as Monitor

class AttackerEnvCaseV31(env.BaseEnv):
    """
    Case: 3.1

    The state observation contains a single command and the state of the
    target system used as honeypot which consists of CPU, Memory and Network
    bandwidths.
    
    Observation
    -----------
        command: name of attacker command
        state: indicate the state of the command, a command can be in a running
        state or is prepared to run.
        cpu: cpu usage of the target system
        memory: memory usage of the target system
        network inbound: network inbound traffic of the target system
        network outbound: network outbound traffic of the target system


    State observation representation
    --------------------------
        command: word2vec
        state: boolean, 1 indicates if the command is running otherwise 0.
        cpu: float
        memory: float
        network inbound: float
        network outbound: float

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
    COMMAND_EXEC_STATE_C = 0
    # R indicates that a command is running
    COMMAND_EXEC_STATE_R = 1

    COMMAND_STATE_INDEX = {
        'C': COMMAND_EXEC_STATE_C,
        'R': COMMAND_EXEC_STATE_R
    }

    def __init__(self):
        self.prepare_command_list()
        observation_size = 6
        action_size = 5

        # we have access to the target system stats, the target system is
        # defined in the configuration file.
        self.monitor = Monitor()

        super().__init__(action_size=action_size,
                         observation_size=observation_size,
                         name="AtackerEnvCaseV31")

    @property
    def observation_space(self):
        return gym.spaces.Box(low=0, high=np.inf, shape=(self.observation_size, 1))
                
    @property
    def action_space(self):
        return gym.spaces.Discrete(self.action_size)
    

    def makeObs(self, basename: str, execCmd: str, cmdExecState: str) -> np.array:
        """construct an observation.

        Params
        ------
            basename (str): the command name
            execCmd (str): the command name in its path
            cmdExecState (str): the state of the command, it can be 'R' or other.
            'R' means that the commmand is in a running state.

        Returns
        -------
            Return a Numpy array containing
                cmdIndex (int): the index of the command in the list of the command
                cmdExecStateValue (boolean): the running state of the command
                cpuUsagePer: CPU usage in percentage between 0 and 100
                memUsagePer: Memory usage in percentage between 0 and 100
                netInUsageBytes: Network inbound usage in bytes
                netOutUsageBytes: Network oubound usage in bytes
        """

        cmdIndex = self.commandNameToCommandIndex(basename, execCmd)

        if cmdExecState == 'R':
            cmdExecStateValue = 1
        else:
            cmdExecStateValue = 0

        cpuUsagePer, memUsagePer, netInUsageBytes, netOutUsageBytes = self.getTargetSystemState()

        obs = np.array([
                        cmdIndex, 
                        cmdExecStateValue, 
                        cpuUsagePer, 
                        memUsagePer, 
                        netInUsageBytes, 
                        netOutUsageBytes])
        return obs

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
            A tuple of parameters indicating the state of the target system.
        """
        # CPU, Memory, Network Inbound, Network Outbound
        cpuUsagePer = self.monitor.getCPUUsagePercentage()
        memUsagePer = self.monitor.getMemoryUsagePercentage()
        netInUsageBytes = self.monitor.getNetworkInboundUsage()
        netOutUsageBytes = self.monitor.getNetworkOutboundUsage()

        return (cpuUsagePer, memUsagePer, netInUsageBytes, netOutUsageBytes)

    def getCommandState(self, state):
        """
        state is a symbol representing command state in process table
        """
        return self.COMMAND_STATES[state]


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
    
    def step(self, obs, action:int) -> Tuple[float, bool, dict]:
        """Return a reward vector given a current state of the observation.

        The reward vector has two components: (1) the 1st component corresponds
        to the reward obtained by correctly choosing the correct action for the
        command alone; (2) the 2nd component correspond to the rewards which
        indicates the state of the target system. If the state is within the
        threashold p0, the reward will be 0, otherwise it will be set to -1.

        Rewards
        -------------
            1: when a download command is allowed
            1: when a custom command is allowed and the p <= p0
            1: when a custom command is blocked or substituted and p > p0, 
            independently of its running status
            0: any other commands

            p0 is a threashold parameter that indicates a current state of the
            target system.
        """

        # init
        done   = False
        # reward vector: at index 0 is for the command
        reward = [0,0]
        info   = {}

        # get the current state of the environment from the observation
        cmdIndex = obs[0]
        cmdExecStateValue = obs[1]
        cpuUsagePer = obs[2]
        memUsagePer = obs[3]
        netInUsageBytes = obs[4]
        netOutUsageBytes = obs[5]

        # get performance index from the passed values
        perf = 0.5
        # perf0 threshold
        perf0 = 1.0
        
        # get the name of the command from the command index
        cmdName = self.ALL_COMMANDS[cmdIndex]
        # get the Markov state corresponding to the command index
        markoveState = self.commandIndexToMarkovState(cmdIndex)

        # we return the status for each action taken, not status for the other
        # action such as "TERMINATE" and "NOP"
        if action == self.ACTION_ALLOW:
            info['status'] = self.BASH_STATUS_OK
        elif action == self.ACTION_BLOCK:
            info['status'] = self.BASH_STATUS_CMD_NOT_FOUND
        elif action == self.ACTION_SUBSTITUTE:
            info['status'] = self.BASH_STATUS_OK

        # reward setting for each attacker input
        if markoveState == self.MARKOV_STATE_CUSTOM:
            if  action == self.ACTION_ALLOW:
                reward[0] = 1
        elif markoveState == self.MARKOV_STATE_COMMAND:
            if cmdName in common.DOWNLOAD_COMMANDS:
                if action == self.ACTION_ALLOW:
                    reward[0] = 1
            else:
                reward = 0
        elif markoveState in self.MARKOV_STATE_TERMINAL:
            done = True

        # the reward is positive [0,1], if the current perf is less then the perf0.
        reward[1] = (perf0 - perf) / perf0

        return reward, done, info