"""
version: 3
"""

# type checking
from typing import Tuple

# libraries
import numpy as np
from sklearn.preprocessing import Normalizer
import gym
from gensim.models import Word2Vec

# Cowrie module
from cowrie.core.config import CowrieConfig

# our modules
from smartproxy.learning.environment import env
from smartproxy.utils import common
from smartproxy.monitor.monitorstats import MonitorStats as Monitor


class AttackerEnvCaseV31(env.BaseEnv):
    """
    Case: 3.1

    The state observation contains a single command and the state of the
    target system used as honeypot which consists of CPU and Memory.
    
    Observation
    -----------
        command: name of attacker command
        state: indicate the state of the command, a command can be in a running
            state or is prepared to run.
        cpu: cpu usage of the target system
        memory: memory usage of the target system

    State observation representation
    --------------------------
        command: word2vec
        state: boolean, 1 indicates if the command is running otherwise 0.
        cpu: float
        memory: float

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

        # number of actions
        action_size = 5

        # we have access to the target system stats, the target system is
        # defined in the configuration file.
        self.monitor = Monitor()

        # call the method to load a model to encode a command
        self.cmdVectorSize, self.commandEncoder = self.loadCommandEncodingModel()

        # number of observation
        observation_size = self.cmdVectorSize + 3

        # init the performance index threshold
        self.perf0 = CowrieConfig.getfloat("rl", "performance_index_0")

        super().__init__(action_size=action_size,
                         observation_size=observation_size,
                         name="AtackerEnvCaseV31")

    @property
    def observation_space(self):
        return gym.spaces.Box(low=0, high=np.inf, shape=(self.observation_size, 1))
                
    @property
    def action_space(self):
        return gym.spaces.Discrete(self.action_size)
    

    def loadCommandEncodingModel(self):
        """
        We use a trained model word2vec from gensim that can output a vector
        representing a command.

        Params
        ------
            None

        Returns
        -------
            Size of the output vector, a Word2Vec model
        """

        model_path = CowrieConfig.get("command_encoder", "model_path")

        model = Word2Vec.load(model_path)

        # we can get the output vector size from the Word2Vec model
        vector_size = model.wv.vector_size

        return vector_size, model

    def encodeCommand(self, basename: str, execCmd: str):
        """
        Using the encoding model and output a vector which represents the
        basename command.

        Params
        ------
            basename (str): the command name
            execCmd (str): the command name in its path
        Returns
        -------
            A vector representation of the input basename
        """

        cmdIndex  = self.commandNameToCommandIndex(basename, execCmd)
        cmdState = self.commandIndexToMarkovState(cmdIndex)
        print("cmdIndex: ", cmdIndex)
        print("cmdState: ", cmdState)
        if cmdState in self.commandEncoder.wv:
            return self.commandEncoder.wv.word_vec(cmdState)
        else:
            return self.commandEncoder.wv.word_vec('__UNKNOWN__')

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
            command encoded vector/array
            cmdExecStateValue (boolean): the running state of the command
            cpuUsage: CPU usage in between 0 and 1
            memUsage: Memory usage in between 0 and 1
            
            cmdIndex (int): the index of the command in the list of the command
        """

        cmdIndex  = self.commandNameToCommandIndex(basename, execCmd)
        cmdVector = self.encodeCommand(basename, execCmd)

        if cmdExecState == 'R':
            cmdExecStateValue = 1
        else:
            cmdExecStateValue = 0

        cpuUsageIndex, memUsageIndex = self.getTargetSystemState()

        # concatenate the vector and other state observation
        obs = np.concatenate((cmdVector, [
                                    cmdExecStateValue, 
                                    cpuUsageIndex, 
                                    memUsageIndex]))
        return obs, cmdIndex

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
        # CPU, Memory
        cpuUsageIndex = self.monitor.getCPUUsagePercentage()
        memUsageIndex = self.monitor.getMemoryUsagePercentage()
        
        return (cpuUsageIndex, memUsageIndex)

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
    
    def getPerformanceIndex(self, cpuUsage: float, memUsage: float):
        """
        Calculate the performance based on the input parameters.

        Params
        ------
            cpuUsage (float): a normalised value between 0 and 1
            memUsage (float): a normalised value between 0 and 1

        Returns
        -------
            maximum of the cpuUsage and memUsage
        """

        return np.max(np.clip([cpuUsage, memUsage], 0, 1))

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
        """

        # init
        done   = False
        # reward vector: at index 0 is for the command
        reward = [0.0, 0.0]
        info   = {}

        # perf0 threshold, set by the constant
        perf0 = self.perf0

        # get the current state of the environment from the observation
        cmdExecStateValue = obs[self.cmdVectorSize] # first to cmdVectorSize if cmd
        cpuUsageIndex = obs[self.cmdVectorSize + 1]
        memUsageIndex = obs[self.cmdVectorSize + 2]

        # get performance index from the passed values
        print(f"cpuUsageIndex: {cpuUsageIndex}, memUsageIndex: {memUsageIndex}")
        perf = self.getPerformanceIndex(cpuUsageIndex, memUsageIndex)
        print(f"performance index: {perf}")
        
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
                # the reward is a positive number [-1,1], if the current perf is less then the perf0.
                reward[0] = max((perf0 - perf) / perf0, 0)
        elif markoveState == self.MARKOV_STATE_COMMAND:
            if cmdName in common.DOWNLOAD_COMMANDS:
                if action == self.ACTION_ALLOW:
                    reward[0] = 1.0
            else:
                reward[0] = 0.0
        elif markoveState in self.MARKOV_STATE_TERMINAL:
            done = True

        # the reward is a positive number [-1,1], if the current perf is less then the perf0.
        # regardless of commands, if I only take into the account the performance
        # index
        reward[1] = np.min([(perf0 - perf) / perf0, 0])

        return reward, done, info