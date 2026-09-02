# type checking
from typing import Tuple

# libraries
import numpy as np
import gymnasium as gym

# Cowrie module
from cowrie.core.config import CowrieConfig

# our modules
from smartproxy import log
from smartproxy.learning.environment import env
from smartproxy.utils import common

from smartproxy.monitor.monitorstats import MonitorStats as Monitor

class RobertaBaseEnv(env.BaseEnv):
    """This represents the environment for Asgard2.0.

    Its state observation contains command embedding, and the state of the
    target system used as honeypot which consists of CPU and Memory. A command
    can be a single command, a command list, a compound command, etc.

    Observation:
        - command: command submitted by an attacker
        - risk level: risk level classifiedy by automated risk assessment
        - state: indicate the state of the command, a command can be in a running
            state or is prepared to run.
        - average cpu usage: average cpu usage of the target system
        - average memory usage : average memory usage of the target system

    State observation representation:
        - command (tensor): embedding
        - risk_level (float): risk level
        - state: boolean, 1 indicates if the command is running otherwise 0.
        - avg_cpu_usage: float
        - avg_mem_usage: float

    Actions:
        - `allow`: allow a command execution
        - `block`: block a command execution
        - `substitute`: substitute a command execution
        - `terminate`: terminate a running command
        - `nop`: take no action

    Rewards:
        Its reward function depends on its own state observation, action,
        and the command risk_level. For more details, see Asgard 2.0 <asgard2.0.html>_.
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

    monitor: Monitor = None

    def __init__(self, embedding_size: int, action_size: int, config: dict, name: str)->None:

        self.debug = CowrieConfig.getboolean("rl", "env_debug", fallback=False)

        self.prepare_command_list()

        # embedding size
        self.embedding_size = embedding_size

        # observation size: embedding_size, state (2), avg_cpu (1), avg_mem (1)
        # net_inbound (1), net_outbound (1), blk_read (1), blk_write (1)
        observation_size = self.embedding_size + 2 + 2 + 2 + 2

        # + the risk level which is encoded as one-hot vector equal to output_size
        observation_size += config["output_size"]

        # init the performance index threshold
        self.perfThreshold = CowrieConfig.getfloat("rl", "performance_threshold")
        self.BLK_READ_BYTE_MAX = CowrieConfig.getfloat("rl", "BLK_READ_BYTE_MAX")
        self.BLK_WRITE_BYTE_MAX = CowrieConfig.getfloat("rl", "BLK_WRITE_BYTE_MAX")
        self.NET_INBOUND_BYTE_MAX = CowrieConfig.getfloat("rl", "NET_INBOUND_BYTE_MAX")
        self.NET_OUTBOUND_BYTE_MAX = CowrieConfig.getfloat("rl", "NET_OUTBOUND_BYTE_MAX")
        self.riskLevelThreshold = CowrieConfig.getfloat("rl", "risk_level_threshold")

        super().__init__(action_size=action_size,
                         observation_size=observation_size,
                         name=name)

    @property
    def observation_space(self):
        return gym.spaces.Box(low=0, high=np.inf, shape=(self.observation_size, 1))

    @property
    def action_space(self):
        return gym.spaces.Discrete(self.action_size)

    def getRiskAssessment(self, cmd: str)->Tuple[list[float], float, list[float]]:
        pass

    def makeObs(self, rawCmd: str, basename: str, execCmd: str, cmdExecState: str) -> Tuple[np.ndarray, int]:
        """
        Construct an observation.

        Args:
            rawCmd (str): raw command as submitted by attacker
            basename (str): the command name if applicable
            execCmd (str): the command along with paths
            cmdExecState (str): the state of the command, it can be 'R' or other.
            'R' means that the commmand is in a running state.

        Returns:
            A Numpy array containing:
            - command embedding
            - risk level
            - cmdExecStateValue (boolean): the running state of the command
            - avgCpuUsage: normalised average CPU usage in between 0 and 1
            - avgMemUsage: normalised average Memory usage in between 0 and 1
        """

        cmdIndex = self.commandNameToCommandIndex(basename, rawCmd)
        riskLevel, prob, embbedding = self.getRiskAssessment(rawCmd)

        if cmdExecState == self.COMMAND_EXEC_STATE_START:
            cmdExecStateValue = np.array([1, 0])
        else:
            cmdExecStateValue = np.array([0, 1])

        targetSystemState = self.getTargetSystemState()
        cpuUsageIndex = targetSystemState["avgCpuUsageIndex"]
        memUsageIndex = targetSystemState["avgMemUsageIndex"]
        netInboundUsageIndex = targetSystemState["networkInboundIndex"]
        netOutboundUsageIndex = targetSystemState["networkOutboundIndex"]
        blkReadIndex = targetSystemState["blkReadIndex"]
        blkWriteIndex = targetSystemState["blkWriteIndex"]
        netInbound = targetSystemState["networkInbound"]
        netOutbound = targetSystemState["networkOutbound"]
        blkRead = targetSystemState["blkRead"]
        blkWrite = targetSystemState["blkWrite"]

        # concatenate the vector and other state observation
        obs = np.concatenate((embbedding, riskLevel, cmdExecStateValue,
                                    [cpuUsageIndex,
                                     memUsageIndex,
                                     netInboundUsageIndex,
                                     netOutboundUsageIndex,
                                     blkReadIndex,
                                     blkWriteIndex
                                     ]))
        if self.debug:
            log.info(f"risk level: {riskLevel} | prob: {prob:0.3f} | \
cpu idx: {cpuUsageIndex:0.5f} | mem. idx: {memUsageIndex:0.5f} | \
net. in idx: {netInboundUsageIndex:0.5f} | net. out. idx: {netOutboundUsageIndex:0.5f} | \
blk. read idx: {blkReadIndex:0.5f} | blk. write idx: {blkWriteIndex:0.5f}")
            log.info(f"net in bytes: {netInbound} | net out bytes: {netOutbound} | blkRead: {blkRead} | blkWrite: {blkWrite}")

        return (obs, cmdIndex)

    def getTargetSystemState(self)->dict:
        """
        Return the current available state of the target system.

        Its values are updated on a regular interval, maybe we should average
        them for the last t second????

        Returns:
            A dcitionary of parameters indicating the index of the target system.
        """
        # average CPU, Memory usage in percentage, we normalise them to be in [0,1]
        avgCpuUsageIndex = self.monitor.getAvgCPUUsagePercentage() / 100
        avgMemUsageIndex = self.monitor.getAvgMemoryUsagePercentage() / 100

        # in bytes
        netIn = self.monitor.getNetworkInboundUsage()
        netOut = self.monitor.getNetworkOutboundUsage()
        # in percentage
        networkInPer = (netIn * 100) / self.NET_INBOUND_BYTE_MAX
        networkOutPer = (netOut * 100) / self.NET_OUTBOUND_BYTE_MAX

        # normalise them and make them bound between 0 (0%) and 1 (100%)
        networkInboundIndex = min(networkInPer/100.0, 1.0)
        networkOutboundIndex = min(networkOutPer/100.0, 1.0)

        # in bytes
        blkRead = self.monitor.getBlkReadUsage()
        blkWrite = self.monitor.getBlkWriteUsage()
        # in percentage
        blkReadPer = (blkRead * 100 / self.BLK_READ_BYTE_MAX)
        blkWritePer = (blkWrite * 100 / self.BLK_WRITE_BYTE_MAX)

        # normalise them and make them bound between 0 (0%) and 1 (100%)
        blkReadIndex = min(blkReadPer/100.0, 1.0)
        blkWriteIndex = min(blkWritePer/100.0, 1.0)

        return {
            "avgCpuUsageIndex": avgCpuUsageIndex,
            "avgMemUsageIndex": avgMemUsageIndex,
            "networkInboundIndex": networkInboundIndex,
            "networkOutboundIndex": networkOutboundIndex,
            "blkReadIndex": blkReadIndex,
            "blkWriteIndex": blkWriteIndex,
            "networkInbound": netIn,
            "networkOutbound": netOut,
            "blkRead": blkRead,
            "blkWrite": blkWrite
        }

    def getActionName(self, action: int) -> str:
        """Return the name of action based on its index name.

        Args:
            action (str): index of the action

        Returns:
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

    def getPerformanceIndex(self,
                            avgCpuUsageNorm: float,
                            avgMemUsageNorm: float,
                            netInboundUsageNorm: float,
                            netOutboundUsageNorm: float,
                            blkReadNorm: float,
                            blkWriteNorm: float,
                            )->float:
        """
        Calculate the performance based on the input parameters.

        TODO: Maybe we need some more sophisticated function!

        Args:
            avgCpuUsageNorm (float): a normalised value between 0 and 1
            avgMemUsageNorm (float): a normalised value between 0 and 1
            netInboundUsageNorm (float): a normalised value between 0 and 1
            netOutboundUsageNorm (float): a normalised value between 0 and 1
            blkReadNorm (float): a normalised value between 0 and 1
            blkWriteNorm (float): a normalised value between 0 and 1

        Returns:
            maximum of the input parameters
        """

        return np.max(np.clip([
            avgCpuUsageNorm,
            avgMemUsageNorm,
            netInboundUsageNorm,
            netOutboundUsageNorm,
            blkReadNorm,
            blkWriteNorm
            ], 0., 1.))

    def normalizeReward(self, perf: float, perfThreshold: float)->float:
        r"""Return a normalized reward.

        This normalized reward is bounded by the performance threshold
        *aka* Security Of Incident (*SoC*) threshold :math:`t_{global}`.

        .. math::

            reward =
                \begin{cases}
                1 - v / t_{global} & \text{if } v <= t_{global} \\
                \frac{-(1 - v / t_{global})}{(1 - 1 / t_{global})} & \text{if } v > t_{global}
                \end{cases}

        Args:
            perf: current performance index
            perfThreshold: performance threshold

        Returns:
            Normalized reward
        """
        reward = 1 - (perf / perfThreshold)

        if reward < 0:
            return -(1 - perf / perfThreshold) / (1 - 1 / perfThreshold)
        else:
            return reward

    def getCommandExecStateValue(self, state:list[int])->int:
        """Return a command exec state.

        Args:
            state: a one-hot encoded vector of dimension `(2,)` where `[1,0]` indicates
                a command state of a short-running command,
                and `[0,1]` is a long-running command.

        Returns:
            command state whose values:
                - 1 (`COMMAND_EXEC_STATE_START_VALUE`): a short-running command
                - 0 (`COMMAND_EXEC_STATE_RUNNING_VALUE`): a long-running command
        """

        if state[0] == 1:
            return self.COMMAND_EXEC_STATE_START_VALUE

        return self.COMMAND_EXEC_STATE_RUNNING_VALUE


    def step(self, obs, cmdIndex, action:int) -> Tuple[list, bool, bool, dict]:
        """Return a reward vector given a current state of the observation.

        The reward vector has two components: the 1st component corresponds
        to the reward obtained by correctly choosing the correct action for the
        command alone or the reward obtained by applying the correct action for
        the desired risk level, and the 3nd component corresponds to the rewards
        which indicates the state of the target system. If the state is within
        the performance threshold, the reward will be equal to the performance
        index.

        Rewards:
            - :math:`1`: when a download command is allowed
            - :math:`(p0 - p)/p0`: when a custom command is allowed and the
              :math:`p \le p_0`, this value is positive but when it is allowed
              and :math:`p > p_0`, it will become negative.
            - :math:`0`: any other commands

            where :math:`p_0` is a threashold parameter that indicates a current state of the
            target system.

        Args:
            obs: current state observation
            cmdIndex: command index when it is possible to identify it
            action: action index

        Returns:
            tuple: A tuple of the following items:
                - reward (float): reward for taking this action
                - terminated (bool): True if we transition to the final state (exit)
                - truncated (bool): True if the episode is end because time step is exceeded
                - info (dict): information
        """

        # init
        terminated = False   # mark an end of an episode (not used)
        truncated  = False   # an episode is truncated when it reach a max. step

        # reward vector: at index 0 is for the command
        reward = [0.0, 0.0]
        info   = {}

        # perf0 threshold, set by the constant
        perfThreshold = self.perfThreshold
        riskLevelThreshold = self.riskLevelThreshold

        # get the current state of the environment from the observation
        riskLevel = np.argmax(obs[-13:-8]) # risk is encoded as a one-hot vector of dim. (5,)
        cmdExecStateValue = self.getCommandExecStateValue(obs[-8:-6]) # cmd exec state is encoded as one-hot of dim. (2,)
        avgCpuUsageNorm = obs[-6]
        avgMemUsageNorm = obs[-5]

        netInboundUsageNorm = obs[-4]
        netOutboundUsageNorm = obs[-3]

        blkReadNorm = obs[-2]
        blkWriteNorm = obs[-1]

        # get performance index from the passed values
        log.info("cpu: {cpu:0.5f}, mem: {mem:0.5f}, \
netin: {netin:0.5f}, netout: {netout:0.5f}, blkread: {blkread:0.5f}, blkwrite: {blkwrite:0.5f}",
                 cpu=avgCpuUsageNorm, mem=avgMemUsageNorm, netin=netInboundUsageNorm,
                 netout=netOutboundUsageNorm, blkread=blkReadNorm, blkwrite=blkWriteNorm)
        perf = self.getPerformanceIndex(avgCpuUsageNorm,
                                        avgMemUsageNorm,
                                        netInboundUsageNorm,
                                        netOutboundUsageNorm,
                                        blkReadNorm,
                                        blkWriteNorm)

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
        curPerfIdx = self.normalizeReward(perf, perfThreshold)
        log.info(f"perf. threshold: {perfThreshold:0.3f}, perf: {perf:0.3f}, current perf. index: {curPerfIdx:0.3f}")

        # command is not yet executed
        if cmdExecStateValue == self.COMMAND_EXEC_STATE_START_VALUE:
            if markovState == self.MARKOV_STATE_TERMINAL:
                terminated = True
            else:
                rewardByCmdName = self.rewardByCommandName(markovState, cmdName, action, curPerfIdx)
                rewardByRiskLevel = self.rewardByRiskLevel(action,
                                                           curPerfIdx,
                                                           riskLevel, riskLevelThreshold)
                # we take the max if both rewards are positive
                if rewardByCmdName > 0 or rewardByRiskLevel > 0 :
                    # reward is (0, 1]
                    reward[0] = max(rewardByCmdName, rewardByRiskLevel)
                else:
                    # reward is [-1, 0)
                    reward[0] = min(rewardByCmdName, rewardByRiskLevel)

        # the command is already executed, it becomes a process
        if cmdExecStateValue == self.COMMAND_EXEC_STATE_RUNNING_VALUE:
            reward[1] = self.rewardByPerformance(action, curPerfIdx)

        return reward, terminated, truncated, info

    def rewardByCommandName(self, markovState: str,
                            cmdName: str,
                            action: int,
                            curPerfIdx: float)->float:
        """
        Caculate reward by using command name as a basis.

        Args:
            markovState (str): current markov state if the command is known
            cmdName (str): name of the command
            action (int): action taken by the agent
            curPerfIdx (float): current performance index

        Returns:
            reward (float): reward based the risk level and performance index
            terminated (bool): True if it is a terminal state
        """
        reward = 0.

        # reward by command type
        if markovState == self.MARKOV_STATE_CUSTOM:
            # if the current perf is less than perf0.
            if curPerfIdx >= 0:
                if  action == self.ACTION_ALLOW:
                    # the reward is between [0,1]
                    reward = max(0, curPerfIdx)
                else:
                    reward = 0.
            # if the current perf is greater than perf0
            else:
                if action == self.ACTION_ALLOW:
                    # the reward is between [-1,0), if the current
                    # perf is greater than the set perf0.
                    reward = min(curPerfIdx, 0)
                else:
                    reward = 0.

        elif markovState == self.MARKOV_STATE_COMMAND:
            # regardless of current performance index
            if cmdName in common.DOWNLOAD_COMMANDS:
                if action == self.ACTION_ALLOW:
                    reward = 1.0
                else:
                    reward = 0.
            else:
                reward = 0.0
        else:
            # other unknown commands
            reward = 0.0

        return reward

    def rewardByRiskLevel(self, action: int,
                          curPerfIdx: float, riskLevel: float,
                          riskLevelThreshold: float)->float:
        """
        Caculate reward by using risk level as a basis.

        Args:
            action (int): action taken by the agent
            curPerfIdx (float): current performance index
            riskLevel (float): current risk level
            riskLevelThreshold (float): risk level threshold as set in the config.

        Returns:
            reward (float): reward based the risk level and performance index
        """

        reward = 0.0

        if riskLevel >= riskLevelThreshold:
            if curPerfIdx >= 0:
                if action == self.ACTION_ALLOW:
                    # the reward is between [0,1]
                    reward = max(0, curPerfIdx)
                else:
                    reward = 0.
            else:
                if action == self.ACTION_ALLOW:
                    # the reward is between [-1,0), if the current
                    # perf is greater than the set perf0.
                    reward = min(curPerfIdx, 0)
                else:
                    reward = 0.
        else: # riskLevel < riskLevelThreshold:
            if curPerfIdx >= 0:
                if action == self.ACTION_ALLOW:
                    # the reward is between [0,1]
                    reward = max(0, curPerfIdx)
                else:
                    reward = 0.
            else:
                if action == self.ACTION_ALLOW:
                    # the curPerfIdx is negative, so the reward is positive (0, 1]
                    # for commands whose riskLevel < riskLevelThreshold.
                    # Encourage the execution of low risk commands
                    reward = -min(curPerfIdx, 0)
                else:
                    reward = 0.

        return reward

    def rewardByPerformance(self, action: int,
                            curPerfIdx: float)->float:
        """
        Caculate reward by using risk level as a basis.

        Args:
            action (int): action taken by the agent
            curPerfIdx (float): current performance index

        Returns:
            reward (float): reward based the risk level and performance index
        """

        reward = 0.

        # if the current perf is less than (<) perf0
        if curPerfIdx >= 0:
            if action == self.ACTION_NOP:
                reward = max(0, curPerfIdx)
            elif action == self.ACTION_TERMINATE:
                reward = -max(0, curPerfIdx)
        # if the current perf is greater than (>) perf0
        else:
            if action == self.ACTION_NOP:
                reward = min(curPerfIdx, 0)
            elif action == self.ACTION_TERMINATE:
                reward = -min(curPerfIdx, 0)

        return reward
