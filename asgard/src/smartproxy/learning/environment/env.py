# -*- coding: utf-8 -*-
from typing import Tuple
from twisted.internet import defer
from twisted.python import log

import gymnasium as gym
import numpy as np
import requests

from cowrie.core.config import CowrieConfig
from smartproxy.learning.preprocess import load_all_commands, load_user_commands
from smartproxy.learning.monitor import Monitor
from smartproxy.learning.environment.utils import check_options

NUMBER_ACTION = 2
NUMBER_FEATURE = 5
NUMBER_COMMAND = 100

class BaseEnv(gym.Env):
    """
    Base environment class which inherits :class:`gymnasium.Env`.
    """

    STATE_COMMAND_TYPE = [
            'command_type_command',
            'commandsubstitution',
            'assignment',
            'pipeline',
            'processsubstitution',
            'list',
            'compound',
            'operator'
        ]
    STATE_COMMANDS = []

    # CUSTOM_COMMANDS = ['custom', 'bash', 'perl', 'sh', 'nohup']
    CUSTOM_COMMANDS = ['custom']
    EMPTY_COMMANDS = ['enter', 'Enter']
    TERMINAL_COMMANDS = ['exit']
    UNKNOWN_COMMANDS = ['unknown']

    EMPTY_COMMAND_IX = None
    EXIT_COMMAND_IX = None
    CUSTOM_COMMAND_IX = None
    UNKNOWN_COMMAND_IX = None

    name = 'base'
    total_command = 0

    BASH_STATUS_OK = 0
    # All builtins return an exit status of 2 to indicate incorrect usage
    BASH_STATUS_BUILTIN_CMD_ERROR = 2

    BASH_STATUS_CMD_NOT_FOUND = 127
    BASH_STATUS_CMD_FOUND_NO_EXEC = 126

    # 128+n if the command was terminated by signal n.
    BASH_STATUS_CMD_SIGKILL = 137
    BASH_STATUS_CMD_SIGINT = 143

    MARKOV_STATE_COMMAND = "__MARKOV_STATE_COMMAND__"
    MARKOV_STATE_EMPTY = "__MARKOV_STATE_EMPTY__"
    MARKOV_STATE_CUSTOM = "__MARKOV_STATE_CUSTOM__"
    MARKOV_STATE_TERMINAL = "__MARKOV_STATE_TERMINAL__"
    MARKOV_STATE_UNKNOWN = "__MARKOV_STATE_UNKNOWN__"

    call_once = False

    def __init__(self, action_size, observation_size, name=None):
        self.action_size = action_size
        self.observation_size = observation_size

        self.prepare_command_list()

        if name:
            self.name = name
        log.msg('using environment: ', self.name)

    @property
    def observation_space(self):
        return gym.spaces.Box(low=-np.inf, high=np.inf, shape=(self.observation_size, ), dtype=np.float32)

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

    def commandNameToCommandIndex(self, basename:str, execCmd:str)->int:
        """Return index which corresponds to the cmd name.

        Args:
            basename string: name no path 'command'
            execCmd string: name including path if any '/path/to/command'

        Returns:
            command index (int): index of the corresponding command
        """

        exec_commands = [
            "perl", "python", "python2", "python3", "php", "ruby",
            "node", "python2.7", "python3.3", "python3.6", "python3.6m",
            "python3.7", "python3.7m", "php7.2", "java", "jar", "nice", "renice"
        ]

        # this is a mild assumption that all custom commands in this form
        # ./, we can turn it to else part, to treat everything else as custom
        if len(execCmd) >= 3 and execCmd[0] == '.' and execCmd[1] == '/':
            return self.CUSTOM_COMMAND_IX
        elif basename in exec_commands:
            return self.CUSTOM_COMMAND_IX
        elif self.is_exec_shell(basename, execCmd):
            return self.CUSTOM_COMMAND_IX
        elif self.is_nohup(basename, execCmd):
            return self.CUSTOM_COMMAND_IX

        if basename in self.COMMAND_TO_IX:
            # some commands have names like the one in the system
            # ex: ./x86_64 but it starts with a "./" so we can assume
            # it is downloaded from external servers
            if len(execCmd) >= 3 and execCmd[0] == '.' and execCmd[1] == '/':
                return self.CUSTOM_COMMAND_IX
            else:
                return self.COMMAND_TO_IX[basename]

        if basename in self.EMPTY_COMMANDS:
            # it can contain something else too, will be added later
            return self.EMPTY_COMMAND_IX

        if basename == "exit_":
            return self.COMMAND_TO_IX["exit"]

        log.msg('Unknown basename: {}, exec cmd: {}, ', basename, execCmd)
        return self.UNKNOWN_COMMAND_IX

    def is_exec_shell(self, basename: str, execCmd:str)->bool:
        """
        This function check if a program uses shell to launch a program or
        a shell script "sh script".

        Args:
            basename (str): basename of a command
            execCmd(str): a command

        Returns:
            True if the command is an exec.
        """

        shells = ["bash", "sh", "dash", "csh", "ksh"]

        is_exec = False
        option_match = False
        if basename in shells:
            tokens = execCmd.split()
            # skip the command name
            for arg in tokens[1:]:
                if not option_match and arg == "-c":
                    option_match = True
                elif option_match and arg not in self.COMMAND_TO_IX:
                    print("arg 1: ", arg)
                    is_exec = True
                elif not option_match and not check_options(arg):
                    print("arg 2: ", arg)
                    is_exec = True

        return is_exec

    def is_nohup(self, basename: str, execCmd: str)->bool:
        """
        This function check if a program uses nohup to launch a program or
        a shell script "nohup ./program".

        Args:
            basename (str): basename of a command
            execCmd(str): a command

        Returns:
            True if the command is an exec.
        """

        is_exec = False
        if basename == "nohup":
            tokens = execCmd.split()
            # skip the command name
            for arg in tokens[1:]:
                if not check_options(arg) and not arg.startswith('>') and arg.startswith('./'):
                    is_exec = True
                    break
                if not check_options(arg) and not arg.startswith('>') and arg.startswith('/'):
                    is_exec = True
                    break
                if not check_options(arg) and not arg.startswith('>'):
                    is_exec = True
                    break

        return is_exec

    def commandIndexToMarkovState(self, cmdIndex:int):
        """Map a command index to its name."""

        if cmdIndex == self.CUSTOM_COMMAND_IX:
            cmdName = "custom"
        elif cmdIndex == self.EMPTY_COMMAND_IX:
            cmdName = "empty"
        #elif cmdIndex == self.EXIT_COMMAND_IX:
        #    cmdName = "exit"
        elif cmdIndex == self.UNKNOWN_COMMAND_IX:
            cmdName = "unknown"
        else:
            # if it is a normal command, return its name
            cmdName = self.COMMANDS[cmdIndex]

        # print(f"cmdName: {cmdName}/{cmdIndex}")

        return self.commandNameToMarkovState(cmdName)

    def commandNameToMarkovState(self, basename:str):
        """Map command index to its Markov state.

        Args:
            basename: is the command name, no path
        """

        if basename in self.COMMAND_TO_IX and \
            basename not in self.TERMINAL_COMMANDS and \
                basename not in self.CUSTOM_COMMANDS:
            return self.MARKOV_STATE_COMMAND
        elif basename in self.EMPTY_COMMANDS:
            return self.MARKOV_STATE_EMPTY
        elif basename in self.TERMINAL_COMMANDS:
            return self.MARKOV_STATE_TERMINAL
        elif basename in self.CUSTOM_COMMANDS:
            return self.MARKOV_STATE_CUSTOM
        else:
            log.msg('unknown: ', basename)
            return self.MARKOV_STATE_UNKNOWN

    def isTerminal(self, basename:str)->bool:
        """
        Check if the basename is a terminal state.
        
        Args:
            basename: command basename

        Returns:
            `True` is basename is a terminal state otherwise `false`.
        """
        if basename in self.STATE_TERMINAL:
            return True
        else:
            return False

    def make_dummy_obs(self):
        raise NotImplementedError

    def make_obs(self):
        raise NotImplementedError

    def step(self, action):
        """
        Takes an action for the current state and observe a reward.
        """
        assert self.action_space.contains(action), "%r (%s) invalid"%(action, type(action))

        done = False

        # reward only if attacker inputs another command otherwise 0
        # if attacker inputs another command, reward +1
        # if cpu, mem, io_face > a threashold, reward -1

        # command_ix = np.random.randint(low=0, high=len(self.command_list), dtype=int)
        command_ix = self.command_to_ix[self._execcmd]
        command_arr = np.array([command_ix])
        param_arr = np.random.uniform(-1, 1, size=(4,))
        self._state = np.concatenate((command_arr, param_arr))

        """
        Execute the command through Shell
        Wait for the next command
        If the next command does not exit, return the next command and false for done
        Else return exit and true for done
        """
        if self._execcmd == 'curl' or self._execcmd == 'wget':
            reward = 1
        else:
            reward = 0

        if self.command_list[command_ix] == 'exit':
            reward = 0
            done = True

        return np.copy(self._state), reward, done, {}

    def reset(self):
        """
        return a new/initial observation when attacker is disconnected or
        a session ended when attacker input 'exit'
        """
        self._execcmd = None
        return np.array([0, 0, 0, 0, 0])

    def close(self):
        return True

class SimulatedBotEnv1(BaseEnv):
    ACTION_ALLOW = 0
    ACTION_BLOCK  = 1
    name = 'SimulatedBotEnv1'

    """
    This env is a simuated env which contain only one observation space -
    a command input.
    """
    def __init__(self, action_size, observation_size):
        BaseEnv.__init__(self, action_size, observation_size)

    def makeObs(self):
        """
        This function will return an one observation which is the command
        """
        command_ix = self.commandToIndex(self._execcmd)
        self._state = np.array([command_ix])
        return np.copy(self._state)

    def reset(self):
        self._execcmd = None
        return np.array([0])

    def step(self, action):
        """
        this env will reward agent whenever a custom command is executed.
        if an exit command is tried, agent will be rewarded -1
        """
        done   = False
        reward = 0
        info   = {}

        info["status"] = 1

        if self._execcmd in self.STATE_TERMINAL:
            done = True

        # only we allow it and it is a custom
        if action == self.ACTION_ALLOW:
            if self._execcmdIndex == self.CUSTOM_COMMAND_IX:
                reward = 1

            info["status"] = 0
        # block, we supposed that session would end if we block an execution
        elif action == self.ACTION_BLOCK:
            done = True

        return np.copy(self._state), reward, done, info

class SimulatedBotEnv2(SimulatedBotEnv1):
    ACTION_ALLOW = 0
    ACTION_BLOCK  = 1
    name = 'SimulatedBotEnv2'

    """
    This env is a simuated env which contain only one observation space -
    a command input.
    """
    def step(self, action):
        """
        this env will reward agent whenever a custom command is executed.
        if an exit command is tried, agent will be rewarded -1
        """
        done   = False
        reward = 0
        info   = {}

        info["status"] = 1

        if self._execcmd in self.STATE_TERMINAL:
            done = True

        # only we allow it and it is a custom
        if action == self.ACTION_ALLOW:
            if self._execcmdIndex == self.CUSTOM_COMMAND_IX:
                reward = 1

            info["status"] = 0
        # block, we supposed that session would end if we block an execution
        elif action == self.ACTION_BLOCK:
            if np.random.randint(2):
                done = True
            else:
                done = False

        return np.copy(self._state), reward, done, info

class AttackerEnv(BaseEnv):

    # different actions available
    ACTION_ALLOW        = 0
    ACTION_BLOCK         = 1
    ACTION_SUBSTITUTE   = 2
    ACTION_TERMINATE    = 3
    ACTION_IDLE         = 4

    """
    `C`    start to execute
    `D`    uninterruptible sleep (usually IO)
    `R`    running or runnable (on run queue)
    `S`    interruptible sleep (waiting for an event to complete)
    `T`    stopped by job control signal
    `t`    stopped by debugger during the tracing
    `W`    paging (not valid since the 2.6.xx kernel)
    `X`    dead (should never be seen)
    `Z`    defunct (“zombie”) process, terminated but not reaped by its parent
    """
    COMMAND_EXEC_STATE_C = 0
    COMMAND_EXEC_STATE_D = 1
    COMMAND_EXEC_STATE_R = 2
    COMMAND_EXEC_STATE_S = 3
    COMMAND_EXEC_STATE_T = 4
    COMMAND_EXEC_STATE_t = 5
    COMMAND_EXEC_STATE_W = 6
    COMMAND_EXEC_STATE_X = 7
    COMMAND_EXEC_STATE_Z = 8
    COMMAND_EXEC_STATE_I = 9

    COMMAND_STATES = {
        'C': COMMAND_EXEC_STATE_C,
        'D': COMMAND_EXEC_STATE_D,
        'R': COMMAND_EXEC_STATE_R,
        'S': COMMAND_EXEC_STATE_S,
        'T': COMMAND_EXEC_STATE_T,
        't': COMMAND_EXEC_STATE_t,
        'W': COMMAND_EXEC_STATE_W,
        'X': COMMAND_EXEC_STATE_X,
        'Z': COMMAND_EXEC_STATE_Z,
        'I': COMMAND_EXEC_STATE_I
    }

    def __init__(self, container_name):
        BaseEnv.__init__(self, action_size=5, observation_size=5, name="AttackerEnv-v0")
        self.monitor = Monitor(container_name=container_name)

        self.riskFactor = 0

        self.init_thresh_hold()

    def init_thresh_hold(self):
        """Initialise the minimum threshold of system env."""

        self.memory_min = CowrieConfig().getint('monitor', 'memory_min', fallback=10000)
        self.network_rcv_min = CowrieConfig().getint('monitor', 'network_rcv_min', fallback=10000)
        self.network_trx_min = CowrieConfig().getint('monitor', 'network_trx_min', fallback=10000)

    def command_state_to_ix(self, cmd_state):
        """Return a command state index based on command state symbold.

        cmdState: a symbol representing command state in process table
        """
        return self.COMMAND_STATES[cmd_state]

    def make_dummy_obs(self, execcmd: str, cmdExecState: str):
        """Make a dummy observation for debug."""

        _state = np.zeros(self.observation_size)

        _state[0] = self.commandNameToCommandIndex(execcmd)
        _state[1] = self.command_state_to_ix(cmdExecState)
        return np.copy(_state)

    def make_obs(self, basename: str, execCmd: str, cmdExecState: str) -> np.array:
        """construct an observation.

        execcmd: command to use in an observation
        cmdState: a letter representing command state
        """

        # wrap it in maybeDeferred in case of a debug is enabled so that we
        # still get a result
        d = defer.maybeDeferred(self.monitor.requestStats)
        d.addCallback(self._cbProcessStat, basename, execCmd, cmdExecState)
        d.addErrback(self._ebProcessStat, basename, execCmd, cmdExecState)
        return d

    def _cbProcessStat(self, stats, basename: str, execCmd: str, cmdExecState:str):
        """It will handle when monitor returns a statistics of the target machine."""

        cmdExecStateIndex = self.command_state_to_ix(cmdExecState)
        command_ix = self.commandNameToCommandIndex(basename, execCmd)
        _state = np.array([command_ix,
                                cmdExecStateIndex,
                                stats['memory'],
                                stats['network_rcv'],
                                stats['network_trx']])
        return _state

    def _ebProcessStat(self, failure, basename: str, execCmd:str, cmdExecState: str):
        """It will handle when a monitor encounter a problem."""
        return failure

    def getCommandState(self, state):
        """
        state is a symbol representing command state in process table
        """
        return self.COMMAND_STATES[state]

    def getActionName(self, action):
        if action == self.ACTION_ALLOW:
            return "ACTION_ALLOW"
        elif action == self.ACTION_BLOCK:
            return "ACTION_BLOCK"
        elif action == self.ACTION_SUBSTITUTE:
            return "ACTION_SUBSTITUTE"
        elif action == self.ACTION_TERMINATE:
            return "ACTION_TERMINATE"
        elif action == self.ACTION_IDLE:
            return "ACTION_IDLE"
        else:
            return "UNKNOWN_ACTION"

    def step(self, obs, action:int) -> Tuple[float, bool, dict]:
        """Return a reward given a current state of the observation.

        Reward system:
        - 1: when a custom command is executed.
        - 0: exit command is tried
        - 1: when a container is compromised which is characterised by an
        increasing consumption of memory, network read and network write
        """

        done   = False
        reward = 0.0
        info   = {}

        _execmdIndex = obs[0].astype(int)
        _cmd_exec_state_index = obs[1]
        _memory = obs[2]
        _network_rcv = obs[3]
        _network_trx = obs[4]

        _markov_state = self.map_command_ix_to_name(_execmdIndex)
        print(f"cmd ix: {_execmdIndex} to _markov_state: {_markov_state}")
        # Action: allow
        if action == self.ACTION_ALLOW:
            info['status'] = self.BASH_STATUS_OK

        # Action: block
        if action == self.ACTION_BLOCK:
            info['status'] = self.BASH_STATUS_CMD_NOT_FOUND

        # Action: substitute
        if action == self.ACTION_SUBSTITUTE:
            info['status'] = self.BASH_STATUS_OK

        # Action: terminate
        if action == self.ACTION_TERMINATE:
            pass

        # Action: idle
        if action == self.ACTION_IDLE:
            pass

        # reward setting for each attacker input

        # when command is not in a runninig state
        if _cmd_exec_state_index == self.COMMAND_EXEC_STATE_C:
            if _markov_state == self.MARKOV_STATE_CUSTOM:
                reward = 1.0
            elif _markov_state == self.MARKOV_STATE_COMMAND:
                reward = 0.01
            elif _markov_state in self.MARKOV_STATE_TERMINAL:
                done = True

        # when command is any other state
        # use these threashold as a gauge:
        # increasing consumption of memory, network read and network write
        if _cmd_exec_state_index != self.COMMAND_EXEC_STATE_C:
            if _memory > self.memory_threshold:
                reward = -1.0

            if _network_rcv > self.network_rcv_threshold:
                reward = -1.0

            if _network_trx > self.network_trx_threshold:
                reward = -1.0

        return reward, done, info

    @property
    def memory_threshold(self):
        return self.memory_min

    @property
    def network_rcv_threshold(self):
        if self.riskFactor == 0:
            return 50000
        elif self.riskFactor == 1:
            return 40000
        elif self.riskFactor == 2:
            return 30000
        elif self.riskFactor == 3:
            return 10000
        elif self.riskFactor == 4:
            return 10000

    @property
    def network_trx_threshold(self):
        if self.riskFactor == 0:
            return 50000
        elif self.riskFactor == 1:
            return 40000
        elif self.riskFactor == 2:
            return 30000
        elif self.riskFactor == 3:
            return 10000
        elif self.riskFactor == 4:
            return 10000