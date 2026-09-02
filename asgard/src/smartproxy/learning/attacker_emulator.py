# -*- coding: utf-8 -*-
"""A module-level docstring

Notice the comment above the docstring specifying the encoding.
Docstrings do appear in the bytecode, so you can access this through
the ``__doc__`` attribute. This is also what you'll see if you call
help() on a module or any other Python object.
"""
import os
import json
from typing import Tuple
import numpy as np

from twisted.python import log

from smartproxy.learning.environment import BaseEnv

from smartproxy.learning.monitor import Monitor

class AttackerEmulator(BaseEnv):
    STATE_INIT = 0
    STATE_CONTINUED = 1
    STATE_BLOCKED = 2
    STATE_TERMINATED = 3

    ACTION_ALLOW = 0
    ACTION_BLOCK = 1
    ACTION_SUBSTITUTE = 2
    ACTION_TERMINATE = 3
    ACTION_NOOP = 4

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

    loaded = False
    riskFactor = 0

    def __init__(self, container_name):
        BaseEnv.__init__(self, action_size=3,
                            observation_size=6,
                            name="FakeAttackerEmulator-v0")

        self.episodes = []
        self.episodeIndex = 0
        self.commandIndex = 0

        self.monitor = Monitor(container_name=container_name)

        # its value will be set later when makeObs() is called
        self._commandState = None

    def initThreshhold(self):
        _stats = self.monitor.requestStats()
        self.start_memory = _stats['memory']
        self.start_network_rcv = _stats['network_rcv']
        self.start_network_trx = _stats['network_trx']

        log.msg('initial state of environment: ', _stats)

    def loadAttackEpisodes(self):
        """Load attacker episodes from files."""

        path_data = "data"
        episodeFiles = [
            "episodes_infosec_buffy.json",
            "episodes_infosec_daisy.json",
            "episodes_infosec_gabble.json",
            "episodes_infosec_rosy.json",
            ]

        for s in episodeFiles:
            self.episodes += [json.loads(line)['cowrie_command_input'] for line in open(os.path.join(path_data, "mongo", "out", s), 'r')]

        self.numberEpisodes = len(self.episodes) 
        loaded = True

    def commandStateToIndex(self, cmdState):
        """Return a command state index based on command state symbold.

        cmdState: a symbol representing command state in process table
        """
        return self.COMMAND_STATES[cmdState]

    def makeObs(self, execcmd: str, cmdExecState: str) -> np.array:
        """construct an observation.

        execcmd: command to use in an observation
        cmdState: a letter representing command state
        """

        _currentStatistics = self.monitor.requestStats()
        cmdExecStateIndex = self.commandStateToIndex(cmdExecState)
        command_ix = self.commandToIndex(execcmd)
        _state = np.array([command_ix,
                                cmdExecStateIndex,
                                _currentStatistics['memory'], 
                                _currentStatistics['network_rcv'],
                                _currentStatistics['network_trx']])
        self._stats = _currentStatistics
        self._cmdExecStateIndex = cmdExecStateIndex
        self._execcmd = execcmd
        self._execcmd_ix = command_ix
        self._markovState = self.mapCommandToState(execcmd)
        return np.copy(_state)

    def reset(self) -> tuple:
        self._state = self.STATE_INIT

        if self.episodeIndex < self.numberEpisodes:
            self.commandIndex = 0
            self.currentEpisodeIndex = self.episodeIndex
            self.currentEpisode = self.episodes[self.episodeIndex]
            cmd = self.currentEpisode[self.commandIndex]
            self.currentEpisodeLenght = len(self.currentEpisode)
            self.episodeIndex += 1
            self.commandIndex += 1
            obs = self.makeObs(cmd, "C")
        else:
            obs = None

        return obs

    def nextCommand(self):
        cmd = None

        if self.commandIndex < self.currentEpisodeLenght:
            cmd = self.currentEpisode[self.commandIndex]
            self.commandIndex += 1
        
        return cmd

    def step(self, action: int) -> Tuple[str, int, bool, dict]:
        """Attacker fake behaviour.
        
        - command is allowed, continue to the next command
		- command is blocked, continue to the next command
			- if allowed, continue to the next command
			- if blocked then terminate the session
			- if substituted the continue to the next command
		- command is substituted, continue to the next command
        """

        done = False
        reward = 0
        obs = None
        info = dict()
        
        

        if action == self.ACTION_TERMINATE:
            pass

        if action == self.ACTION_NOOP:
            pass

        # how attacker will react next
        if self._state == self.STATE_INIT or self._state == self.STATE_BLOCKED:
            # send a new command if any
            cmd = self.nextCommand()
            if cmd:
                obs = self.makeObs(cmd, 'C')
            else:
                # otherwise terminate the session
                done = True
                obs = 'exit'
        
        if self._state == self.STATE_TERMINATED:
            # terminate the session
            done = True
            obs = 'exit'

        # reward setting for each attacker input
        # when command it not yet running
        if self._cmdExecStateIndex == self.COMMAND_EXEC_STATE_C:
            if self._markovState == self.MARKOV_STATE_CUSTOM:
                reward = 1
            elif self._markovState == self.MARKOV_STATE_COMMAND:
                reward = 0.01
            elif self._markovState in self.MARKOV_STATE_TERMINAL:
                done = True
        else:
            if self._stats['memory'] > self.memory_threshold:
                reward = -1

            if self._stats['network_rcv'] > self.network_rcv_threshold:
                reward = -1

            if self._stats['network_trx'] > self.network_trx_threshold:
                reward = -1

        # info setting

        return obs, reward, done, info

    
    @property
    def memory_threshold(self):
        return self.start_memory

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