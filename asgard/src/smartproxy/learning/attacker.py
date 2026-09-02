# -*- coding: utf-8 -*-

import os
import json
import numpy as np

from twisted.python import log

from smartproxy.learning.environment.env import BaseEnv

from smartproxy.learning.monitor import Monitor
from smartproxy.utils import common

class AttackerEmulator():
    """
    Using the algorithme that is similar to the one from Dowling thesis.

    - command is allowed, continue to the next command
    - command is blocked, continue to the next command
        - if the next command is allowed, continue to the next command
        - if the next command is blocked, terminate the session
        - if the next command is substituted, continue to the next command
    - command is substituted, continue to the next command
    """
    STATE_CONTINUE = 0
    STATE_BLOCK = 1
    STATE_TERMINATE = 2

    ACTION_ALLOW = 0
    ACTION_BLOCK = 1
    ACTION_SUBSTITUTE = 2

    loaded = False

    def __init__(self):
        self._init()

    def _init(self):
        self.episodes = []
        self.episodeIndex = 0
        self.commandIndex = 0
    
    def loadAttackEpisodesByFilename(self, filename):
        """Load attacker episode from filename."""

        self._init()

        try:
            with open(filename, 'r') as infile:
                for line in infile:
                    episode = json.loads(line)
                    episode['filename'] = filename
                    self.episodes.append(episode)
            self.numberEpisodes = len(self.episodes) 
            self.loaded = True
        except json.decoder.JSONDecodeError as e:
            log.msg(e)

    def loadAttackEpisodes(self):
        """Load attacker episodes from a pre-defined filenames."""

        self._init()

        path_data = "data"
        episodeFiles = [
            "episodes_infosec_buffy.json",
            "episodes_infosec_daisy.json",
            "episodes_infosec_gabble.json",
            "episodes_infosec_rosy.json",
            ]

        try:
            for s in episodeFiles:
                with open(os.path.join(path_data, "mongo", "out_replaced", s), 'r') as infile:
                    for line in infile:
                        episode = json.loads(line)
                        episode['filename'] = s
                        self.episodes.append(episode)
            self.numberEpisodes = len(self.episodes) 
            self.loaded = True
        except json.decoder.JSONDecodeError as e:
            log.msg(e)

    def loadTestAttackEpisodes(self):
        """Load test attack episodes from a pre-defined filename."""

        self._init()

        path_data = "data"
        episodeFiles = [
            "single_case.json"
            ]

        try:
            for s in episodeFiles:
                with open(os.path.join(path_data, "test", s), 'r') as infile:
                    for line in infile:
                        episode = json.loads(line)
                        episode['filename'] = s
                        self.episodes.append(episode)
            self.numberEpisodes = len(self.episodes) 
            self.loaded = True
        except json.decoder.JSONDecodeError as e:
            log.msg(e)

    def setEpisodeIndex(self, i):
        self.episodeIndex = i

    def reset(self) -> tuple:
        self._state = self.STATE_CONTINUE

        if self.episodeIndex < self.numberEpisodes:
            self.commandIndex = 0
            self.currentEpisodeIndex = self.episodeIndex
            self.currentEpisode = self.episodes[self.episodeIndex]
            
            self.currentEpisodeLength = len(self.currentEpisode['cowrie_command_input'])
            self.episodeIndex += 1
            return False, self.episodeIndex, self.currentEpisode

        return True, -1, {}

    def resetUsingCommandList(self) -> tuple:
        self._state = self.STATE_CONTINUE

        if self.episodeIndex < self.numberEpisodes:
            self.commandIndex = 0
            self.currentEpisodeIndex = self.episodeIndex
            self.currentEpisode = self.episodes[self.episodeIndex]
            
            self.currentEpisodeLength = len(self.currentEpisode['command_list'])
            self.episodeIndex += 1
            return False, self.episodeIndex, self.currentEpisode

        return True, -1, {}

    def getCredential(self):
        credential = self.currentEpisode["cowrie_login_success"]

        return credential["username"], credential["password"]

    def nextCommand(self):
        cmd = None

        # how attacker will react next
        if self._state == self.STATE_CONTINUE or self._state == self.STATE_BLOCK:
            # send a new command if any
            if self.commandIndex < self.currentEpisodeLength:
                cmd = self.currentEpisode['cowrie_command_input'][self.commandIndex]
                self.commandIndex += 1

            if cmd == 'exit':
                done = True

            if cmd == "":
                return self.nextCommand()
            
            if not cmd:
                done = True
                cmd = 'exit_'
        
        if self._state == self.STATE_TERMINATE:
            # terminate the session
            done = True
            cmd = 'exit_'
        
        return cmd

    def nextCommandUsingCommandList(self):
        cmd = None

        # how attacker will react next
        if self._state == self.STATE_CONTINUE or self._state == self.STATE_BLOCK:
            # send a new command if any
            if self.commandIndex < self.currentEpisodeLength:
                cmd = self.currentEpisode['command_list'][self.commandIndex]
                self.commandIndex += 1

            if cmd == 'exit':
                done = True

            if cmd == "":
                return self.nextCommandUsingCommandList()
            
            if not cmd:
                done = True
                cmd = 'exit_'
        
        if self._state == self.STATE_TERMINATE:
            # terminate the session
            done = True
            cmd = 'exit_'
        
        return cmd

    def step(self, action: int, obs: None):
        """Attacker fake behaviour.
        
        - command is allowed, continue to the next command
		- command is blocked, continue to the next command
			- command is allowed, continue to the next command
			- command is blocked then terminate the session
            - command is substituted, continue to the next command
		- command is substituted, continue to the next command
        """
        
        # how attacker will react
        if action == self.ACTION_ALLOW:
            self._state = self.STATE_CONTINUE

        if action == self.ACTION_BLOCK:
            if self._state == self.STATE_CONTINUE:
                self._state = self.STATE_BLOCK

            elif self._state == self.STATE_BLOCK:
                self._state = self.STATE_TERMINATE

        if action == self.ACTION_SUBSTITUTE:
            self._state = self.STATE_CONTINUE

class HelizaAttacker(AttackerEmulator):
    """
    Try to build attack behaviour by combining the state transition probabilities
    collected from Heliza dataset. But the dataset is not complete.

    Here how we proceed:

    - Build command transition probabilities
    - Based on that command transitions, attacker chooses what to do next:
        - submit next command
        - terminate the session
    - If command did not fall to any command transitions, we proceed as in the
    fake botnet
        - command is allowed, continue to the next command
        - command is block, continue to the next command
            - the next command is blocked again, terminate session
            - the next command is allowed, continue to the next command
            - the next command is substituted, continue to the next command
        - command is substituted, continue to the next command
    """

    STATE_INSULT = 4

    ACTION_INSULT = 3

    CMD_AFTER_INSULT = ["exit", "ls", "cd", 
                        "uname", "ps", "last",
                        "wget", "id", "w", 
                        "others"]

    NUMBER_COMMANDS = 10 # len(CMD_AFTER_INSULT)

    PROBABILITY_DIST = [
        0.1577,
        0.1116,
        0.0995,
        0.0582,
        0.0582,
        0.0509,
        0.0461,
        0.0436,
        0.0436,
        0.3306
    ]

    def setEnv(self, env):
        self.env = env

    def nextCommandUsingCommandList(self):
        cmd = None

        # how attacker will react next
        if self._state == self.STATE_CONTINUE or self._state == self.STATE_BLOCK:
            # send a new command if any
            if self.commandIndex < self.currentEpisodeLength:
                cmd = self.currentEpisode['command_list'][self.commandIndex]
                self.commandIndex += 1

            if cmd == 'exit':
                done = True

            if cmd == "":
                return self.nextCommandUsingCommandList()
            
        if not cmd:
            done = True
            cmd = 'exit_'
        
        # if self._state == self.STATE_INSULT:
        #     choice = np.random.choice(NUMBER_COMMANDS, 1, p=PROBABILITY_DIST)

        if self._state == self.STATE_TERMINATE:
            # terminate the session
            done = True
            cmd = 'exit_'
        
        return cmd

    def getAction(self, action):
        if action == "allow":
            return self.ACTION_ALLOW
        elif action == "block":
            return self.ACTION_BLOCK
        elif action == "substitute":
            return self.ACTION_SUBSTITUTE
        elif action == "insult":
            return self.ACTION_INSULT

    def step(self, action: int, obs: int):
        """Attacker fake behaviour.
        
        - command is allowed, continue to the next command
		- command is blocked, continue to the next command
			- if the next command is allowed, continue to the next command
			- if the next command is blocked, terminate the session
			- if substituted the continue to the next command
		- command is substituted, continue to the next command
        - command is insult, this is command attacker input next
            Command	Frequency
            exit	15.77
            ls	    11.16
            cd	    9.95
            uname	5.82
            ps	    5.82
            last	5.09
            wget	4.61
            Id	    4.36
            w	    4.36
            others	33.06
        """
        env = self.env
        e = self.currentEpisode

        cmdIndex = obs
        cmdName = env.ALL_COMMANDS[cmdIndex]
        markoveState = env.commandIndexToMarkovState(cmdIndex)

        actionByHeliza = self.currentEpisode["actions"][self.commandIndex - 1]
        actionIndexByHeliza = self.getAction(actionByHeliza)

        # reward setting for each attacker input

        if cmdName in common.HACKING_COMMANDS:
            if action != env.ACTION_ALLOW:
                self._state = np.random.choice([self.STATE_CONTINUE, self.STATE_TERMINATE], p=[0.8, 0.2])
            if action == actionIndexByHeliza:
                self._state = self.STATE_CONTINUE

        elif cmdName in common.DOWNLOAD_COMMANDS:
            if action != env.ACTION_ALLOW:
                self._state = np.random.choice([self.STATE_CONTINUE, self.STATE_TERMINATE], p=[0.1, 0.9])
            if action == actionIndexByHeliza:
                self._state = self.STATE_CONTINUE

        elif cmdName in common.ChangeFS:
            if action == env.ACTION_BLOCK:
                self._state = np.random.choice([self.STATE_CONTINUE, self.STATE_TERMINATE], p=[0.9, 0.1])
            if action == actionIndexByHeliza:
                self._state = self.STATE_CONTINUE

        elif cmdName in common.HARDWARE:
            if action == env.ACTION_BLOCK:
                self._state = np.random.choice([self.STATE_CONTINUE, self.STATE_TERMINATE], p=[0.9, 0.1])
            if action == actionIndexByHeliza:
                self._state = self.STATE_CONTINUE

        elif cmdName in common.SCRIPT:
            if action != env.ACTION_ALLOW:
                self._state = np.random.choice([self.STATE_CONTINUE, self.STATE_TERMINATE], p=[0.9, 0.1])
            if action == actionIndexByHeliza:
                self._state = self.STATE_CONTINUE

        elif cmdName in common.USER:
            if action == env.ACTION_BLOCK:
                self._state = np.random.choice([self.STATE_CONTINUE, self.STATE_TERMINATE], p=[0.9, 0.1])
            if action == actionIndexByHeliza:
                self._state = self.STATE_CONTINUE

        elif cmdName in common.FILESYS:
            if action == env.ACTION_BLOCK:
                self._state = np.random.choice([self.STATE_CONTINUE, self.STATE_TERMINATE], p=[0.9, 0.1])
            if action == actionIndexByHeliza:
                self._state = self.STATE_CONTINUE

        elif cmdName in common.INSTALL:
            if action != env.ACTION_ALLOW:
                self._state = np.random.choice([self.STATE_CONTINUE, self.STATE_TERMINATE], p=[0.1, 0.9])
            if action == actionIndexByHeliza:
                self._state = self.STATE_CONTINUE

        elif cmdName in common.PROCESS:
            if action == env.ACTION_BLOCK:
                self._state = np.random.choice([self.STATE_CONTINUE, self.STATE_TERMINATE], p=[0.9, 0.1])
            if action == actionIndexByHeliza:
                self._state = self.STATE_CONTINUE

        else:
            if action == self.ACTION_ALLOW:
                self._state = self.STATE_CONTINUE

            if action == self.ACTION_BLOCK:
                self._state = self.STATE_TERMINATE

            if action == self.ACTION_SUBSTITUTE:
                self._state = self.STATE_CONTINUE

            if action == self.ACTION_INSULT:
                self._state = self.STATE_CONTINUE

class DowlingAttackerEmulator():
    """
    Using the algorithme that was mentioned in Dowling thesis.

    - command is allowed, continue to the next command
    - command is blocked, continue to the next command
        - if next command is allowed, continue to the next command
        - if next command is blocked, terminate the session
        - if next command is substituted, continue to the next command
    - command is substituted
        - if two previous commands are substituted, terminate the session
        - otherwise continue to the next command
    """

    STATE_1 = 1
    STATE_2 = 2
    STATE_3 = 3
    STATE_4 = 4
    STATE_TERMINATE = 5

    ACTION_ALLOW = 0
    ACTION_BLOCK = 1
    ACTION_SUBSTITUTE = 2

    loaded = False

    def __init__(self):
        self._init()

    def _init(self):
        self.episodes = []
        self.episodeIndex = 0
        self.commandIndex = 0
    
    def loadAttackEpisodesByFilename(self, filename):
        """Load attacker episode from filename."""

        self._init()

        try:
            with open(filename, 'r') as infile:
                for line in infile:
                    episode = json.loads(line)
                    episode['filename'] = filename
                    self.episodes.append(episode)
            self.numberEpisodes = len(self.episodes) 
            self.loaded = True
        except json.decoder.JSONDecodeError as e:
            log.msg(e)

    def loadAttackEpisodes(self):
        """Load attacker episodes from a pre-defined filenames."""

        self._init()

        path_data = "data"
        episodeFiles = [
            "episodes_infosec_buffy.json",
            "episodes_infosec_daisy.json",
            "episodes_infosec_gabble.json",
            "episodes_infosec_rosy.json",
            ]

        try:
            for s in episodeFiles:
                with open(os.path.join(path_data, "mongo", "out_replaced", s), 'r') as infile:
                    for line in infile:
                        episode = json.loads(line)
                        episode['filename'] = s
                        self.episodes.append(episode)
            self.numberEpisodes = len(self.episodes) 
            self.loaded = True
        except json.decoder.JSONDecodeError as e:
            log.msg(e)

    def loadTestAttackEpisodes(self):
        """Load test attack episodes from a pre-defined filename."""

        self._init()

        path_data = "data"
        episodeFiles = [
            "single_case.json"
            ]

        try:
            for s in episodeFiles:
                with open(os.path.join(path_data, "test", s), 'r') as infile:
                    for line in infile:
                        episode = json.loads(line)
                        episode['filename'] = s
                        self.episodes.append(episode)
            self.numberEpisodes = len(self.episodes) 
            self.loaded = True
        except json.decoder.JSONDecodeError as e:
            log.msg(e)

    def setEpisodeIndex(self, i):
        self.episodeIndex = i

    def reset(self) -> tuple:
        self._state = self.STATE_1

        if self.episodeIndex < self.numberEpisodes:
            self.commandIndex = 0
            self.currentEpisodeIndex = self.episodeIndex
            self.currentEpisode = self.episodes[self.episodeIndex]
            
            self.currentEpisodeLength = len(self.currentEpisode['cowrie_command_input'])
            self.episodeIndex += 1
            return False, self.episodeIndex, self.currentEpisode

        return True, -1, {}

    def resetUsingCommandList(self) -> tuple:
        self._state = self.STATE_1

        if self.episodeIndex < self.numberEpisodes:
            self.commandIndex = 0
            self.currentEpisodeIndex = self.episodeIndex
            self.currentEpisode = self.episodes[self.episodeIndex]
            
            self.currentEpisodeLength = len(self.currentEpisode['command_list'])
            self.episodeIndex += 1
            return False, self.episodeIndex, self.currentEpisode

        return True, -1, {}

    def getCredential(self):
        credential = self.currentEpisode["cowrie_login_success"]

        return credential["username"], credential["password"]

    def nextCommand(self):
        cmd = None

        # how attacker will react next
        if self._state != self.STATE_TERMINATE:
            # send a new command if any
            if self.commandIndex < self.currentEpisodeLength:
                cmd = self.currentEpisode['cowrie_command_input'][self.commandIndex]
                self.commandIndex += 1

            if cmd == 'exit':
                done = True

            if cmd == "":
                return self.nextCommand()
            
            if not cmd:
                done = True
                cmd = 'exit_'
        
        if self._state == self.STATE_TERMINATE:
            # terminate the session
            done = True
            cmd = 'exit_'
        
        return cmd

    def nextCommandUsingCommandList(self):
        cmd = None

        # how attacker will react next
        if self._state != self.STATE_TERMINATE:
            # send a new command if any
            if self.commandIndex < self.currentEpisodeLength:
                cmd = self.currentEpisode['command_list'][self.commandIndex]
                self.commandIndex += 1

            if cmd == 'exit':
                done = True

            if cmd == "":
                return self.nextCommandUsingCommandList()
            
            if not cmd:
                done = True
                cmd = 'exit_'
        
        if self._state == self.STATE_TERMINATE:
            # terminate the session
            done = True
            cmd = 'exit_'
        
        return cmd

    def step(self, action: int, obs: None):
        """
        Malware fake behaviour.
        
        - command is allowed, continue to the next command
		- command is blocked, continue to the next command
			- if next command is allowed, continue to the next command
			- if next command is blocked, terminate the session
			- if next command is substituted, continue to the next command
		- command is substituted
            - if two previous commands are substituted, terminate the session
            - otherwise continue to the next command
        """
        
        # how attacker will react
        if action == self.ACTION_ALLOW:
            self._state = self.STATE_1

        if action == self.ACTION_BLOCK:
            if self._state != self.STATE_2:
                self._state = self.STATE_2
            elif self._state == self.STATE_2:
                self._state = self.STATE_TERMINATE

        if action == self.ACTION_SUBSTITUTE:
            if self._state == self.STATE_1:
                self._state = self.STATE_3
            elif self._state == self.STATE_2:
                self._state = self.STATE_3
            elif self._state == self.STATE_3:
                self._state = self.STATE_4
            elif self._state == self.STATE_4:
                self._state = self.STATE_TERMINATE