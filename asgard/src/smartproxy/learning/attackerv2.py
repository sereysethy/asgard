# -*- coding: utf-8 -*-

"""
Attack simulator v2
- real attacks based on CVE
- Metasploit
- Markov Decision Process
"""

import os
import json
import numpy as np

from twisted.python import log

from smartproxy.learning.environment.env import BaseEnv

from smartproxy.learning.monitor import Monitor
from smartproxy.utils import common
from smartproxy.utils import utils

class AttackerEmulatorV2():
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
			- if allowed, continue to the next command
			- if blocked then terminate the session
			- if substituted the continue to the next command
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
