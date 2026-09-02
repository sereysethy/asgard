from typing import Tuple
import re
import shlex
import numpy as np
import torch

from twisted.python import log

# Cowrie
from cowrie.core.config import CowrieConfig

# Smart proxy
from smartproxy.command.shell_complex_parsing_exec import ShellComplexParsingForExec
import smartproxy.utils.utils as utils

from smartproxy.learning.rl.dqnlearner import DQNLearner
from smartproxy.learning.environment.roberta import RobertaEnvV10

class ShellRobertaExec(ShellComplexParsingForExec):
    """
    Class responsible for analyzing commands and delegating decisions to an agent in exec.

    This is for Asgard2.0.
    """

    # Environment, initialized later
    env: RobertaEnvV10

    # Learning agent, initialized later
    agent: DQNLearner

    def __init__(self, username:str=None, simulated:bool=False, exploration:bool=True):
        super().__init__(username, simulated, exploration) # type: ignore

        # add sample index to command to keep track of the command in the observation
        self.sample['cmd_index'] = []
        self.sample['terminated'] = []
        self.sample['truncateds'] = []
        self.sample['next_cmd_str'] = []
        self.sample['next_cmd_arg'] = []
        self.sample['count_actions'] = []

    def addAgentAndEnv(self, agent, env):
        """
        This function allows the protocol to pass the agent and the environment
        from factory.
        """

        # @override
        super().addAgentAndEnv(agent, env)

        self.device = self.agent.device
        self.sample['count_actions'] = [0 for i in range(self.env.action_size)]

    def _getAction(self, obs:list[float], cmd:str) -> int:
        """
        A wrapper function that will communicate with the agent to query new
        action given a state observation. Certain actions are masked because
        they do not apply for certain state observation.

        If the state observation that represents the command that is not yet
        executed, as a result only the actions: allow, block and substiute are
        applied. The action terminate and nop only apply for the executed
        commands and if they are still running for example as a daemon or in
        a background.

        Args:
            obs (Numpy.ndarray): state observation
            cmd (dict): represents the parsed command object.

        Returns:
            action (int): action index
        """

        # if the command is not yet executed
        if cmd['state'] == self.env.COMMAND_EXEC_STATE_START:
            # mask the action indexes for 'terminate' and 'nop'
            mask = [0,0,0,1,1]
        else:
            # mask the actions indexs for 'allow', 'block' and 'substitute'
            mask = [1,1,1,0,0]

        action = self.agent.getAction(obs, self.exploration, mask)

        # count the number of actions taken
        self.sample['count_actions'][action] += 1

        return action

    def _takeAction(self, cmd:dict, obs:np.ndarray, cmdIndex:int, action:int)->bool:
        """
        Take action by calling the function step of the environment which will
        return a reward, done and information.

        Args:
            cmd (dict): parsed command
            obs (np.array): numpy array
            cmdIndex (int): index of command in the commannds list
            action (int): action index

        Returns:
            The dictionary of what is return from the environent.
        """
        next_obs = None
        next_cmd_str = None
        next_arg = None
        next_basename = None
        next_cmd = None
        next_action = None
        next_reward = None
        next_done = None
        next_terminated = None
        next_truncated = None
        next_info = None
        next_cmd_index = None

        reward, terminated, truncated, info = self.env.step(obs, cmdIndex, action)

        template = 'take action: {} for command: {} ({}), reward: {}, \
reward vector: {}, terminated: {}, info: {}'
        log.msg(template.format(self.env.getActionName(action),
                                        cmd['basename'],
                                        cmd['cmd_str'],
                                        sum(reward),
                                        reward,
                                        terminated,
                                        info))

        # sum the vector reward to obtain a single reward
        reward = sum(reward)

        # truncated is always FALSE, we use it for future compatability of the gym env.
        done = terminated or truncated
        next_done = done

        if done:
            if cmd['basename'] != 'exit_' and not self.lastExperience:
                # next_obs is None
                self._pushSampleToMemory((obs, action, None, reward, terminated, info))
                previousSample = (obs, cmd['cmd_str'], cmd['basename'], action, reward, terminated, truncated, info, cmdIndex)
                self._saveExperience(previousSample, None, None)
            elif self.lastExperience:
                next_obs = obs
                (obs_, cmd_str_, basename_, action_, reward_, terminated_, truncated_, info_, cmdIndex_) = self.lastExperience

                # save the last experience along with the current experience
                previousSample = self.lastExperience
                self.lastExperience = None

                # save current obs, obs is next_obs
                self._pushSampleToMemory((obs_, action_, next_obs, reward_, terminated, info_))

                previousSample = (obs_, cmd_str_, \
                                        basename_, \
                                        action_, reward_, terminated, truncated,\
                                        info_, cmdIndex_)
                self._saveExperience(previousSample, cmd['cmd_str'], cmd['basename'])
        else:
            if not self.lastExperience:
                self.lastExperience = (obs, cmd['cmd_str'], cmd['basename'], action, reward, terminated, truncated, info, cmdIndex)
            else:
                (obs_, cmd_str_, basename_, action_, reward_, terminated_, truncated_, info_, cmdIndex_) = self.lastExperience

                next_obs = obs
                next_cmd_str = cmd['cmd_str']
                next_basename = cmd['basename']
                next_action = action
                next_reward = reward
                next_terminated = terminated
                next_truncated = truncated
                next_info = info
                next_cmd_index = cmdIndex

                # save the last experience along with the current experience
                previousSample = self.lastExperience
                self._saveExperience(previousSample, next_cmd_str, next_basename)
                self._pushSampleToMemory((obs_, action_, next_obs, reward_, terminated_, info_))

                # replace old experience by a current experience
                self.lastExperience = (next_obs, next_cmd_str, next_basename, next_action, \
                                        next_reward, next_terminated, next_truncated,\
                                        next_info, next_cmd_index)

        env = {
            "cmd_str": next_cmd_str,
            "action": next_action,
            "reward": next_reward,
            "done": next_done,
            "terminated": next_terminated,
            "truncated": next_truncated,
            "info": next_info
        }

        return env

    def _pushSampleToMemory(self, sample)->None:
        """wrapper class that will push sample to memory buffer of DQN

        Args:
            sample (tuple): containing sample to be added to memory buffer
        """

        self.agent.pushSampleToMemory(sample)

    def _saveExperience(self, previousSample: dict, next_cmd_str: str, next_basename: str)->None:
        (obs_, cmd_str, basename, action, reward, terminated, truncated, info, cmd_index) = previousSample
        self.sample["cmd_str"].append(cmd_str)
        self.sample["basenames"].append(basename)
        self.sample["actions"].append(action.tolist())
        self.sample["rewards"].append(reward)
        self.sample["terminated"].append(terminated)
        self.sample["truncateds"].append(truncated)
        self.sample["infos"].append(info)
        if next_cmd_str:
            self.sample["next_cmd_str"].append(next_cmd_str)
        if next_basename:
            self.sample["next_basenames"].append(next_basename)
        self.sample["cmd_index"].append(cmd_index)

    def _saveLastExperience(self)->None:
        """
        This is function is called when an attacker is disconnected abrupty
        like Ctrl+D. It is called in the super class function closeConnection()
        """

        if self.lastExperience:
            obs_, cmd_str_, basename_, action_, reward_, terminated_, truncated_, info_, cmdIndex_ = self.lastExperience
            self.lastExperience = None

            # we set this to True
            terminated_ = True

            self.sample["cmd_str"].append(cmd_str_)
            self.sample["basenames"].append(basename_)
            self.sample["actions"].append(action_.tolist())
            self.sample["rewards"].append(reward_)
            self.sample["terminated"].append(terminated_)
            self.sample["truncateds"].append(truncated_)
            self.sample["infos"].append(info_)
            self.sample["cmd_index"].append(cmdIndex_)

            # next obs is None and Done is set to true to mark as final state
            self._pushSampleToMemory((obs_, action_, None, reward_, terminated_, info_))

    def next(self):
        log.msg(f"next, self.index: {self.index}, len cmdpending: {len(self.cmdpending)}")
        if self.index < len(self.cmdpending):
            parsedcmd = self.cmdpending[self.index]
            self.index += 1
            log.msg('executing command index: {}'.format(parsedcmd))
            # this is used to indicate that we can start executing a new command;
            # this is re-init when there are multiple pipeline or compound commands
            self.startexec = True
            self.exec(parsedcmd)
        elif self.context:
            print("before restoring context")
            print("before previousOutputFile: ", self.previousOutputFile)
            print("before self.state: ", self.state)
            cmd = self._restoreContext()
            print("after self.state: ", self.state)
            print("after self.parentState: ", self.parentState)
            # state is not none indicates that we still need to execute sub-command
            # which is part of the parent command
            if self.state is None and self.index < len(self.cmdpending):
                cmd = self.cmdpending[self.index]
                self.index += 1
                log.msg(f'executing command context: {cmd}')
                self.exec(cmd)
            else:
                # if no more sub-command, we resume executing parent command
                # which we get when a context is restored
                log.msg(f'resuming executing command: {cmd}')
                self.exec(cmd)
        else:
            # close connection
            self.protocol.executeNextCommand()

    def _makeObs(self, rawCmd, basename, execCmd, cmdExecState)->Tuple[np.array, int]:
        """A wrapper function that will encode a command by calling a makeObs of
        the environment.

        Args:
            rawCmd (str): raw command as submitted by attacker
            basename (str): basename of the command
            execCmd (str): command in full path if any
            cmdExecState (str): the state of the command "Start to run" or
                "Running"

        Returns:
            tuple: A tuple containing:
                - Obs (np.array): A numpy array containing the encoded command and
                  the state of the target system.
                - cmdIndex (int): Command index in the command list.
        """

        return self.env.makeObs(rawCmd, basename, execCmd, cmdExecState)

    def exec(self, parsedcmd):
        """This function will execute a parsed command.
        """

        log.msg('start executing command: ', parsedcmd)

        t = parsedcmd['type']

        if t == 'command':
            pass
        elif t == 'commandsubstitution':
            return self._execCmd(parsedcmd)
        elif t == 'assignment':
            return self._execCmd(parsedcmd)
        elif t == 'pipeline':
            return self._execCmd(parsedcmd)
        elif t == 'processsubstitution':
            return self._execCmd(parsedcmd)
        elif t == 'list':
            return self._execCmd(parsedcmd)
        elif t == 'compound':
            return self._execCmd(parsedcmd)
        elif t == 'operator':
            return self._execCmd(parsedcmd)
        else:
            return self._execCmd(parsedcmd)

        if self.debug:
            # in debug mode, we always execute a command
            # self._execCmd(cmd)
            # self._obs = self.env.makeDummyObs()
            pass
        else:
            # create an observation
            rawCmd = parsedcmd['cmd_str']
            if t == 'command' and isinstance(parsedcmd['cmd'], str):
                basename = utils.get_basename(parsedcmd['cmd'])
            else:
                basename = ''
            parsedcmd['basename']  = basename
            execcmd = parsedcmd['cmd']

            # if there is no state present in the parsed command, it means
            # that the command is not yet executed, it is just submitted from
            # the attacker. It is not provided by the transformer, so we will
            # manually added to the parsed command object
            if 'state' not in parsedcmd:
                parsedcmd['state'] = self.env.COMMAND_EXEC_STATE_START

            cmdStateExec = parsedcmd['state']

            # create an observation based on obtained basename
            obs, cmdIndex = self._makeObs(rawCmd, basename, execcmd, cmdStateExec)
            # query action from current policy
            self.action = self._getAction(obs, parsedcmd)
            env = self._takeAction(parsedcmd, obs, cmdIndex, self.action)

            self.done = env['done']
            parsedcmd['env'] = env

            if self.done:
                self.closeConnection()
            else:
                # check for every command if it is a download command, then download
                # the file
                self.trydownload(parsedcmd)

                if self.action == self.env.ACTION_ALLOW:
                    self._execActionAllow(parsedcmd, obs)
                elif self.action == self.env.ACTION_BLOCK:
                    self._execActionBlock(parsedcmd, obs)
                elif self.action == self.env.ACTION_SUBSTITUTE:
                    self._execActionSubstitute(parsedcmd, obs)
                elif self.action == self.env.ACTION_TERMINATE:
                    self._execActionTerminate(parsedcmd, obs)
                elif self.action == self.env.ACTION_NOP:
                    self._execActionNop(parsedcmd, obs)

    def prepareSampleBeforeLosingConnection(self):
        """
        This should be called by the protocol in the event
        that we lost connection unexpectedly due to CRTL+D
        """

        # create an object ressemble to the parsed command
        parsedcmd = {}
        basename = "exit_"
        parsedcmd['basename'] = basename
        parsedcmd['cmd'] = basename
        parsedcmd['cmd_str'] = "exit_"
        parsedcmd['state'] = self.env.COMMAND_EXEC_STATE_START
        parsedcmd['arg'] = []
        rawCmd = parsedcmd['cmd_str']
        # create an observation based on obtained basename
        obs, cmdIndex = self._makeObs(rawCmd, basename, basename, parsedcmd['state'])
        # query action from current policy
        self.action = self._getAction(obs, parsedcmd)
        env = self._takeAction(parsedcmd, obs, cmdIndex, self.action)

    def _execActionTerminate(self, parsedcmd, obs):
        """
        Terminate the running command.
        """

        raise "Action terminate is not applied for the command that is not yet executed."

    def _execActionNop(self, parsedcmd, obs):
        """
        Do nothing on the running command
        """

        raise "Action nop is not applied for the command that is not yet executed."

    def _execsimple(self, cmd):
        """
        Execute simple command, check if we have sub variables and fetch their
        values accordingly.
        """

        print("_execsimple parent state: ", self.parentState)
        print("_execsimple state: ", self.state)
        print("_execsimple substate: ", self.substate)

        if self.action == self.env.ACTION_ALLOW:
            execcmd = cmd['cmd_str']
            pattern = execcmd
        elif self.action == self.env.ACTION_BLOCK:
            cmdName, execcmd, pattern, _ = self.prepareBlockedCommand(cmd)
            # replace the first {} with empty str "" and the second with the cmdName
            execcmd = execcmd.format("", cmdName)
            pattern = pattern.format("", cmdName)
        elif self.action == self.env.ACTION_SUBSTITUTE:
            # we still print something to produce empty content
            execcmd = ' (echo "")'
            pattern = ' (echo "")'

        execcmd = bytes(execcmd, 'utf8')
        pattern = bytes(pattern, 'utf8')

        # no context, no parent command
        if not self.context:
            if self.action == self.env.ACTION_ALLOW:
                if self.substate is None:
                    self.filteroff = False
                    if self.operatorCommand is None and self.substate is None:
                        self.substate = "send_backend_command"
                        execcmd += b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\n'
                        self.writeToBackend(execcmd)
            elif self.action == self.env.ACTION_BLOCK:
                self.filteroff = False
                if self.substate is None:
                    if self.operatorCommand:
                        pattern = self.operatorPattern + pattern
                        execcmd = self.operatorCommand + execcmd
                        self.operatorCommand = None
                        self.substate = "send_backend_block_command_with_operator"
                    else:
                        self.substate = "send_backend_block_command"
                    self.nextCmd = execcmd + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\n'
                    self.nextCmdPattern = pattern + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\r\n'
                    self.writeToBackend(self.nextCmd)
            elif self.action == self.env.ACTION_SUBSTITUTE:
                self.filteroff = False
                self.substate = "send_backend_substitute_command"
                self.nextCmd = b' printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\n'
                self.nextCmdPattern = b' printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\r\n'
                self.writeToBackend(self.nextCmd)
        else:
            self.filteroff = False

            if self.operatorCommand:
                pattern = self.operatorPattern + execcmd
                execcmd = self.operatorCommand + execcmd
                self.operatorCommand = None
                self.substate = "send_backend_list_command_with_operator"
            else:
                pattern = execcmd
                self.substate = "send_backend_list_command"

            if self.action == self.env.ACTION_SUBSTITUTE:
                self.nextCmd = execcmd + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\n'
                self.nextCmdPattern = pattern + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\r\n'
            else:
                self.nextCmd = execcmd + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\n'
                self.nextCmdPattern = pattern + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\r\n'
            self.writeToBackend(self.nextCmd)

    def prepareBlockedCommand(self, cmd: dict)->tuple[str, str, str, bool]:
        """
        Take a parsed command and prepare a fake command-not-found error message
        using 'echo' to print the err msg.

        Params
        ------
            cmd (dict): parsed command

        Returns
        -------
            a tuple containing a command name (str), fake command-not-found template,
            and its pattern template (str), flag if there is a command name or not.
        """

        cmdType: str = cmd['type']
        cmdName: str = None
        noCmdName: bool = False
        # re create the command by adding '\n in front of the err msg
        # so that the result will include '\n' followed by err msg.
        if self.cmdLineNumber == 1:
            prefixbash = '{}-bash: '
        else:
            lineno = str(self.cmdLineNumber - 1)
            prefixbash = '{}-bash: ' + lineno + ': '

        errmsg = prefixbash + '{}' + ': command not found'
        execcmd = ' (echo "' + errmsg + '" && false; exit 127)'
        pattern = ' \(echo "' + errmsg + '" && false; exit 127\)'

        if cmdType == 'command' and 'old_type' not in cmd:
            cmdName = cmd['cmd']
            if cmd['redirects']:
                for redirect in cmd['redirects']:
                    red = ' ' + redirect['type'] + redirect['output']
                    execcmd = red + ' ' + execcmd
                    pattern = red + ' ' + pattern
                    # some case, command is just the redirection, so no actual command
                    if red.strip() == cmdName:
                        noCmdName = True
            if noCmdName:
                errmsg = prefixbash + '{}' + ': Permission denied'
                # no parenthesis, for redirection commands
                execcmd = ' (echo "' + errmsg + '" && false; exit 127)'
                pattern = ' \(echo "' + errmsg + '" && false; exit 127\)'
                cmdName = cmdName[1:]
        elif cmdType == 'command' and cmd['old_type'] == 'pipeline':
            for _cmd in cmd['cmd']:
                if _cmd['type'] == 'command' and cmdName is None:
                    cmdName = _cmd['cmd']

                for redirect in _cmd['redirects']:
                    red = ' ' + redirect['type'] + redirect['output']
                    execcmd = red + ' ' + execcmd
                    pattern = red + ' ' + pattern
        elif cmdType == 'command' and cmd['old_type'] == 'compound':
            # The error message can be something like this or
            # bash: -c: line 1: syntax error: unexpected end of file
            # -bash: syntax error near unexpected token XXXX"
            errmsg = "{}-bash: syntax error near unexpected token \`{}'"
            execcmd = ' (echo "' + errmsg + '" && false; exit 127)'
            pattern = ' \(echo "' + errmsg + '" && false; exit 127\)'
            cmdList = cmd['cmd_str'].strip().split()
            cmdName = cmdList[0]

        return cmdName, execcmd, pattern, noCmdName

    def _execoperator(self, cmd: dict)->None:
        """
        Execute command based on current operator

        Params
        ------
            cmd (dict): parsed command

        Returns
        -------
            None
        """
        operator = cmd['operator']

        if operator == '&&':
            if self.exitStatus == 0:
                self.operatorCommand = b' true && '
                self.operatorPattern = b' true && '
            else:
                self.operatorCommand = b' false && '
                self.operatorPattern = b' false && '
            self.next()
        elif operator == '||':
            if self.exitStatus == 0:
                self.operatorCommand = b' true || '
                self.operatorPattern = b' true \|\| '
            else:
                self.operatorCommand = b' false || '
                self.operatorPattern = b' false \|\| '
            self.next()
        elif operator == ';':
            # a next command is called
            self.next()
        elif operator == '&':
            # a next command is called
            self.next()

    def _execassignment(self, cmd):
        """
        Execute assignment command
        """
        self.filteroff = False
        if self.substate is None:
            self.substate = "send_backend_newline"
            execcmd = b' ' + bytes(cmd['cmd'], 'utf8') + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\n'
            self.writeToBackend(execcmd)
        else:
            self.substate = "send_backend_assignment"
            execcmd = b' ' + bytes(cmd['cmd'], 'utf8') + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)'
            self.nextCmd = execcmd + b'\n'
            self.writeToBackend(self.nextCmd)

    def _execcommand(self, cmd: dict)->None:
        """
        @override

        call `_execsimple()` directly, because piped commands are treated as
        a single command statement.

        Params
        ------
            cmd (dict): parsed command
        """

        self._execsimple(cmd)

    def _execlist(self, cmd):
        """
        Execute a list command
        """
        if self.state is None:
            self.state = 'list'
            self.startexec = False
            self._saveContext(cmd)
            self.parentState = 'list'
            self.cmdpending = cmd['cmd']
            self.filteroff = False
            self.next()
        elif self.state == "list":
            if self.parentState is None:
                # send data to frontend
                if self.previousOutputFile:
                    path = self.previousOutputFile
                    self.previousOutputFile = None
                    self.filteroff = True
                    self.writeToStdOut(path)
            self.substate = None
            self.state = None
            self.next()
        else:
            self.state = None
            self.input = b''
            self.next()

    def preparefakehistory(self, cmd: dict)->None:
        r"""
        Prepare fake history command, the first one is to be sent to backend
        while the second is to used to detect when the backend replies;
        the only different is that the backend always replies with `"\\r\\n"`.

        Args:
            cmd: parsed command
        """

        rawCmd = cmd['cmd_str']
        quotedCmd = shlex.quote(rawCmd)
        self.fakeHistoryCommand = b'history -s ' + bytes(quotedCmd, 'utf8') + b'\n'
        # need to quote this special character '?' for re.sub!
        quotedCmd = re.sub(r'\?', r'\\?', quotedCmd)
        pattern = 'history -s ' + quotedCmd + '\r\n'
        self.fakeHistoryPattern = bytes(pattern, 'utf8')

    def _execpipeline(self, cmd: dict)->None:
        """
        Execute a pipeline

        Params:
        -------
            cmd (dict): it is parsed command containing command type, raw command
            and a list of commands that make up this command pipeline.

        Returns:
        -------
            None
        """

        if self.startexec:
            # no save history
            self.state = 'pipeline'
            self.startexec = False
            self.substate = None #"start_exec_command_pipeline"
            self.filteroff = False
            newCmd = cmd.copy()
            newCmd['type'] = 'command'
            newCmd['old_type'] = 'pipeline'
            self.exec(newCmd)
        else:
            self.state = None
            self.input = b''
            self.next()

    def _execcompound(self, cmd: dict):
        """
        @overide
        Execute compound command.

        Params:
        -------
            cmd (dict): it is parsed command containing command type, raw command
            and a compound command.

        Returns:
        -------
            None
        """
        if self.startexec:
            self.state = 'compound'
            self.startexec = False
            self.substate = None #"start_exec_command_compound"
            self.filteroff = False
            newCmd = cmd.copy()
            newCmd['type'] = 'command'
            newCmd['old_type'] = 'compound'
            self.exec(newCmd)
        else:
            self.state = None
            self.input = b''
            self.next()

    def dataReceivedFromBackend(self, data):
        isprompt = False

        log.msg("dataReceivedFromBackend")
        log.msg("state: ", self.state)
        log.msg("substate: ", self.substate)
        log.msg("filteroff: ", self.filteroff)

        if self.filteroff:
            self.substate = None
            self.protocol.write(data)
            return
        else:
            self.data += data

        print("Buffering data: ", self.data)

        if self.data.find(self.MAGIC_BYTES) >= 0:
            log.msg("motif is detected")
            isprompt = True
        else:
            # no prompte detected, buffering received data
            return

        self.processExitStatus()

        if not self.filteroff:
            if isprompt:
                if self.substate == "send_backend_command":
                    _data = re.sub(self.MAGIC_BYTES, b"", self.data)
                    self.data = b''
                    self.substate = None
                    self.protocol.writeToAttacker(_data)
                    self.next()
                elif self.substate == "send_backend_newline":
                    self.data = b''
                    self.next()
                elif self.substate == "send_backend_assignment":
                    self.data = b''
                    self.next()
                elif self.substate == "send_backend_list_command" or \
                    self.substate == "send_backend_list_command_with_operator":
                    _data = re.sub(self.MAGIC_BYTES, b"", self.data)
                    self.data = b''
                    self.nextCmdPattern = None
                    self.nextCmd = None
                    self.protocol.writeToAttacker(_data)
                    self.next()
                elif self.substate == "send_backend_list_command_input" or \
                    self.substate == "send_backend_list_command_input_with_operator":
                    self.data = b''
                    self.next()
                elif self.substate == "send_backend_pipeline_next_command":
                    self.data = b''
                    self.next()
                elif self.substate == "send_backend_pipeline_last_command":
                    _data = re.sub(self.MAGIC_BYTES, b"", self.data)
                    self.data = b''
                    self.protocol.writeToAttacker(_data)
                    self.next()
                # BEGIN: ACTION_BLOCK
                elif self.substate == "send_backend_block_command" or \
                    self.substate == "send_backend_block_command_with_operator":
                    _data = re.sub(self.MAGIC_BYTES, b"", self.data)
                    self.data = b''
                    self.protocol.writeToAttacker(_data)
                    self.filteroff = True
                    self.substate = None
                    self.next()
                # END: ACTION_BLOCK
                # BEGIN: ACTION_SUBSTITUTE
                elif self.substate == "send_backend_substitute_command":
                    _data = re.sub(self.MAGIC_BYTES, b"", self.data)
                    self.protocol.writeToAttacker(self.data)
                    self.data = b''
                    self.substate = None
                    self.filteroff = True
                    self.next()
                # END: ACTION_SUBSTITUTE
                # Global
                elif self.substate == "send_backend_for_prompt":
                    _data = re.sub(b'\r\n', b'', self.data)
                    self.data = b''
                    self.filteroff = True
                    self.protocol.writeToAttacker(_data)
                    self.next()