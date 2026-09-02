from typing import Tuple
import re
import shlex
import numpy as np
import torch

from twisted.python import log

# Cowrie
from cowrie.core.config import CowrieConfig

# Smart proxy
from smartproxy.command.shell_complex_parsing import ShellComplexParsing
import smartproxy.utils.utils as utils

from smartproxy.learning.rl.dqnlearner import DQNLearner
from smartproxy.learning.environment.roberta import RobertaEnvV10

class ShellRoberta(ShellComplexParsing):
    """
    Class responsible for analyzing commands and delegating decisions to an agent.

    This is for Asgard2.0.

    State observation:
        - risk level associated to the command
        - command embedding representing the command
        - state of the command execution: start (C) or running (R)
        - normalised cpu percentage usage
        - normalised memory percentage usage

    Actions:
        - allow: for short-running commands
        - block: for short-running commands
        - substitute: for short-running commands
        - terminate: for a long-running command
        - nop: for a for a long-running command

    Attributes:
        env: represents the instance of the environment.

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

    def _getAction(self, obs:list[float], cmd: dict) -> int:
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
            The dictionary of what is returned from the environent.

        :meta public:
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
            cmd = self._restoreContext()
            # state is none indicates that we still need to execute sub-command
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
            self.substate = "send_backend_for_prompt"
            self.writeToBackend(b'\n')

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
            Obs (np.array): A numpy array containing the encoded command and
            the state of the target system.
            cmdIndex (int): Command index in the command list.

        :meta public:
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
        # here we do not use "exit_", because the embedding has to match
        # the final state "exit"
        rawCmd = "exit"
        # create an observation based on obtained basename
        obs, cmdIndex = self._makeObs(rawCmd, basename, basename, parsedcmd['state'])
        # query action from current policy
        self.action = self._getAction(obs, parsedcmd)
        env = self._takeAction(parsedcmd, obs, cmdIndex, self.action)

    def _execActionAllow(self, parsedcmd, obs):
        """Execute action `allow`.

        Whatever it is input by attacker, it is already submitted to the backend.
        So to trigger the execution, we just need to write b'\n' to shell
        channel.
        """

        log.msg("exec action allow")
        self._execCmd(parsedcmd)

    def _execActionBlock(self, parsedcmd, obs):
        """
        Execute action `block`.

        - Write an error message to the attacker to indicate that
        the "command is not found" using "-bash attacker_command: command not found".
        For root user, the "-" does not appear in the "bash". We ignore it for now.
        - Empty command buffer in the shell on the target machine by sending ^C
        - Prepare fake command history.
        """
        log.msg("exec action block")

        self.savedparsedcmd = parsedcmd
        self.filteroff = False

        if not self.context:
            self.substate = "action_block_send_backend_empty_buffer"

            # empty command buffer in the backend
            self.writeToBackend(b'\x03')

            # use the original command string to fake the history
            self.preparefakehistory(parsedcmd)
        else:
            self._execCmd(parsedcmd)

    def _execActionSubstitute(self, parsedcmd, obs):
        """
        Execute action `substitute`.

        - Empty command buffer in the shell on the target machine
        - Select a response from a set of pre-defined responses
        - Write a selected response to the attacker
        """
        log.msg("exec action substitute")

        self.savedparsedcmd = parsedcmd
        self.filteroff = False

        if not self.context:
            self.substate = "action_substitute_send_backend_empty_buffer"

            # empty command buffer in the backend
            self.writeToBackend(b'\x03')

            # use the original command string to fake the history
            self.preparefakehistory(parsedcmd)
        else:
            self._execCmd(parsedcmd)

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

    def _execStdout(self, cmd: dict, execcmd:str, pattern: str,
                    cmdName: str=None, noCmdName: bool=False)->None:
        """
        When the output is of type 'stdout', it meants that the result should
        be sent out to the attacker. But there are cases where we need to check
        the output, especially when the action is "BLOCK".

        Args:
            cmd (dict): parsed command
            execcmd (bytes):
            pattern (bytes):
        """

        # no context, it means the command is not part of any other commands.
        if not self.context:
            if self.action == self.env.ACTION_ALLOW:
                # it should be None.
                if self.substate is None:
                    if self.operatorCommand is None and self.substate is None:
                        self.substate = "send_backend_newline"
                        self.writeToBackend(b'\n')
                # it can have some issues if substate is not None.
            elif self.action == self.env.ACTION_BLOCK:
                if self.substate == "execute_block_action_using_normal_flow":
                    if noCmdName:
                        execcmd = execcmd.format("", cmdName)
                        pattern = pattern.format("", cmdName)
                    else:
                        execcmd = execcmd.format("\\n", cmdName)
                        pattern = pattern.format("\\n", cmdName)
                    # execcmd = '>&2 ' + execcmd
                    # pattern = '>&2 ' + pattern

                    if self.operatorCommand:
                        pattern = self.operatorPattern + pattern + '; else exit 127; fi'
                        execcmd = self.operatorCommand + execcmd + '; else exit 127; fi'
                        self.operatorCommand = None
                        self.substate = "send_backend_block_command_with_operator"
                    else:
                        self.substate = "send_backend_block_command"

                    # as usual we append a space before the command to remove it
                    # from history, and also add () to execute in a subshell
                    self.nextCmd = ' (' + execcmd + ')\n'
                    # for pattern, we need to escape the parenthesises and also
                    # instead of '\n', we add '\r\n', because after we send it
                    # to the backend, the shell replies with '\r\n'.
                    pattern = re.escape(pattern)
                    self.nextCmdPattern = ' \(' + pattern + '\)\r\n'
                    self.nextCmd = bytes(self.nextCmd, 'utf8')
                    self.nextCmdPattern = bytes(self.nextCmdPattern, 'utf8')
                    self.writeToBackend(self.nextCmd)

            elif self.action == self.env.ACTION_SUBSTITUTE:
                self.substate = "send_backend_substitute_command"
                self.nextCmd = b' \n'
                self.nextCmdPattern = b' \r\n'
                self.writeToBackend(self.nextCmd)
        else:
            self.filteroff = False

            if cmdName:
                execcmd = execcmd.format("", cmdName)
                pattern = pattern.format("", cmdName)

            if self.operatorCommand:
                pattern = self.operatorPattern + pattern + '; else exit 127; fi'
                execcmd = self.operatorCommand + execcmd + '; else exit 127; fi'
                self.operatorCommand = None
                self.substate = "send_backend_list_command_with_operator"
            else:
                self.substate = "send_backend_list_command"

            if self.action == self.env.ACTION_SUBSTITUTE:
                self.nextCmd = b' \n'
                self.nextCmdPattern = b' \r\n'
                self.writeToBackend(self.nextCmd)
            elif self.action == self.env.ACTION_BLOCK:
                self.substate = "send_backend_block_command"
                self.nextCmd = ' (' + execcmd + ')\n'
                # we need to escape all the special characters, because this
                # pattern will be used to filter out the commands sent from backend.
                pattern = re.escape(pattern)
                self.nextCmdPattern = ' \(' + pattern + '\)\r\n'
                self.nextCmd = bytes(self.nextCmd, 'utf8')
                self.nextCmdPattern = bytes(self.nextCmdPattern, 'utf8')
                self.writeToBackend(self.nextCmd)
            else:
                self.nextCmd = ' (' + execcmd + ')\n'
                # we need to escape all the special characters, because this
                # pattern will be used to filter out the commands sent from backend.
                pattern = re.escape(pattern)
                self.nextCmdPattern = ' \(' + pattern + '\)\r\n'
                self.nextCmd = bytes(self.nextCmd, 'utf8')
                self.nextCmdPattern = bytes(self.nextCmdPattern, 'utf8')
                self.writeToBackend(self.nextCmd)

    def _execsimple(self, cmd):
        """
        Execute simple command. The command is executed in according to the
        action taken and then we only capture the stdout
        to consume it later, for stderr, we will display it back to
        the attacker.
        """
        print("_execsimple parent state: ", self.parentState)
        print("_execsimple state: ", self.state)
        print("_execsimple substate: ", self.substate)

        if self.action == self.env.ACTION_ALLOW:
            # prepare a normal command to be executed, if there is
            # argument, we concatenate them.
            execcmd = cmd['cmd_str']
            pattern = execcmd
            self._execStdout(cmd, execcmd, pattern)
        elif self.action == self.env.ACTION_BLOCK:
            cmdName, execcmd, pattern, noCmdName = self.prepareBlockedCommand(cmd)
            self._execStdout(cmd, execcmd, pattern, cmdName, noCmdName)
        elif self.action == self.env.ACTION_SUBSTITUTE:
            # nothing to execute, it is an empty string.
            execcmd = ''
            pattern = ''
            self._execStdout(cmd, execcmd, pattern)

    def prepareBlockedCommand(self, cmd: dict)->tuple[str, str, str, bool]:
        """
        Take a parsed command and prepare a fake command-not-found error message
        using 'echo' to print the err msg.

        Args:
            cmd (dict): parsed command

        Returns:
            tuple: A tuple containing:
                - a command name (str),
                - a fake command-not-found template,
                - a pattern template (str),
                - a flag if there is a command name or not.
        """

        cmdType: str = cmd['type']
        cmdName: str = None
        noCmdName: bool = False
        # re create the command by adding '\n in front of the err msg
        # so that the result will include '\n' followed by err msg.
        errmsg = '{}-bash: {}: command not found'
        execcmd = 'echo -e "' + errmsg + '" && false; exit 127'
        pattern = 'echo -e "' + errmsg + '" && false; exit 127'
        execcmd = '>&2 ' + execcmd
        pattern = '>&2 ' + pattern

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
                errmsg = '{}-bash: {}: Permission denied'
                # no parenthesis, for redirection commands
                execcmd = ' echo -e "' + errmsg + '" && false; exit 127'
                pattern = ' echo -e "' + errmsg + '" && false; exit 127'
                execcmd = '>&2 ' + execcmd
                pattern = '>&2 ' + pattern
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
            errmsg = "{}-bash: syntax error near unexpected token \`{}'"
            execcmd = 'echo -e "' + errmsg + '" && false; exit 127'
            pattern = 'echo -e "' + errmsg + '" && false; exit 127'
            execcmd = '>&2 ' + execcmd
            pattern = '>&2 ' + pattern
            cmdList = cmd['cmd_str'].strip().split()
            cmdName = cmdList[0]

        # set the error message for block action, this can be used when
        # there is a problem of nextCmdPattern substitution, it happens when
        # the backend ends a modified data due to terminal dimension changes.
        self.blockedErrorMsg = bytes(errmsg.format("\r\n", cmdName), 'utf8')

        return cmdName, execcmd, pattern, noCmdName

    def _execoperator(self, cmd: dict)->None:
        """
        @overide
        Execute command based on current operator

        Args:
            cmd (dict): parsed command
        """
        operator = cmd['operator']

        if operator == '&&':
            self.operatorCommand = ' if [ $? -eq 0 ]; then true && '
            self.operatorPattern = ' if [ $? -eq 0 ]; then true && '
            self.next()
        elif operator == '||':
            self.operatorCommand = ' if [ $? -ne 0 ]; then false || '
            self.operatorPattern = ' if [ $? -ne 0 ]; then false || '
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

        if self.substate is None:
            self.substate = "send_backend_newline"
            self.writeToBackend(b'\n')
        else:
            self.substate = "send_backend_assignment"
            execcmd = b' ' + bytes(cmd['cmd'], 'utf8')
            self.nextCmd = execcmd + b'\n'
            self.writeToBackend(self.nextCmd)

    def _execcommand(self, cmd: dict)->None:
        """
        @override

        call `_execsimple()` directly, because piped commands are treated as
        a single command statement.

        Args:
            cmd (dict): parsed command
        """

        self._execsimple(cmd)

    def _execlist(self, cmd: dict)->None:
        """
        Execute a list command
        """
        print("_execlist, context: ", self.context)

        if not self.context:
            if self.startexec:
                # save history
                # self.state = 'list'
                self.startexec = False
                self._saveContext(cmd)
                self.cmdpending = cmd['cmd']
                self.substate = "send_backend_empty_buffer"
                self.filteroff = False
                self.preparefakehistory(cmd)
                self.writeToBackend(b'\x03')
            else:
                self.state = None
                self.input = b''
                self.next()
        else:
            if self.startexec:
                # no save history
                self.state = 'list'
                self.startexec = False
                self._saveContext(cmd)
                self.cmdpending = cmd['cmd']
                self.substate = "start_exec_command_list"
                self.filteroff = False
                self.next()
            else:
                self.state = None
                self.input = b''
                self.next()

    def _execpipeline(self, cmd: dict)->None:
        """
        Execute a pipeline

        Args:
            cmd (dict): it is parsed command containing command type, raw command
            and a list of commands that make up this command pipeline.
        """
        #FIXME fix state, use different var or manage step
        ####
        ####
        print("_execpipeline")
        print("self.state: ", self.state)
        print("self.startexec: ", self.startexec)

        if self.startexec:
            # no save history
            self.state = 'pipeline'
            self.startexec = False
            self.substate = "start_exec_command_pipeline"
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

        Args:
            cmd (dict): it is parsed command containing command type, raw command
            and a compound command.
        """
        if self.startexec:
            self.state = 'compound'
            self.startexec = False
            self.substate = "start_exec_command_compound"
            self.filteroff = False
            newCmd = cmd.copy()
            newCmd['type'] = 'command'
            newCmd['old_type'] = 'compound'
            self.exec(newCmd)
        else:
            self.state = None
            self.input = b''
            self.next()
