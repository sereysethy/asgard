import re
import os
import shlex
from twisted.python import failure, log

from cowrie.core.config import CowrieConfig

from bashlex import parser

from smartproxy.command.transformerv2 import nodevisitor
from smartproxy import tlog
from smartproxy.utils import utils
from smartproxy.utils import common
from smartproxy.shell import download
import smartproxy.utils.utils as utils

def strip_ansi_codes(s):
    # return re.sub(b'\x1b\[([0-9,A-Z@]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?', b'', s)
    return re.sub(b'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', b'', s)

def strip_os_codes(s, isroot=False):
    if isroot:
        return re.sub(b'\x1b\]?(\d;)([@\w: ~#/]*)\x07', b'', s)
    else:
        return re.sub(b'\x1b\]?(\d;)([@\w: ~$/]*)\x07', b'', s)

def strip_prompt(s, prompt):
    p = prompt + b':[ /\w\.\-~#$]*'

    return re.sub(p, b'', s)

class ShellComplexParsing():
    """
    Class responsible for analyzing commands and delegating decisions to an agent.

    This class processes incoming commands by preprocessing them and parsing them
    into an Abstract Syntax Tree (AST). The resulting AST is used to generate a list
    of command objects to be executed.

    For each command in the list, the agent is invoked to determine how the command
    should be handled. A command may be:

        - allowed to execute,
        - blocked from execution, or
        - substituted.

    At the end of each episode, a sample command is returned for evaluation
    purposes.
    """

    MAX_TRY_MAKE_OBS = 3
    MAGIC_BYTES = b'#####'
    fakeHistoryCommand = None
    fakeHistoryPattern = None
    operatorCommand = None
    operatorPattern = None

    def __init__(self, username=None, simulated=False, exploration=True):
        self.debug = CowrieConfig.getboolean('shell', 'debug', fallback=False)

        self.simulated = simulated
        self.exploration = exploration

        self.trees = None

        self.request = b'exec'
        self.execcmd = None

        # Session variable
        self.subCmdIndex = 0
        self.arrCmds = []

        ####
        self.cmdpending = []
        self.stack = []

        self.attackerCmd = {}           # contains current command object
        self.internalCmd = {}

        self.cmdIndex = 0
        self.input = b''
        self.data = b''
        self.extdata = b''
        self.execcmd = b''      # contains a flat command string to be executed
        self.var = {}
        self.cwd = ""           # current working directory
        self.exitStatus = True

        self.pipe = False
        self.line = ''
        self.state = None
        self.parentState = None
        self.substate = None
        self.buffer = b''
        self.executingCompoundCmd = False

        self.cmdStack = []
        self.cmdStackIndex = -1

        self.context = []
        self.state = None
        self.response = None
        self.inputData = b''
        self.elseIfIndex = 0
        # this is to prevent the command to be executed again after
        # its context is restored.
        self.startexec = True
        # global variables
        self.done = False
        self.action = None
        self.savedparsedcmd = None

        self.attacker = None
        self.tmpIndexFile = 0

        self.agent = None
        self.env = None

        # this will hold the error message that will be used to show to the attacker
        # when there is a problem of filtering/matching.
        self.blockedErrorMsg: bytes = b''

        self.sample = {
            "obs": [],
            "cmd_str": [],
            "cmd_arg": [],
            "basenames": [],
            "cmds": [],
            "actions": [],
            "rewards": [],
            "dones": [],
            "next_obs": [],
            "next_basenames": [],
            "next_cmds": [],
            "infos": []
        }

        self.filteroff = True
        self.lastExperience = None
        self.backend = None

        if username:
            hostname = CowrieConfig.get("proxy", "target_hostname")
            if username == 'root':
                self.isroot = True
            else:
                self.isroot = False
            # make username@hostname by using username of attacker
            _prompt = username + "@" + hostname
            self.targetPrompt = bytes(_prompt, "utf8")
        else:
            self.targetPrompt = bytes(CowrieConfig.get("proxy", "target_prompt"), "utf8")

        # where to write tmp files for pipes commands
        self.tmpFolder = CowrieConfig.get("docker", "tmp_folder")
        self.baseIndex = 0
        self.previousOutputFile = None
        self.contextLetter = self._getBaseContextLetter()
        self.globalCounter = 0

        # keep track of all the opened shell, the attacker can decide to launch
        # another shell on top of the current shell like 'sh'
        self.shellStack = []

    def getTmpFolder(self):
        """Return a path where we will write temporary files for pipe.
        """
        return os.path.join(self.tmpFolder, self.transportId)

    def addAgentAndEnv(self, agent, env):
        """
        This function allows the protocol to pass the agent and the environment
        from factory.

        Args:
            agent: the instance of agent used to make decision.
            env: the instance of the environment.
        """
        self.agent = agent
        self.env = env

    def _getAction(self, obs):
        """wrapper function"""
        action = self.agent.getAction(obs, self.exploration)
        return action

    def _takeAction(self, cmd, obs, action):
        """
        Take action for a state observation representing a given command.

        Args:
            cmd: command string.
            obs: state observation representing the `cmd`, which is a command basename.
            action: action to perform for a state observation `obs`

        Returns:
            dict: A dictionary of the following items:
                - obs: the current observation.
                - action: the action taken.
                - reward: the observed reward.
                - done: `True` if `obs` is a terminal state, otherwise `False`.
                - info: other releven information if any.

        :meta public:
        """
        reward, done, info = self.env.step(obs, action)

        template = 'take action: {} for command: {} ({}), obs: {}, reward: {}, done: {}, info: {}'
        log.msg(template.format(self.env.getActionName(action),
                                        cmd['basename'],
                                        cmd['cmd'],
                                        obs,
                                        reward,
                                        done,
                                        info))

        if not self.lastExperience:
            self.lastExperience = (obs, cmd['cmd_str'], cmd['arg'], cmd['basename'], cmd['cmd'], action, reward, done, info)
        else:
            obs_, cmd_str_, arg_, basename_, cmd_, action_, reward_, done_, info_ = self.lastExperience

            done_ = done or done_

            self.sample["obs"].append(obs_)
            self.sample["cmd_str"].append(cmd_str_)
            self.sample["cmd_arg"].append(arg_)
            self.sample["basenames"].append(basename_)
            self.sample["cmds"].append(cmd_)
            self.sample["actions"].append(action_.tolist())
            self.sample["rewards"].append(reward_)
            self.sample["dones"].append(done_)
            self.sample["infos"].append(info_)
            self.sample["next_obs"].append(obs)
            self.sample["next_basenames"].append(cmd['basename'])
            self.sample["next_cmds"].append(cmd['cmd'])

            # replace old experience by a current experience if not final state 'exit'
            if not done_:
                self.lastExperience = (obs, cmd['cmd_str'], cmd['arg'], cmd['basename'], cmd['cmd'], action, reward, done, info)
            else:
                self.lastExperience = None

        env = {
            "obs": obs,
            "action": action,
            "reward": reward,
            "done": done,
            "info": info
        }

        return env

    def _saveLastExperience(self):
        """
        Save last sample (experience) for logging purpose.

        It uses a class attribute `lastExperience` which is set in :meth:`_takeAction`.
        """

        if self.lastExperience:
            obs_, cmd_str_, arg_, basename_, cmd_, action_, reward_, done_, info_ = self.lastExperience

            done_ = True
            self.sample["obs"].append(obs_)
            self.sample["cmd_str"].append(cmd_str_)
            self.sample["cmd_arg"].append(arg_)
            self.sample["basenames"].append(basename_)
            self.sample["cmds"].append(cmd_)
            self.sample["actions"].append(action_.tolist())
            self.sample["rewards"].append(reward_)
            self.sample["dones"].append(done_)
            self.sample["infos"].append(info_)

            self.lastExperience = None

    def _makeObs(self, basename: str, execCmd: str)->int:
        """
        A wrapper function to create a state observation using the command basename.

        Args:
            basename: command basename.
            execCmd: raw input command.

        Returns:
            Command index representing the command basename
        """
        return self.env.makeObs(basename, execCmd)

    def getSample(self)->dict:
        """
        Get a list of samples recorded during the episode of the interaction.

        Returns:
            dict: A dictionary of sample consisting of:
                - `obs`: list of observations.
                - `cmd_str`: list of command strings.
                - `cmd_arg`: list of command arguments.
                - `basenames`: list of command basenames.
                - `cmds`: list of raw commands.
                - `actions`: list of actions taken for each observation.
                - `rewards`: lsit of observed rewards taken for each observation.
                - `dones`: list of boolean indicating if the next state `obs` is terminal.
                - `infos`: list of info dictionary.
        """
        return self.sample

    def addbackend(self, backend, protocol):
        """
        Add backend channel to this shell to allow it to communicate with
        the backend ssh server.

        Args:
            backend: reprensents the channel to communicate with the target system.
            protocol: shell protocol associated to process the interaction.
        """

        self.backend = backend
        self.protocol = protocol
        self.transportId = self.protocol.transportId
        self.uid = self.protocol.uid
        self.gid = self.protocol.gid

        # we re-init the targetPrompt attribute of the protocol, it is used to
        # check if the terminate state is changed.
        self.protocol.targetPrompt = self.targetPrompt

    def writeToBackend(self, data: bytes):
        """
        Shell writes data to backend channel.

        Args:
            data: contains data to write to backend channel.
        """

        log.msg("shell write to backend")
        self.backend.write(data)

    def parsing(self, line: str)->list:
        """
        Parsing command line to build AST.

        Args:
            line: The input command line.

        Retruns:
            A list of command objects which is ready to be decided on.

        :meta public:
        """
        cmdpending = []
        try:
            # trees = parser.parsesingle(line, expansionlimit=1, strictmode=False)
            self.trees = parser.parse(line)

            for tree in self.trees:
                visitor = nodevisitor(line)
                visitor.visit(tree)
            cmdpending = visitor.cmdpending
        except:
            # something is wrong, maybe it is not covered by parser like
            # comment
            cmdpending = self._parseUnknown(line)

        return cmdpending

    def _parseUnknown(self, line: str):
        """
        Parse line which is not ignored/parsed by bashlex

        Args:
            line: The input command line.

        Returns:
            A list of command objects which is ready to be decided on.

        :meta public:
        """

        cmdpending = []
        for i in range(len(line)):
            c = line[i]
            # whitespace is always 'unparsed'
            if c.isspace():
                continue

            # the parser ignores comments but we can use a trick to see if this
            # starts a comment and is beyond the ending index of the parsed
            # portion of the inpnut
            if not self.trees and c == '#':
                comment = {'type': 'comment',
                           'redirect': False,
                           'output': None,
                           'cmd_str': line,
                           'cmd': line,
                           'arg': [],
                           'pipe': False,
                           'sub': False,
                           'input': None,
                           'last': False,
                           'redirects': [],
                           'append': False,
                           'params': []
                           }
                cmdpending.append(comment)
                break

        return cmdpending

    def processDataRecieved(self, cmd):
        """
        Currently not used.

        :meta private:
        """
        pass

    def processExitStatus(self, cmd):
        """
        Currently not used.

        :meta private:
        """
        pass

    def _filterReceivedData(self, data, cmd):
        """
        Currently not used.

        :meta private:
        """
        pass

    def makeDecision(self, attackerInput):
        """
        A top level method to invoke the decision process on a command line input.

        It first tries to parse the command line input to get a list of command object.
        For each command object from the list, it starting making a decision.
        The process is complex, as the command can be a simple or in complex like a piped
        command with/without redirection, etc. It involes building a stack to keep
        track of the commands.
        """
        self.cmdpending = self.parsing(attackerInput)

        if self.cmdpending:
            self.state = None
            self.index = 0
            self.startexec = True
            self.next()
        else:
            log.msg("parsing error")
            self.filteroff = True
            self.writeToBackend(b'\n')

    def next(self):
        """
        Executes a next command in the current command object list.
        """
        log.msg(f"next, self.index: {self.index}, len cmdpending: {len(self.cmdpending)}")
        if self.index < len(self.cmdpending):
            parsedcmd = self.cmdpending[self.index]
            self.index += 1
            log.msg('executing command index: {}'.format(parsedcmd))
            self.exec(parsedcmd)
        elif self.context:
            cmd = self._restoreContext()
            # state is none indicates that we still need to execute sub-command
            # which is part of the parent command
            if self.state is None and self.index < len(self.cmdpending):
                cmd = self.cmdpending[self.index]
                self.index += 1
                log.msg('executing command context: {}'.format(cmd))
                self.exec(cmd)
            else:
                # if no more sub-command, we resume executing parent command
                # which we get when a context is restored
                log.msg('resuming executing command: {}'.format(cmd))
                self.exec(cmd)
        else:
            self.substate = "send_backend_for_prompt"
            self.writeToBackend(b'\n')

    def closeConnection(self, timeoutReached:bool=False):
        """
        Close the connection

        Args:
            timeoutReached: Close the connection because of `timeoutReached`.
        """
        self._saveLastExperience()
        self.filteroff = True
        # it is not a timeout
        if not timeoutReached:
            # we send newline because the attacker already input 'exit'
            self.writeToBackend(b'\n')
        else:
            # it is a timeout, then we terminate the connection, it will close
            # all th opened channels.
            self.backend.loseConnection()

    def exec(self, parsedcmd: dict):
        """
        Execute a command based on its type.

        A command can be a simple command, a command substitution, an assigment,
        etc. For each command, the shell will query the agent for action to perfom.
        Based on the returned action, the shell will take action accordingly.

        Args:
            parsedcmd: command object
        """

        log.msg('start executing command: ', parsedcmd)

        t = parsedcmd['type']

        if t == 'noop':
            # self.env.setExeccmd(cmd)
            pass
        elif t == 'command':
            # self.env.setExeccmd(cmd)
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
            basename = utils.get_basename(parsedcmd['cmd'])
            parsedcmd['basename']  = basename
            execcmd = parsedcmd['cmd']

            # create an observation based on obtained basename
            obs = self._makeObs(basename, execcmd)
            # query action from current policy
            self.action = self._getAction(obs)
            env = self._takeAction(parsedcmd, obs, self.action)

            self.done = env['done']
            parsedcmd['env'] = env

            if self.done:
                if self.isLastshell():
                    self.closeConnection()
                else:
                    self._closeCurrentShell()
            else:
                # check for every command if it is a download command, then download
                # the file
                self.trydownload(parsedcmd)

                if self.action == self.env.ACTION_ALLOW:
                    self._checkNewshell(parsedcmd)
                    self._execActionAllow(parsedcmd, obs)
                elif self.action == self.env.ACTION_BLOCK:
                    self._execActionBlock(parsedcmd, obs)
                elif self.action == self.env.ACTION_SUBSTITUTE:
                    self._execActionSubstitute(parsedcmd, obs)

    def _closeCurrentShell(self):
        """
        This will close the current shell without closing the connection.
        We will pop out the shell from the shell stack and send newline to the
        backend to exit the current shell.
        """

        self.filteroff = True
        self._popShellstack()
        self.writeToBackend(b'\n')

    def isLastshell(self)->bool:
        """
        Check if it is the last shell on the stack.

        Returns:
            ``True`` if it is the last shell on the stack, otherwise ``False``
        """

        if len(self.shellStack) == 0:
            return True
        else:
            return False

    def _checkNewshell(self, parsedcmd):
        """
        Check if there is a tentative of executing a new shell.
        Because a new shell can change the prompt.
        For example: sh -> '$ ' for normal user, or '# ' for root.
        """

        cmd = parsedcmd['cmd']
        numArg = len(parsedcmd['arg'])

        # new shell invoked.
        if cmd == 'sh' and numArg == 0:
            # keep track of shell
            self._pushShellstack(cmd)
            # change the prompt accordingy
            if self.isroot:
                self.targetPrompt = b'# '
            else:
                self.targetPrompt = b'$ '
            self.protocol.targetPrompt = self.targetPrompt
            self.shellprog = b'sh'
        elif cmd == 'bash' and numArg == 0:
            self._pushShellstack(cmd)
            # change the prompt
            self.shellprog = b'bash'

    def _pushShellstack(self, sh):
        """
        Push new opened sh to the stack. It can keep track on how many
        shells were opened so far. The attacker can open a new shell to evade
        the control.

        Args:
            sh: string is a new shell
        """
        self.shellStack.append(sh)

    def _popShellstack(self):
        """
        Pop a shell out of the opened shell stack if the stack is not empty.

        Returns:
            shell on top of the stack or None if the shell stack is empty.
        """
        if len(self.shellStack) > 0:
            return self.shellStack.pop()
        else:
            return None

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
        parsedcmd['arg'] = []
        # create an observation based on obtained basename
        obs = self._makeObs(basename, basename)
        # query action from current policy
        self.action = self._getAction(obs)
        env = self._takeAction(parsedcmd, obs, self.action)

    def _execCmd(self, cmd):
        """
        A wrapper that calls subsequent method according to command type:
        _execType()
        """
        cmdType = cmd['type']
        log.msg('executing command type: ', cmdType)
        return getattr(self, '_exec%s' % cmdType)(cmd)

    def trydownload(self, parsedcmd):
        """
        If it is a download command, silenlty start download the file.
        """
        cmd = parsedcmd["cmd"]
        if cmd == 'wget':
            args = parsedcmd["arg"]
            c = download.wget(self.protocol, args)
            d = c.start()
        elif cmd == 'curl':
            args = parsedcmd["arg"]
            c = download.curl(self.protocol, args)
            d = c.start()

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

        # cmd = parsedcmd["cmd"]
        # if cmd != '':
        #     self.writeToAttacker(b'\r\n')
        #     args = parsedcmd["arg"]
        #     c = self.commands["nop"](self.terminal, args)
        #     c.start()

        #     self.substate = b'send_backend_empty_buffer'
        #     # empty command buffer in the backend
        #     self.backendChannel.write(b'\x03')

        #     # prepare fake history command, the first one is to be sent to backend
        #     # while the second is to used to detect when the backend replies;
        #     # the only different is that the backend always replies with "\r\n"
        #     self.fakeHistoryCommand = b'history -s "' + bytes(cmd, 'utf8') + b'"\n'
        #     self.fakeHistoryPattern = b'history -s "' + bytes(cmd, 'utf8') + b'"\r\n'

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

    def _saveContext(self, cmd):
        """
        Save a current contextual variables
        """
        context = {}
        context['cmd'] = cmd
        context['cmdpending'] = self.cmdpending
        context['index'] = self.index
        context['state'] = self.state
        context['parentState'] = self.parentState
        context['elseIfIndex'] = self.elseIfIndex
        context['input'] = self.input
        context['data'] = self.data
        context['extdata'] = self.extdata
        context['contextLetter'] = self.contextLetter
        context['tmpIndexFile'] = self.tmpIndexFile
        context['startexec'] = self.startexec

        # reinit contextual variables
        self.index = 0
        self.state = None
        self.elseIfIndex = 0
        self.input = b''
        self.data = b''
        self.extdata = b''
        self.contextLetter = self._getBaseContextLetter()
        self.tmpIndexFile = 0
        self.startexec = True
        self.parentState = None

        self.context.append(context)

    def _restoreContext(self):
        """
        Restore to a previous context
        """
        context = self.context.pop()
        cmd = context['cmd']
        self.cmdpending = context['cmdpending']
        self.state = context['state']
        self.parentState = context['parentState']
        self.index = context['index']
        self.elseIfIndex = context['elseIfIndex']
        self.input = context['input'] + self.input
        self.data = context['data'] + self.data
        self.extdata = context['extdata'] + self.extdata
        self.contextLetter = context['contextLetter']
        self.tmpIndexFile = context['tmpIndexFile']
        self.startexec = context['startexec']

        print('restoring context, index: ', self.index, '; elseIfIndex: ', self.elseIfIndex)
        print('restoring cmdpending: ', self.cmdpending)

        return cmd

    def _getBaseContextLetter(self):
        """
        Return a next letter that will serve as a contextual letter for
        each command pipes. So that the when there is a new piped commands
        they will not override each other.
        """

        x = 'abcdefghijklmnopqrstuvwxyz'
        self.baseIndex += 1
        return x[self.baseIndex]

    def _getNextTmpFile(self):
        """
        Return a next tmp file of the current context letter.
        """

        base = self.getTmpFolder()
        context = self.contextLetter
        self.tmpIndexFile += 1
        index = self.tmpIndexFile

        tmpFile = bytes(base + context + str(index), "utf8")
        return tmpFile

    def _getCurrentTmpFile(self):
        """
        Return a current tmp file of the current context letter.
        """
        base = self.getTmpFolder()
        context = self.contextLetter
        index = self.tmpIndexFile

        tmpFile = bytes(base + context + str(index), "utf8")
        return tmpFile

    def _execcomment(self, cmd):
        '''
        It is a comment, just ignore it for now
        '''
        self._exec()

    def _execoperator(self, cmd):
        """
        Execute command based on current operator
        """
        operator = cmd['operator']

        if operator == '&&':
            self.operatorCommand = b' if [ $? -eq 0 ]; then true && '
            self.operatorPattern = b' if \[ \$\? -eq 0 \]; then true && '
            self.next()
        elif operator == '||':
            self.operatorCommand = b' if [ $? -ne 0 ]; then false || '
            self.operatorPattern = b' if \[ \$\? -ne 0 \]; then false \|\| '
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

    def _execcommand(self, cmd):
        """
        Execute commands: it can be pipe command or simple command
        """
        if self.pipe:
            self._execpipe(cmd)
        else:
            self._execsimple(cmd)

    def _execpipe(self, cmd):
        """
        Execute pipe command, the input will be simulated by an echo of internal
        `input` variable.

        $ echo input | next_command (in the pipeline)
        """

        # get the current temporary file
        tmpFile = self._getCurrentTmpFile()

        if self.action == self.env.ACTION_BLOCK:
            # self.pipe = False
            self.input = b''
            errmsg = b'-bash: ' + bytes(cmd['cmd'], 'utf8') + b': command not found'
            execcmd = b' cat ' + tmpFile + b' | ' + b' (>&2 echo ' + errmsg + b' && false)'
            pattern = b' cat ' + tmpFile + b' \| ' + b' \(>&2 echo ' + errmsg + b' && false\)'

            if self.operatorCommand:
                execcmd += self.operatorCommand + execcmd
                pattern += self.operatorCommand + pattern
                self.operatorCommand = None
            # we do not need argument for the blocked command
        elif self.action == self.env.ACTION_SUBSTITUTE:
            execcmd = b' cat ' + tmpFile
            pattern = b' cat ' + tmpFile
            if self.operatorCommand:
                execcmd += self.operatorCommand + execcmd
                pattern += self.operatorCommand + pattern
                self.operatorCommand = None
            # we do not need argument for the substituted command
        elif self.action == self.env.ACTION_ALLOW:
            basename = utils.get_basename(cmd['cmd'])
            execcmd = b' cat ' + tmpFile + b' | ' + bytes(cmd['cmd'], 'utf8')
            pattern = b' cat ' + tmpFile + b' \| ' + bytes(cmd['cmd'], 'utf8')

            if self.operatorCommand:
                execcmd += self.operatorCommand + execcmd
                pattern += self.operatorCommand + pattern
                self.operatorCommand = None

            for arg in cmd['arg']:
                execcmd += b' ' + bytes(arg, 'utf8')
                pattern += b' ' + bytes(arg, 'utf8')

        if cmd["output"] == "input":
            self.substate = "send_backend_pipeline_next_command"
            # self.tmpIndexFile += 1
            # index = bytes(str(self.tmpIndexFile), "utf8")
            tmpFile = self._getNextTmpFile()
            # path = self.getTmpFolder(b'_tmp')
            execcmd += b' > ' + tmpFile
            pattern += b' > ' + tmpFile

        elif cmd["output"] == "stdout":
            self.substate = "send_backend_pipeline_last_command"
            """
            reinit
            """
            self.pipe = False
            self.input = b''

        if self.action == self.env.ACTION_SUBSTITUTE:
            self.nextCmd = execcmd + b'\n'
            self.nextCmdPattern = pattern + b'\r\n'
        else:
            self.nextCmd = execcmd + b'\n'
            self.nextCmdPattern = pattern + b'\r\n'
        print("pattern to replace XXXX: ", self.nextCmdPattern)
        self.writeToBackend(self.nextCmd)

    def _execsimple(self, cmd):
        """
        Execute simple command. The command is executed in according to the
        action taken and then we capture only capture the stdout
        to consume it later, for stderr, we will display it back to
        the attacker.
        """
        print("_execsimple parent state: ", self.parentState)
        print("_execsimple state: ", self.state)
        print("_execsimple substate: ", self.substate)

        if self.action == self.env.ACTION_ALLOW:
            # prepare a normal command to be executed, if there is
            # argument, we concatenate them.
            execcmd = bytes(cmd['cmd'], 'utf8')
            for arg in cmd['arg']:
                execcmd += b' ' + bytes(arg, 'utf8')
            pattern = execcmd
        elif self.action == self.env.ACTION_BLOCK:
            # prepare an error message using 'echo' to print the err msg.
            errmsg = b'-bash: ' + bytes(cmd['cmd'], 'utf8') + b': command not found'
            execcmd = b'echo "' + errmsg + b'" && false'
            pattern = b'echo "' + errmsg + b'" && false'
        elif self.action == self.env.ACTION_SUBSTITUTE:
            # nothing to execute, it is an empty string.
            execcmd = b''
            pattern = b''

        if cmd["output"] == "stdout":
            self._execStdout(cmd, execcmd, pattern)

        if cmd["output"] == "input":
            self._execInput(cmd, execcmd, pattern)

    def _execStdout(self, cmd, execcmd, pattern):
        """
        When the output is of type 'stdout', it meants that the result should
        be sent out to the attacker. But there are cases where we need to check
        the output, especially when the action is "BLOCK".

        Args:
            cmd: object
            execcmd: bytes
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
                    # no redirection
                    if len(cmd['redirects']) == 0:
                        # re create the command by adding '\n in front of the err msg
                        # so that the result will include '\n' followed by err msg.
                        execcmd = b' echo -e "\\n-bash: ' + bytes(cmd['cmd'], 'utf8') + b': command not found" && false'
                        pattern = b' echo -e "\\\\n-bash: ' + bytes(cmd['cmd'], 'utf8') + b': command not found" && false'
                        execcmd = b'>&2 ' + execcmd
                        pattern = b'>&2 ' + pattern
                    else:
                        # for redirection, we do not need '\n' in the redirected
                        # file, except when the the output is to stdout.
                        for redirect in cmd['redirects']:
                            _input = None
                            _output = None
                            if redirect['input']:
                                _input = bytes(redirect['input'], 'utf8')
                            if redirect['output']:
                                _output = bytes(redirect['output'], 'utf8')

                            # from stderr
                            if _input == b'2':
                                if _output == b'/dev/null':
                                    execcmd = b'>/dev/null 2>&1 ' + execcmd
                                    pattern = b'>/dev/null 2>&1 ' + pattern
                                # to stdout
                                elif _output == b'1':
                                    # redefine the err msg with a newline.
                                    execcmd = b' echo -e "\\n-bash: ' + bytes(cmd['cmd'], 'utf8') + b': command not found" && false'
                                    pattern = b' echo -e "\\\\n-bash: ' + bytes(cmd['cmd'], 'utf8') + b': command not found" && false'
                                    execcmd = b'2>&1 ' + execcmd
                                    pattern = b'2>&1 ' + pattern
                                elif _output:
                                    # here the output is a file
                                    execcmd = b'>' + _output + b' 2>&1 ' + execcmd
                                    pattern = b'>' + _output + b' 2>&1 ' + pattern
                            # stdout, the input is omitted
                            elif _input is None:
                                if _output == b'/dev/null':
                                    execcmd = b'>/dev/null 2>&1 ' + execcmd
                                    pattern = b'>/dev/null 2>&1 ' + pattern

                    if self.operatorCommand:
                        pattern = self.operatorPattern + pattern + b'; fi'
                        execcmd = self.operatorCommand + execcmd + b'; fi'
                        self.operatorCommand = None
                        self.substate = "send_backend_block_command_with_operator"
                    else:
                        self.substate = "send_backend_block_command"

                    # as usual we append a space before the command to remove it
                    # from history, and also add () to execute in a subshell
                    self.nextCmd = b' (' + execcmd + b')\n'
                    # for pattern, we need to escape the parenthesises and also
                    # instead of '\n', we add '\r\n', because after we send it
                    # to the backend, the shell replies with '\r\n'.
                    self.nextCmdPattern = b' \(' + pattern + b'\)\r\n'
                    self.writeToBackend(self.nextCmd)

            elif self.action == self.env.ACTION_SUBSTITUTE:
                self.substate = "send_backend_substitute_command"
                self.nextCmd = b' \n'
                self.nextCmdPattern = b' \r\n'
                self.writeToBackend(self.nextCmd)
        else:
            self.filteroff = False

            if self.operatorCommand:
                pattern = self.operatorPattern + pattern + b'; fi'
                execcmd = self.operatorCommand + execcmd + b'; fi'
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
                self.nextCmd = b' (' + execcmd + b')\n'
                self.nextCmdPattern = b' \(' + pattern + b'\)\r\n'
                self.writeToBackend(self.nextCmd)
            else:
                self.nextCmd = b' (' + execcmd + b')\n'
                self.nextCmdPattern = b' \(' + pattern + b'\)\r\n'
                self.writeToBackend(self.nextCmd)

    def _execInput(self, cmd, execcmd, pattern):
        """
        When the output is of type 'input', it means that it is part of the
        other command, so we capture its output and store it in a temporary file.

        Args:
            cmd: object
            execmd: bytes
            pattern: bytes
        """

        self.filteroff = False
        self.pipe = True

        tmpFile = self._getCurrentTmpFile()

        if self.action == self.env.ACTION_ALLOW:
            execcmd = b'(' + execcmd + b') > ' + tmpFile
            pattern = b'\(' + pattern + b'\) > ' + tmpFile

        elif self.action == self.env.ACTION_BLOCK:
            # no redirection
            if len(cmd['redirects']) == 0:
                # we will capture what is in the stdout to a tmpFile to be consumed
                # later, stderr will not be captured, and it will be written back
                # to the attacker.
                execcmd +=  b' > ' + tmpFile
                pattern +=  b' > ' + tmpFile
            else:
                redirectStr = b''
                for redirect in cmd['redirects']:
                    _input = None
                    _output = None
                    if redirect['input']:
                        _input = bytes(redirect['input'], 'utf8')
                    if redirect['output']:
                        _output = bytes(redirect['output'], 'utf8')
                    # from stderr
                    if _input == b'2':
                        # to stdout
                        if _output == b'1':
                            # we need to capture stderr
                            redirectStr += b'2>&1 '
                        # to /dev/null
                        elif _output == b'/dev/null':
                            redirectStr += b'2>/dev/null '
                        # to any other files
                        elif _output:
                            redirectStr += b'2>' + _output + b' '
                    # from stdout
                    elif _input is None:
                        # to /dev/null
                        if _output == b'/dev/null':
                            redirectStr += b'>/dev/null '
                        elif _output == b'2':
                            redirectStr += b'>&2 '
                        elif _output:
                            redirectStr += b'>' + _output + b' '
                # we got all of the redirections, let add them to the command.
                execcmd = b'(' + redirectStr + execcmd + b')' + b' > ' + tmpFile
                pattern = b'\(' + redirectStr + pattern + b'\)' + b' > ' + tmpFile
        elif self.action == self.env.ACTION_SUBSTITUTE:
            # here nothing is execute but we still need to create the empty
            # temporary file which can be consumed later, for the next command.
            execcmd += execcmd + b' >' + tmpFile
            pattern += pattern + b' >' + tmpFile

        if self.operatorCommand:
            pattern = self.operatorPattern + execcmd + b'; fi'
            execcmd = self.operatorCommand + execcmd + b'; fi'
            self.operatorCommand = None
            self.substate = "send_backend_list_command_input_with_operator"
        else:
            self.substate = "send_backend_list_command_input"

        # append a space before the prepared command, so
        # that it will not be kept in the history.
        self.nextCmd = b' ' + execcmd + b'\n'
        self.nextCmdPattern = b' ' + pattern + b'\r\n'
        self.writeToBackend(self.nextCmd)

    def _execlist(self, cmd):
        """
        Execute a list command
        """
        print("_execlist, context: ", self.context)

        if not self.context:
            if self.startexec:
                # save history
                self.state = 'list'
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

    def _execpipeline(self, cmd):
        """
        Execute a pipeline
        """
        #FIXME fix state, use different var or manage step
        ####
        ####
        print("_execpipeline")
        print("self.state: ", self.state)
        print("self.startexec: ", self.startexec)
        if not self.context:
            if self.startexec:
                # save history
                self.state = 'list'
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

    def _execcompound(self, cmd):
        if self.substate is None:
            self.writeToBackend(b'\n')
        else:
            self.state = 'compound'
            execcmd = b' ' + bytes(cmd["cmd_str"], 'utf8')
            self.nextCmd = execcmd + b'\n'
            self.nextCmdPattern = execcmd + b'\r\n'
            self.substate = "start_exec_command_compound"
            self.filteroff = False
            self.writeToBackend(self.nextCmd)

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

    def extDataReceivedFromBackend(self, data: bytes)->None:
        """
        Extended data which is in general data sent through stderr.
        We should also control it, it can leak out some errors to attacker.

        Args:
            data: contains external data to write back to the backend channel.
        """
        #TODO do some filter in according to commands sent to the target machine
        self.protocol.extWrite(data)

    def dataReceivedFromBackend(self, data: bytes):
        """
        Data received from backend channel

        Args:
            data (bytes): received data from the backend channel.
        """
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

        log.msg("Buffering data: ", self.data)
        if self.data.find(self.targetPrompt) >= 0:
            log.msg("prompt is detected")
            isprompt = True
        else:
            # no prompte detected, buffering received data
            return

        if not self.filteroff:
            if isprompt:
                if self.substate == "action_block_send_backend_empty_buffer":
                    self.substate = "action_block_send_fake_history_command"
                    # after we got ^, we sent a newline to client
                    _data = re.sub(b'^C', b'', self.data)
                    self.data = b''
                    self.writeToBackend(self.fakeHistoryCommand)
                elif self.substate == "action_block_send_fake_history_command":
                    _data = re.sub(self.fakeHistoryPattern, b'', self.data)
                    self.substate = "execute_block_action_using_normal_flow"
                    self.data = b''
                    self._execCmd(self.savedparsedcmd)
                elif self.substate == "send_backend_block_command_with_operator" or \
                    self.substate == "send_backend_block_command":

                    if self.data.find(b'Permission denied') >= 0:
                        # here bash returned some error, we need to show it.
                        _data = re.sub(self.nextCmdPattern, b'', self.data)
                        _data = strip_ansi_codes(_data)
                        _data = strip_os_codes(_data, self.isroot)
                        _data = strip_prompt(_data, self.targetPrompt)
                        # remove last newline, because we will get a new prompt later
                        _data = re.sub(b'\r\n$', b'', _data)
                        # append newline
                        _data = b'\r\n' + _data
                    else:
                        _data = re.sub(b'\r(?!\n)', b'', self.data)
                        _data = re.sub(self.nextCmdPattern, b'', _data)
                        _data = strip_ansi_codes(_data)
                        _data = strip_os_codes(_data, self.isroot)
                        _data = strip_prompt(_data, self.targetPrompt)
                        # this will just do the search for the string,
                        # the nextCmdPattern will not match, when the width of the
                        # screen is too small, the backend will add \r to display the screen.
                        _pattern = b'\r\n-bash'
                        _found = re.search(_pattern, _data)
                        if _found:
                            _data = _data[_found.start():]
                            # remove last newline, because we will get a new prompt later
                            _data = re.sub(b'\r\n$', b'', _data)
                        elif self.blockedErrorMsg:
                            # worse case we will our own error message, for roberta
                            _data = self.blockedErrorMsg
                            self.blockedErrorMsg = b''
                        else:
                            _data = b'\r\n'
                    self.data = b''
                    self.nextCmdPattern = None
                    self.nextCmd = None
                    self.protocol.writeToAttacker(_data)
                    self.filteroff = True
                    self.next()
                # BEGIN ACTION: Substitute
                elif self.substate == "action_substitute_send_backend_empty_buffer":
                    self.substate = "action_substitute_send_fake_history_command"
                    # after we got ^, we sent a newline to client
                    _data = re.sub(b'^C', b'', self.data)
                    self.data = b''
                    # self.protocol.writeToAttacker(b'\r\n')
                    self.writeToBackend(self.fakeHistoryCommand)
                elif self.substate == "action_substitute_send_fake_history_command":
                    _data = re.sub(self.fakeHistoryPattern, b'', self.data)
                    # self.protocol.writeToAttacker(_data)
                    self.substate = "execute_substitute_action_using_normal_flow"
                    self.data = b''
                    self._execCmd(self.savedparsedcmd)
                elif self.substate == "send_backend_substitute_command":
                    # _data = re.sub(b'\r\n', b'', self.data)
                    # _data = re.sub(self.nextCmdPattern, b'', self.data)
                    # self.protocol.writeToAttacker(self.data)
                    self.data = b''
                    self.filteroff = True
                    self.next()
                # END ACTION: Substitute
                elif self.substate == "send_backend_empty_buffer":
                    self.substate = "send_fake_history_command"
                    self.data = b''
                    # after we got ^, we sent a newline to client
                    self.protocol.writeToAttacker(b'\r\n')
                    # prepare fake history command
                    self.writeToBackend(self.fakeHistoryCommand)
                elif self.substate == "send_fake_history_command":
                    # nothing is sent out to client
                    self.substate = "done_send_fake_history_command"
                    self.data = b''
                    self.next()
                elif self.substate == "send_backend_assignment":
                    self.data = b''
                    self.next()
                elif self.substate == "send_backend_list_command" or \
                    self.substate == "send_backend_list_command_with_operator":
                    # remove '\r' if not followed by '\n'
                    _data = re.sub(b'\r(?!\n)', b'', self.data)
                    _data = re.sub(self.nextCmdPattern, b'', _data)
                    _data = strip_ansi_codes(_data)
                    _data = strip_os_codes(_data, self.isroot)
                    _data = strip_prompt(_data, self.targetPrompt)
                    self.data = b''
                    self.nextCmdPattern = None
                    self.nextCmd = None
                    self.protocol.writeToAttacker(_data)
                    self.next()
                elif self.substate == "send_fake_history_command":
                    # nothing is sent out to client
                    self.substate = "done_send_fake_history_command"
                    self.data = b''
                    self.next()
                elif self.substate == "send_backend_list_command_input" or \
                    self.substate == "send_backend_list_command_input_with_operator":
                    """
                    The stdout of command is captured in the tmpfile, but
                    the stderr is sent here, we can filter out the submitted command,
                    and send the stderr to the attacker.
                    """
                    _data = re.sub(self.nextCmdPattern, b'', self.data)
                    _data = strip_ansi_codes(_data)
                    _data = strip_os_codes(_data, self.isroot)
                    _data = strip_prompt(_data, self.targetPrompt)
                    self.data = b''
                    self.nextCmdPattern = None
                    self.nextCmd = None
                    self.protocol.writeToAttacker(_data)
                    self.next()
                elif self.substate == "send_backend_pipeline_next_command":
                    self.data = b''
                    self.next()
                elif self.substate == "send_backend_pipeline_last_command":
                    _data = re.sub(b'\r(?!\n)', b'', self.data)
                    _data = re.sub(self.nextCmdPattern, b'', _data)
                    _data = strip_ansi_codes(_data)
                    _data = strip_os_codes(_data, self.isroot)
                    _data = strip_prompt(_data, self.targetPrompt)
                    self.data = b''
                    self.protocol.writeToAttacker(_data)
                    self.next()
                elif self.substate == "send_backend_for_prompt":
                    _data = re.sub(b'\r\n', b'', self.data)
                    self.data = b''
                    self.filteroff = True
                    self.substate = None
                    self.protocol.writeToAttacker(_data)
                elif self.substate == "start_exec_command_compound":
                    _data = re.sub(b'\r(?!\n)', b'', self.data)
                    _data = _data.replace(self.nextCmdPattern, b'')
                    # _data = re.sub(self.nextCmdPattern, b'', _data)
                    _data = strip_ansi_codes(_data)
                    _data = strip_os_codes(_data, self.isroot)
                    _data = strip_prompt(_data, self.targetPrompt)
                    self.data = b''
                    self.protocol.writeToAttacker(_data)
                    self.next()
