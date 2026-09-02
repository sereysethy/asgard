import re
import json

from twisted.python import log
import smartproxy.utils.utils as utils

from smartproxy.command.shell_complex_parsing import ShellComplexParsing
from smartproxy import tlog

def strip_ansi_codes(s):
    # return re.sub(b'\x1b\[([0-9,A-Z@]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?', b'', s)
    return re.sub(b'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', b'', s)

def strip_os_codes(s):
    return re.sub(b'\x1b\]?(\d;)([@\w: ~$]*)\x07', b'', s)

def strip_prompt(s, prompt):
    # reg = re.compile(b"[ .\w\r\n\d]*nproc@honeypot:~\$ (\w*)")
    p = prompt + b':~\$ '
    # return re.sub(b"nproc@honeypot:~\$ ", b'', s)
    return re.sub(p, b'', s)

class ShellComplexParsingForExec(ShellComplexParsing):
    """
    Class responsible for analyzing commands and delegating decisions to an agent in exec.

    This is for Asgard1.0.
    """

    MAX_TRY_MAKE_OBS = 3
    MAGIC_BYTES = b'#####'
    fakeHistoryCommand = None
    fakeHistoryPattern = None
    operatorCommand = None
    operatorPattern = None
    promptTimeout = None

    def __init__(self, username=None, simulated=False, exploration=True):
        super().__init__(username, simulated, exploration)

        # this represents the command line number
        self.cmdLineNumber = 0

    def writeToBackend(self, data)->None:
        """Shell writes data to backend channel.

        Args:
            data: bytes
        """

        if self.backend:
            log.msg("backend available, shell write to backend")
            self.backend.write(data)
        else:
            log.msg("shell write to backend, backend not available")

    def makeDecision(self, lineNumber, attackerInput):
        self.cmdLineNumber = lineNumber
        self.cmdpending = self.parsing(attackerInput)
        if self.cmdpending:
            self.state = None
            self.index = 0
            self.startexec = True
            self.next()
        else:
            log.err(f"Error parsing of input: {attackerInput}")
            self.protocol.writeToAttacker(b'bash: -c: line 1: syntax error: unexpected end of file\r\n')
            self.closeConnection()


    def next(self):
        log.msg(f"next, self.index: {self.index}, len cmdpending: {len(self.cmdpending)}")
        if self.index < len(self.cmdpending):
            parsedcmd = self.cmdpending[self.index]
            self.index += 1
            log.msg('executing command index: {}'.format(parsedcmd))
            self.exec(parsedcmd)
        elif self.context:
            cmd = self._restoreContext()
            # state is not none indicates that we still need to execute sub-command
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
            # close connection
            self.protocol.executeNextCommand()

    def closeConnection(self, timeoutReached=False):
        """
        @override

        The parameter `timeoutReached` is not used for exec.
        """

        self.writeToBackend('exit\n')

    def exec(self, parsedcmd):
        """
        Execute a command.

        Args:
            parsedcmd: represents a parsed command
        """

        log.msg('start executing command: ', parsedcmd)

        if self.done:
            self.closeConnection()

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
                self.closeConnection()

            # check for every command if it is a download command, then download
            # the file
            self.trydownload(parsedcmd)

            if self.action == self.env.ACTION_ALLOW:
                self._execActionAllow(parsedcmd, obs)
            elif self.action == self.env.ACTION_BLOCK:
                self._execActionBlock(parsedcmd, obs)
            elif self.action == self.env.ACTION_SUBSTITUTE:
                self._execActionSubstitute(parsedcmd, obs)

    def _execCmd(self, cmd):
        """
        A wrapper that calls subsequent method according to command type:
        `_execType()`.

        Args:
            cmd: A command to execute
        """
        cmdType = cmd['type']
        log.msg('executing command type: ', cmdType)
        return getattr(self, '_exec%s' % cmdType)(cmd)

    def _execActionAllow(self, parsedcmd, obs):
        """Execute action `allow`.

        Whatever it is input by attacker, it is already submitted to the backend.
        So to trigger the execution, we just need to write b'\n' to shell
        channel.

        Args:
            parsedcmd: A parsed command to execute
            obs: NOT used.
        """

        log.msg("exec action allow")
        self._execCmd(parsedcmd)

    def _execActionBlock(self, parsedcmd, obs):
        """
        Execute action `block`.

        It perform the following execution flow:
            - Write an error message to the attacker to indicate that
            the "command is not found" using "-bash attacker_command: command not found".
            For root user, the "-" does not appear in the "bash". We ignore it for now.
            - Empty command buffer in the shell on the target machine by sending ^C
            - Prepare fake command history.
        """

        log.msg("exec action block")
        self._execCmd(parsedcmd)

    def _execActionSubstitute(self, parsedcmd, obs):
        """
        Execute action `substitute`.

        It perform the following execution flow:
            - Empty command buffer in the shell on the target machine
            - Select a response from a set of pre-defined responses
            - Write a selected response to the attacker
        """
        log.msg("exec action substitute")
        self._execCmd(parsedcmd)
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

    def _execcomment(self, cmd):
        """
        It is a comment, just ignore it for now
        """
        self.next()

    def _execoperator(self, cmd):
        """
        Execute command based on current operator
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

        .. code-block::
            $ echo input | next_command (in the pipeline)
        """

        log.msg("_execsimple parent state: ", self.parentState)
        log.msg("_execsimple state: ", self.state)
        log.msg("_execsimple substate: ", self.substate)

        tmpFile = self._getCurrentTmpFile()
        if self.cmdLineNumber == 1:
            errmsg = b'-bash: '
        else:
            lineno = bytes(str(self.cmdLineNumber - 1), "utf8")
            errmsg = b'-bash: ' + lineno + b': '

        if self.action == self.env.ACTION_BLOCK:
            # self.pipe = True
            self.input = b''
            # errmsg = b'-bash: ' + bytes(cmd['cmd'], 'utf8') + b': command not found\r\n'
            errmsg += bytes(cmd['cmd'], 'utf8') + b': command not found'
            execcmd = b' (echo ' + errmsg + b' && false)'
            pattern = b' \(echo ' + errmsg + b' && false\)'

            execcmd = b' cat ' + tmpFile + b' | ' + execcmd
            pattern = b' cat ' + tmpFile + b' \| ' + pattern

            if self.operatorCommand:
                execcmd += self.operatorCommand + execcmd
                pattern += self.operatorCommand + pattern
                self.operatorCommand = None

        elif self.action == self.env.ACTION_SUBSTITUTE:
            execcmd = b' cat ' + tmpFile
            pattern = b' cat ' + tmpFile
            if self.operatorCommand:
                execcmd += self.operatorCommand + execcmd
                pattern += self.operatorCommand + pattern
                self.operatorCommand = None
            # we do not need argument for substituted commands
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
            tmpFile = self._getNextTmpFile()
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
            self.nextCmd = execcmd + b' ; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\n'
            self.nextCmdPattern = pattern + b' ; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\r\n'
        else:
            self.nextCmd = execcmd + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\n'
            self.nextCmdPattern = pattern + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\r\n'
        log.msg("pattern to replace XXXX: ", self.nextCmdPattern)
        self.writeToBackend(self.nextCmd)

    def _execsimple(self, cmd):
        """
        Execute simple command, check if we have sub variables and fetch their
        values accordingly.
        """

        log.msg("_execsimple parent state: ", self.parentState)
        log.msg("_execsimple state: ", self.state)
        log.msg("_execsimple substate: ", self.substate)

        if self.cmdLineNumber == 1:
            errmsg = b'-bash: '
        else:
            lineno = bytes(str(self.cmdLineNumber - 1), "utf8")
            errmsg = b'-bash: ' + lineno + b': '

        if self.action == self.env.ACTION_ALLOW:
            execcmd = b' '
            for assignment in cmd['assignments']:
                execcmd += bytes(assignment, 'utf8') + b' '

            execcmd += bytes(cmd['cmd'], 'utf8')
            for arg in cmd['arg']:
                execcmd += b' ' + bytes(arg, 'utf8')
                pattern = execcmd
        elif self.action == self.env.ACTION_BLOCK:
            errmsg += bytes(cmd['cmd'], 'utf8') + b': command not found'
            execcmd = b' (echo ' + errmsg + b' && false)'
            pattern = b' \(echo ' + errmsg + b' && false\)'
        elif self.action == self.env.ACTION_SUBSTITUTE:
            # we still print something to produce empty content
            execcmd = b' (echo "")'
            pattern = b' (echo "")'

        if cmd["output"] == "stdout":
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

                if self.parentState == "compound":
                    # if it is the compound so everything will be redirected
                    # to the same temporary file
                    tmpFile = self._getCurrentTmpFile()
                    execcmd +=  b' >> ' + tmpFile
                    self.previousOutputFile = tmpFile
                elif self.parentState == "pipeline":
                    # if it is the pipeline, so for sure we have a previous
                    # file
                    tmpFile = self.previousOutputFile
                    self.previousOutputFile = None
                    execcmd =  b'cat ' + tmpFile + b' | ' + execcmd
                    tmpFile = self._getNextTmpFile()
                    execcmd +=  b' >> ' + tmpFile
                    self.previousOutputFile = tmpFile

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

        if cmd["output"] == "input":
            self.filteroff = False
            self.pipe = True

            if self.previousOutputFile is None:
                tmpFile = self._getCurrentTmpFile()
                execcmd +=  b' > ' + tmpFile
                self.previousOutputFile = tmpFile
            else:
                tmpFile = self._getNextTmpFile()
                execcmd = b'cat ' + self.previousOutputFile + b' | ' + execcmd + b' > ' + tmpFile
                self.previousOutputFile = tmpFile

            if self.operatorCommand:
                pattern = b'(' + self.operatorPattern + execcmd + b')' + b' > ' + tmpFile
                execcmd = b'(' + self.operatorCommand + execcmd + b')' + b' > ' + tmpFile
                self.operatorCommand = None
                self.substate = "send_backend_list_command_input_with_operator"
            else:
                pattern = execcmd
                self.substate = "send_backend_list_command_input"

            if self.action == self.env.ACTION_SUBSTITUTE:
                self.nextCmd = execcmd + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\n'
                self.nextCmdPattern = pattern + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\r\n'
            elif self.action == self.env.ACTION_BLOCK:
                self.protocol.writeToAttacker(errmsg+b'\r\n')
                self.nextCmd = execcmd + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\n'
                self.nextCmdPattern = pattern + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\r\n'
            elif self.action == self.env.ACTION_ALLOW:
                self.nextCmd = execcmd + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\n'
                self.nextCmdPattern = pattern + b'; printf \'' + self.MAGIC_BYTES + b'{"exit": %d, "cwd": "%s"}\' $? $(pwd)' + b'\r\n'
            self.writeToBackend(self.nextCmd)

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

    def _execpipeline(self, cmd):
        """
        Execute a pipeline
        """
        #FIXME fix state, use different var or manage step
        ####
        ####
        if self.state is None:
            self.state = 'pipeline'
            self.startexec = False
            self._saveContext(cmd)
            self.parentState = 'pipeline'
            self.cmdpending = cmd['cmd']
            self.filteroff = False
            self.next()
        elif self.state == "pipeline":
            if self.parentState is None:
                path = self.previousOutputFile
                self.previousOutputFile = None
                self.filteroff = True
                self.writeToStdOut(path)
            elif self.parentState == "list":
                # self.previousOutputFile = None
                pass
            self.substate = None
            self.state = None
            self.next()
        else:
            self.elseIfIndex = 0
            self.state = None
            self.input = b''
            self.next()

    def _execcompound(self, cmd):
        if self.state is None:
            nextcmd = cmd['cmd']
            if nextcmd[0]['type'] == 'if':
                self._execif(cmd)
            else:
                self.state = 'compound'
                self.startexec = False
                self._saveContext(cmd)
                self.parentState = 'compound'
                self.cmdpending = cmd['cmd']
                self.filteroff = False
                self.next()
        elif self.state == "compound":
            if self.parentState is None:
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


    def _execif(self, cmd):
        if self.action == self.env.ACTION_ALLOW:
            # we execute it directly
            self.writeToBackend(bytes(cmd["cmd_str"], "utf8") + b'\n')
            self.filteroff = True
            self.next()
        elif self.action == self.env.ACTION_BLOCK:
            self.writeToBackend(bytes(cmd["cmd_str"], "utf8") + b'\n')
            self.filteroff = True
            self.next()
        elif self.action == self.env.ACTION_SUBSTITUTE:
            self.next()

    def writeToStdOut(self, path):
        _execmd = b"cat " + path + b'\n'
        self.writeToBackend(_execmd)

    def preparefakehistory(self, cmd):
        self.fakeHistoryCommand = b'history -s "' + bytes(cmd["cmd_str"], "utf8") + b'"\n'
        self.fakeHistoryPattern = b'history -s "' + bytes(cmd["cmd_str"], "utf8") + b'"\n'

    def processExitStatus(self):
        """
        This method will analyse the received buffer and get the exit status of
        the executed command and also the current working directory
        """
        data = self.data
        length = len(data)
        found = data.find(self.MAGIC_BYTES)
        try:
            if found >= 0:
                status = json.loads(s=data[found + 5:])
                self.exitStatus = status['exit']
                self.cwd = status['cwd']
            self.data = data[0:found]
            log.msg("exit status: ", self.exitStatus)
            log.msg("cwd status: ", self.cwd)
        except  Exception as e:
            self.data = b''
            log.msg("error processing exit status")
            log.msg(e)

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

        log.msg("Buffering data: ", self.data)

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