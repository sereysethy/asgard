# -*- test-case-name: cowrie.test.protocol -*-
# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import re
import os
import socket
import sys
import time
import traceback

from typing import Any
from configparser import Error

from twisted.internet import defer
from twisted.conch import recvline
from twisted.conch.insults import insults
from twisted.internet import error
from twisted.protocols.policies import TimeoutMixin
from twisted.python import failure, log

from cowrie.core.config import CowrieConfig
from cowrie.shell import command

from smartproxy.realssh import channel
from smartproxy.utils import common

def strip_ansi_codes(s):
    # return re.sub(b'\x1b\[([0-9,A-Z@]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?', b'', s)
    return re.sub(b'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', b'', s)

def strip_os_codes(s):
    return re.sub(b'\x1b\]?(\d;)([@\w: ~$/]*)\x07', b'', s)

def strip_csi_P_codes(s):
    # CSI Ps P  Delete Ps Character(s) (default = 1) (DCH).
    # remove \x1b[XXP XX is number of characters to delete
    return re.sub(b'\x1b\[[0-9]*[P]', b'', s)

def get_text(s):
    reg = re.compile(b"[ .\w\r\n\d]*nproc@honeypot:~\$ (\w*)")
    r = reg.search(s)
    if r:
        input = r.group(1)
        _r = bytes_to_array(input)
        return _r
    else:
        _r = list()
        return list()

def bytes_to_array(b):
    l = []
    for i in b:
        l.append(i.to_bytes(1, byteorder='big'))
    return l

class HoneyPotBaseProtocol(insults.TerminalProtocol, TimeoutMixin):
    """
    Base protocol for interactive and non-interactive use.

    This class was originally taken from the Cowrie project.
    It is a base honeypot protocol class that implements the TerminalProtocol
    from the twisted insults class.

    This class is invoked to handle the interaction between
    the attacker and the backend system for both interactive and non-interactive
    use.

    Args:
        user:   it is known as an avatar of a user that connects to
                this session.
    """

    commands = {}

    termstate = b"input"
    cmdState = b"input"
    substate = None
    action = 0
    fakeHistoryCommand= None
    fakeHistoryPattern = None
    shell = None
    # client request, it is init by each sub class
    request: bytes = None
    # flag to indicate when the timeout has been reached
    timeoutReached = 0
    # everything is setup to receive commands
    setup_ready = False
    def __init__(self, user: Any):
        self.user = user
        self.environ = self.user.environ
        self.hostname: str = self.user.server.hostname
        self.fs = self.user.server.fs
        self.pp = None
        self.logintime: float
        self.realClientIP: str
        self.realClientPort: int
        self.kippoIP: str
        self.clientIP: str
        self.sessionno: int
        self.factory = None
        self.return_key = False
        self.username = self.user.username
        # get set later when connection is made
        self.password = None

        if self.fs.exists(user.avatar.home):
            self.cwd = user.avatar.home
        else:
            self.cwd = "/"
        self.data = b''
        self.password_input = False
        self.cmdstack = []

        # BEGIN SMP
        # 'targetPrompt' will be re-init in shell, after the connection to the
        # backend is finished.
        self.targetPrompt = bytes(CowrieConfig.get("proxy", "target_prompt"), "utf8")

        self.mode = "insert"
        self.expectPrompt = False

        # RL agent and environment, they will be set later when the connection
        # is made.
        self.agent = None
        self.env = None

        # It holds the connection to the backend for exec and shell-pty
        self.backendConn = None
        # It holds the channel for scp
        self.backendChannel = None

        self.remoteWindow: int = self.user.remote['remoteWindow']
        self.remoteMaxPacket: int = self.user.remote['remoteMaxPacket']
        # END SMP

    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need provide how we grab
        the proper transport to access underlying SSH information. Meant to be
        overridden for other protocols.
        """
        return self.terminal.transport.session.conn.transport

    def logDispatch(self, **args):
        """
        Send log directly to factory, avoiding normal log dispatch
        """
        args["sessionno"] = self.sessionno
        self.factory.logDispatch(**args)

    def connectionMade(self):
        pt = self.getProtoTransport()
        # we cancel the timeout in the transport, if the attacker already opens
        # a shell or executes commands.
        pt.setTimeout(None)

        self.factory = pt.factory
        self.sessionno = pt.transport.sessionno
        self.realClientIP = pt.transport.getPeer().host
        self.realClientPort = pt.transport.getPeer().port
        self.logintime = time.time()
        self.agent = self.factory.agent
        self.env = self.factory.env
        self.password = pt.transport.password.decode("utf8")
        self.transportId = pt.transportId
        log.msg(eventid="cowrie.session.params", arch=self.user.server.arch)

        timeout = CowrieConfig.getint("honeypot", "interactive_timeout", fallback=180)
        self.setTimeout(timeout)

        # Source IP of client in user visible reports (can be fake or real)
        try:
            self.clientIP = CowrieConfig.get("honeypot", "fake_addr")
        except Exception:
            self.clientIP = self.realClientIP

        # Source IP of server in user visible reports (can be fake or real)
        if CowrieConfig.has_option("honeypot", "internet_facing_ip"):
            self.kippoIP = CowrieConfig.get("honeypot", "internet_facing_ip")
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    self.kippoIP = s.getsockname()[0]
            except Exception:
                self.kippoIP = "192.168.0.1"

        """
        BEGIN SMP:
        Make connection to the target machine
        """
        backendConn = pt.transport.backendConn
        self.uid = pt.transport.userinfo["uid"]
        self.gid = pt.transport.userinfo["gid"]
        self._cbTargetMachineReady(backendConn)
        """
        END SMP
        """

    def timeoutConnection(self):
        """
        this logs out when connection times out
        """
        self.timeoutReached = 1
        ret = failure.Failure(error.ProcessTerminated(exitCode=1))
        self.terminal.transport.processEnded(ret)

    def closed(self):
        """
        This is called from channel, when the backend channel is closed.
        This will terminate the connection to attacker.
        """
        if self.terminal:
            self.terminal.transport.loseConnection()

    def connectionLost(self, reason):
        """
        Called when the connection is shut down.
        Clear any circular references here, and any external references to
        this Protocol. The connection has been closed.
        """
        self.setTimeout(None)
        insults.TerminalProtocol.connectionLost(self, reason)
        self.terminal = None  # (this should be done by super above)
        self.cmdstack = []
        self.fs = None
        self.pp = None
        self.user = None
        self.environ = None
        if self.setup_ready and not self.shell.done:
            self.shell.prepareSampleBeforeLosingConnection()

        # we pass the flag timeoutReached to shell, because it it a timeout
        # shell knows how to terminate connection for timeout reached.
        if self.setup_ready:
            self.shell.closeConnection(self.timeoutReached)
            sample = self.shell.getSample()
            self.factory.doTraining(self.transportId, sample)
        self.shell = None
        self.agent = None
        self.env = None
        self.factory = None
        self.backendConn = None

    def txtcmd(self, txt):
        class Command_txtcmd(command.HoneyPotCommand):
            def call(self):
                log.msg(f'Reading txtcmd from "{txt}"')
                with open(txt) as f:
                    self.write(f.read())

        return Command_txtcmd

    def isCommand(self, cmd):
        """
        Check if cmd (the argument of a command) is a command, too.
        """
        return True if cmd in self.commands else False

    def getCommand(self, cmd, paths):
        if not len(cmd.strip()):
            return None
        path = None
        if cmd in self.commands:
            return self.commands[cmd]
        if cmd[0] in (".", "/"):
            path = self.fs.resolve_path(cmd, self.cwd)
            if not self.fs.exists(path):
                return None
        else:
            for i in [f"{self.fs.resolve_path(x, self.cwd)}/{cmd}" for x in paths]:
                if self.fs.exists(i):
                    path = i
                    break

        txt = os.path.normpath(
            "{}/txtcmds/{}".format(CowrieConfig.get("honeypot", "share_path"), path)
        )
        if os.path.exists(txt) and os.path.isfile(txt):
            return self.txtcmd(txt)

        if path in self.commands:
            return self.commands[path]

        log.msg(f"Can't find command {cmd}")
        return None

    def lineReceived(self, line: bytes):
        # Before this, all data is 'bytes'. Here it converts to 'string' and
        # commands work with string rather than bytes.

        line = line.decode("utf8")
        self.attackerInput = line
        log.msg(f"protocol lineReceived: {line}")

    def call_command(self, pp, cmd, *args):
        self.pp = pp
        obj = cmd(self, *args)
        obj.set_input_data(pp.input_data)
        self.cmdstack.append(obj)
        obj.start()

        if self.pp:
            self.pp.outConnectionLost()

    def uptime(self):
        """
        Uptime
        """
        pt = self.getProtoTransport()
        r = time.time() - pt.factory.starttime
        return r

    def eofReceived(self):
        """
        BEGIN SMP:

        This function is called from realssh/insults/LoggingServerProtocol() when
        the attacker signal EOF. So before this would terminate the connection
        immediately by ending the process of the attacker's transport (terminal).

        Update: 15/03/2024: but for now we will hold it open until all the
        connection to backend is established.

        TODO: this should probably not go through transport, but use processprotocol to close stdin
        """

        if self.backendConn:
            if self.terminal and self.terminal.transport:
                # terminate the attacker connection
                ret = failure.Failure(error.ProcessTerminated(exitCode=0))
                self.terminal.transport.processEnded(ret)
                self.terminal = None
            self.backendConn = None

    def _cbTargetMachineReady(self, conn):
        """
        BEGIN SMP:

        This function is called when the connection to target machine
        is ready. It is called by a defer.

        If request is 'shell-pty', we open a shell-pty request to target machine.

        If request is 'exec', we execute a bash to execute the programs.
        """

        self.backendConn = conn
        # attach the connection to backend back to frontend, it is needed to do
        # port forwarding in forwarding file.
        pt = self.getProtoTransport()
        pt.backendConn = conn

        if self.request == b'shell-pty':
            self.backendConn.openChannel(channel.SSHChannelPtyShell(protocol=self,
                                                                    remoteWindow=self.remoteWindow,
                                                                    remoteMaxPacket=self.remoteMaxPacket,
                                                                    conn=self.backendConn))
        if self.request == b'shell':
            self.backendConn.openChannel(channel.SSHChannelShell(protocol=self,
                                                                    remoteWindow=self.remoteWindow,
                                                                    remoteMaxPacket=self.remoteMaxPacket,
                                                                    conn=self.backendConn))
        elif self.request == b'exec':
            self.request = b'bash'
            self.backendConn.openChannel(channel.SSHChannelExecBash(protocol=self,
                                                                    remoteWindow=self.remoteWindow,
                                                                    remoteMaxPacket=self.remoteMaxPacket,
                                                                    conn=self.backendConn))
        elif self.request == b'exec-scp':
            self.backendConn.openChannel(channel.SSHChannelExecScp(protocol=self,
                                                                   remoteWindow=self.remoteWindow,
                                                                   remoteMaxPacket=self.remoteMaxPacket,
                                                                   conn=self.backendConn))
        # everything is ready!
        self.setup_ready = True

    def _ebTargetMachineFailed(self, failure):
        """
        BEGIN SMP:

        This function is called when the connection to target machine
        failed. Maybe we will close connection to attacker.
        """
        log.err(f"Connect to target machine failed: {repr(failure)}")
        pt = self.getProtoTransport()
        pt.transport.loseConnection()

    def write(self, data: bytes):
        """
        BEGIN SMP:

        This function will be called when data is received from target
        machine through a channel. It knows what to do with data
        received, whehter to exit or to show prompt.

        Mode:
            input: data is intercepted and make decision on each newline
            detected.

            interactive: no decision is made, everything should be allowed to
            pass to attacker.

            input: no decision is made, everything should be allowed to pass to
            attacker.
        """
        # init
        isprompt = False

        # accumulate all received data from backend channel
        self.data += data

        log.msg("protocol received data from backend: ", self.data)
        # check if we receievd prompt, then reset everything
        if self.data.find(self.targetPrompt) >= 0:
            log.msg("prompt is detected")
            isprompt = True

        # prompt is detected and we are in TAB mode
        # if we detect \x07
        if isprompt:
            log.msg("tab section")
            log.msg("\tsubstate: ", self.substate)
            # tab character, bash completion
            if self.termstate == b'tab':
                _data = strip_os_codes(self.data)
                log.msg("strip_os_codes: ", _data)
                _data = strip_ansi_codes(_data)
                log.msg("strip_ansi_codes: ", _data)
                self.lineBuffer = get_text(_data)
                self.lineBufferIndex = len(self.lineBuffer)
                self.termstate = b'input'
                log.msg("1) bash completion data: ", self.lineBuffer)
            else:
                # reset everything
                log.msg("reset everything")
                self.termstate = b'input'
                self.substate = None
                self.return_key = False
                self.mode = 'insert'
                self.cmdState = None
                self.lineBuffer = get_text(self.data)
                self.lineBufferIndex = len(self.lineBuffer)
                log.msg("reset everything, self.lineBuffer: ", self.lineBuffer)

        elif self.termstate == b'tab':
            # prompt is not detected and we are in TAB mode
            # if we have a string terminator ST, it means we have a full bash
            # completion
            nbspace = data.count(b' ')
            nbST = data.count(b'\x07')

            if nbspace == 0:
                _data = self.data.replace(b'\r\n', b'')
                _data = _data.replace(b'\x07', b'')
                self.lineBuffer += bytes_to_array(_data)
                self.lineBufferIndex = len(self.lineBuffer)
                self.substate = None
                # self.termstate = b'input'
                log.msg("2) bash completion data: ", self.lineBuffer)
            elif nbspace == 1:
                _data = self.data.replace(b' ', b'')
                self.lineBuffer += bytes_to_array(_data)
                self.lineBufferIndex = len(self.lineBuffer)
                self.substate = None
                self.termstate = b'input'
                log.msg("3) bash completion data: ", self.lineBuffer)
            elif nbST == 1 and len(self.data) == 1:
                self.substate = b'bash_completion_second_tab'
                # _data = data.replace(b'\x07', b'')
                # self.lineBuffer += bytes_to_array(_data)
                # self.lineBufferIndex = len(self.lineBuffer)
                self.substate = None
                self.mode = "insert"
            elif nbST == 1 and len(self.data) > 1:
                self.substate = b'bash_completion_second_tab'
                _data = self.data.replace(b'\x07', b'')
                self.lineBuffer += bytes_to_array(_data)
                self.lineBufferIndex = len(self.lineBuffer)
                self.substate = None
                self.mode = "insert"
                log.msg("4) bash completion data: ", self.lineBuffer)

        if self.termstate == b'history':
            _data = strip_os_codes(self.data)
            _data = strip_ansi_codes(_data)

            # check if backspace detected
            nbBackSpaces = _data.count(b'\x08')

            # there is backspace, some of characters in commands are replaced
            if nbBackSpaces > 0:
                # remove all the backspaces
                _data = _data.replace(b'\x08', b'')
                # check the offset, from which index to replace
                offset = self.lineBufferIndex - nbBackSpaces
                # offset to replace
                if offset > 0:
                    self.lineBuffer = self.lineBuffer[0:offset] + bytes_to_array(_data)
                else:
                # replace all
                    self.lineBuffer = bytes_to_array(_data)
            else:
            # no backspaces detected
            #TODO: NOT Working yet
                log.msg("no backspaces detected.")
                _data = self.data.replace(b'\x07', b'')
                self.lineBuffer += bytes_to_array(_data)
            self.lineBufferIndex = len(self.lineBuffer)
            self.termstate = b'input'

        # in input mode, we write data based on action taken
        if self.termstate == b'input':
            self.terminal.write(self.data)
            self.data = b''

        # in editor mode, we will not intercept anything
        if self.termstate == b'editor':
            log.msg("state: editor")
            self.terminal.write(self.data)
            self.data = b''

        # in interactive mode, we will not intercept anything
        if self.termstate == b'interactive':
            log.msg("state: interactive")
            self.terminal.write(self.data)
            self.data = b''

        if self.termstate == b'tab':
            self.terminal.write(self.data)
            self.data = b''

        # For reminder only:
        # In new shell mode, nothing to be done because we detect a new prompt,
        # and the termstate is set to 'input'. So the following code is not needed.
        # if self.termstate == b'shell':
        #     self.terminal.write(data)

    def writeToAttacker(self, data: bytes):
        """
        Write data directly to attacker without processing anything. There are
        cases where the write function is used.
        """
        log.msg("writeToAttacker:", data)
        if self.terminal:
            self.terminal.write(data)

    def extWrite(self, data: bytes):
        """
        BEGIN SMP:

        This function will be called when extended data is received
        from target machine through a channel. It knows what to do with
        extended data received.
        """
        if self.terminal:
            self.terminal.write(data)

    def getCommandState(self, cmd: str)->bytes:
        """
        Get command category.

        Args:
            cmd: command input by the attacker

        Returns:
            command category
        """
        if cmd in common.EDITOR:
            commandCategory = b"editor"
        elif cmd in common.INTERACTIVE:
            commandCategory = b"interactive"
        elif cmd in common.SHELL:
            commandCategory = b"shell"
        else:
            commandCategory = b"input"

        return commandCategory

    def getTerminalState(self, state: bytes)->bytes:
        """
        Given the type of commands, we also move the terminal
        state that allows us to know what to do with data received
        from backend.

        This terminal state can be:
        - data: no filter, everything is forwarded to attacker terminal
        - tab: bash completion
        - history: command history

        Args:
            state: state of the current terminal

        Returns:
            state of the terminal
        """

        termstate = b""
        if state == b"editor":
            termstate = b"editor"
        elif state == b"interactive":
            termstate = b"interactive"
        elif state == b"shell":
            termstate = b"shell"
        else:
            termstate = b"input"

        return termstate

class HoneyPotExecProtocol(HoneyPotBaseProtocol):
    """
    Class to handle non-interactive session.
    """

    # input_data is static buffer for stdin received from remote client
    input_data: bytes = b""
    request: bytes = b'exec'
    cmdstackindex: int = 0
    cmdexecstacks = []
    index:int = 0
    exec_running: bool = True

    def __init__(self, user: Any, execcmd: bytes):
        # Before this, execcmd is `bytes`. Here it converts to `string` and
        # commands work with string rather than bytes.

        try:
            self.execcmd = execcmd.decode("utf8")

        except UnicodeDecodeError:
            log.err(f"Unusual execcmd: {repr(execcmd)}")
        HoneyPotBaseProtocol.__init__(self, user)

        # load shell as defined in the configuration file section "rl"
        shellName = CowrieConfig.get("rl", "shell_exec_name")
        if shellName == "ShellComplexParsingForExec":
            from smartproxy.command.shell_complex_parsing_exec import ShellComplexParsingForExec
            self.shell = ShellComplexParsingForExec(self.username)
        elif shellName == "ShellComplexOneHotExec":
            from smartproxy.command.shell_onehot_exec import ShellComplexOneHotExec
            self.shell = ShellComplexOneHotExec(self.username)
        elif shellName == "ShellRobertaExec":
            from smartproxy.command.shell_roberta_exec import ShellRobertaExec
            self.shell = ShellRobertaExec(self.username)
        else:
            raise Exception("shell not found")

    def connectionMade(self):
        HoneyPotBaseProtocol.connectionMade(self)
        self.shell.addAgentAndEnv(self.agent, self.env)

        log.msg(eventid="cowrie.command.input", input=self.execcmd, format="CMD: %(input)s")
        self.cmdstack = self.execcmd.split('\n')

    def eofReceived(self):
        """
        This function is called from realssh/insults/LoggingServerProtocol() when
        the attacker signal EOF. So before this would terminate the connection
        immediately by ending the process of the attacker's transport (terminal).

        Update: 15/03/2024: but for now we will hold it open until all the
        connection to backend is established.

        TODO: this should probably not go through transport, but use processprotocol to close stdin
        """
        if self.exec_running:
            log.msg("exec is running")
            return
        # call parent class
        HoneyPotBaseProtocol.eofReceived(self)

    def keystrokeReceived(self, keyID, modifier):
        self.input_data += keyID

    def dataReceived(self, data):
        """
        Data received from attacker's terminal when bash is invoked.

        This function is only called when we are in input mode.

        Args:
            data: (bytes)
        """
        # if we still keep receiving data from the attacker, reset the timeout
        self.resetTimeout()

        log.msg(f"dataReceived from attacker, data: {data}")
        log.msg(f"dataReceived from attacker, state: {self.termstate}")

        self.cmdState = self.getCommandState(data)
        self.termstate = self.getTerminalState(self.cmdState)
        if self.cmdState == b'input':
            line = data.strip(b'\n')
            line = line.decode('utf-8')
            # self.attackerInput = None
            self.makeDecision(line)
        elif self.cmdState == b'editor':
            self.backendChannel.write(data)
        elif self.cmdState == b'interactive':
            self.backendChannel.write(data)
        else:
            self.backendChannel.write(data)

    def cbAnalyseInput(self, data: bytes):
        """
        This function is invoked when when bash is executed in the target
        machine. It can be invoked by the backend channel or it can be invoked
        when unknown commands are input.

        1   ssh xxx cd\\npwd\\nxxx

        """

        data = data.strip(b'\n')
        log.msg(f"data received: {data}")
        if data == b'':
            log.msg("data is empty")
            self.executeNextCommand()
        else:
            hint = data.decode('utf8')
            if hint == self.lookahead():
                log.msg("hint matches stack head")
                self.popstack()
                self.executeNextCommand()
            else:
                log.msg("hint doesnt match stack head")
                self.executeNextCommand()

    def executeNextCommand(self):
        """
        Execute command in the command stack when first passed from the attacker
        in exec mode.

        If there is a command to execute in command stack, we execute it and
        then make a decision on it. If there is no more command to execute,
        and we are not in any contextual command, then close the channel.
        """

        if self.cmdstackindex < len(self.cmdstack):
            line = self.cmdstack[self.cmdstackindex]
            self.cmdstackindex += 1
            if line != '':
                self.makeDecision(line)
            else:
                self.executeNextCommand()
        elif self.stackIsEmpty():
            self.exec_running = False
            self.closeChannel()

    def closeChannel(self):
        """
        This function is used to closed the channle that we open to
        execute command in exec mode.

        It is called after there is no more command to execute or it can be
        called by the backend channel, when there is a problem like the
        attacker already closed the frontend channel, which will delete the
        shell.
        """

        self.backendChannel.loseConnection()
        del self.backendChannel

    def lookahead(self)->str:
        """
        Return the head of the stack if stack is not empty otherwise, return
        an empty string.

        Returns:
            value on the stack head
        """

        if len(self.cmdexecstacks) > 0:
            log.msg("lookahead: ", self.cmdexecstacks[-1])
            return self.cmdexecstacks[-1]
        else:
            log.msg("empty")
            return ""

    def pushstack(self, cmd)->None:
        """
        Push a hint to stack indicating a command is about to execute

        Args:
            cmd: (str) not used

        Return:
            None
        """
        hint = "XXXXXXX" + str(self.index)
        self.index += 1
        self.cmdexecstacks.append(hint)

        return hint

    def popstack(self)->str:
        return self.cmdexecstacks.pop()

    def stackIsEmpty(self)->bool:
        """
        Check if stack is empty.
        """
        return len(self.cmdexecstacks) == 0

    def makeDecision(self, line):
        """
        Make decision on each command input

        @param line: {str} attacker command line buffer
        """
        log.msg("we got a return, makeDecision")
        log.msg(eventid="cowrie.command.input", input=line, format="CMD: %(input)s")
        self.shell.makeDecision(self.cmdstackindex, line)

    def _execActionAllow(self, parsedcmd, obs):
        """Execute action `allow`.

        Write b'\n' to shell channel on the target machine to trigger the execution

        case:
            cmd is empty, send just echo ""
            cmd is not empty:
                cmd is unknwon
        """
        cmd = parsedcmd["cmd_str"]

        log.msg("exec action allow for cmd: ", cmd)
        if obs == self.env.UNKNOWN_COMMAND_IX:
            self._execUnknownCmd(cmd, obs)
        else:
            if isinstance(cmd, str):
                cmd = cmd.encode("utf-8")

            if cmd != b'':
                cmd = cmd.strip(b'\n')
                self.backendChannel.write(cmd + b'; ')

            if cmd == b'exit':
                self.backendChannel.write(b'\n')
            else:
                motif = self.pushstack(cmd)
                m = b'echo ' + bytes(motif, "utf-8") + b'\n'
                self.backendChannel.write(m)

    def _execUnknownCmd(self, parsedcmd, obs):
        """
        Execute an unknown command in "allow" mode.

        Just transmit everything as it is sent from attacker.
        """

        cmd = parsedcmd["cmd"]
        # convert it to bytes first if it in str.
        if isinstance(cmd, str):
            cmd = cmd.encode("utf-8")

        # if cmd is empty byte, which can happen.
        if cmd == b'':
            motif = self.pushstack(cmd)
            m = b'echo ' + bytes(motif, "utf-8") + b'\n'
            self.backendChannel.write(m)
        else:
            self.backendChannel.write(cmd + b'\n')
            # invoke the next input from the command stack
            self.cbAnalyseInput(b'')

    def _execActionBlock(self, parsedcmd, obs):
        """
        Execute action `block`.

        - write an error message to the attacker to indicate that the
        command is not found using the following format:
            "bash: line __LINE_NUM__: __CMD_NAME__: command not found"
        - send an echo to backend to invoke the next command if any
        """
        log.msg("exec action block")

        cmd = parsedcmd["cmd"]
        # convert it to bytes first if it in str.
        if isinstance(cmd, str):
            cmd = cmd.encode("utf-8")

        linenumber = bytes(str(self.cmdstackindex - 1), "utf8")
        extdata = b'bash: line ' + linenumber + b': ' + cmd + b': command not found\n'

        self.write(extdata)
        motif = self.pushstack(cmd)
        m = b'echo ' + bytes(motif, "utf-8") + b'\n'
        self.backendChannel.write(m)

    def _execActionSubstitute(self, parsedcmd, obs):
        """Execute action `substitute`.

        - Select a response from a set of pre-defined responses of each command
        - Write a selected response to the attacker
        - Send echo + motif to backend to invoke the next command
        """
        log.msg("exec action substitute")
        cmd = parsedcmd["cmd_str"]
        if isinstance(cmd, str):
            cmd = cmd.encode("utf-8")

        self.write(cmd + b'cmd is substituted\r\r\n')

        if cmd != b'':
            args = parsedcmd["arg"]
            c = self.commands[parsedcmd["cmd"]](self.terminal, args)
            c.start()

        motif = self.pushstack(cmd)
        m = b'echo ' + bytes(motif, "utf-8") + b'\n'
        self.backendChannel.write(m)

class HoneyPotInteractiveProtocol(HoneyPotBaseProtocol, recvline.HistoricRecvLine):
    request = b'shell-pty'

    def __init__(self, user: Any):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotBaseProtocol.__init__(self, user)
        self.shell_ready: bool = False
        self.buf: bytes = b''

        shellName = CowrieConfig.get("rl", "shell_interactive_name")
        if shellName == "ShellComplexParsing":
            from smartproxy.command.shell_complex_parsing import ShellComplexParsing
            self.shell = ShellComplexParsing(self.username)
        elif shellName == "ShellComplexOneHot":
            from smartproxy.command.shell_onehot import ShellComplexOneHot
            self.shell = ShellComplexOneHot(self.username)
        elif shellName == "ShellRoberta":
            from smartproxy.command.shell_roberta import ShellRoberta
            self.shell = ShellRoberta(self.username)
        else:
            raise Exception("shell not found")

    def connectionMade(self):
        HoneyPotBaseProtocol.connectionMade(self)
        recvline.HistoricRecvLine.connectionMade(self)
        self.shell.addAgentAndEnv(self.agent, self.env)

    def displayMOTD(self):
        pass
        # try:
        #     self.terminal.write(self.fs.file_contents("/etc/motd"))
        # except Exception:
        #     pass

    def timeoutConnection(self):
        """
        this logs out when connection times out
        """
        self.terminal.write(b"timed out waiting for input: auto-logout\n")
        HoneyPotBaseProtocol.timeoutConnection(self)

    def connectionLost(self, reason):
        HoneyPotBaseProtocol.connectionLost(self, reason)
        recvline.HistoricRecvLine.connectionLost(self, reason)
        self.keyHandlers = {}

    def initializeScreen(self):
        """
        Overriding super to prevent terminal.reset()
        """
        # self.setInsertMode()
        pass

    def call_command(self, pp, cmd, *args):
        self.pp = pp
        self.setTypeoverMode()
        HoneyPotBaseProtocol.call_command(self, pp, cmd, *args)

    def characterReceived(self, ch, moreCharactersComing):
        """
        Easier way to implement password input?

        This function is invoked before the dataReceived() of this
        protocol. Normally there should be no dataReceived method here,
        because everything should be handled by the ServerProtocol.
        """
        log.msg(f"characterReceived, termstate: {self.termstate}")
        log.msg(f"characterReceived mode: {self.mode}")
        if self.mode == "insert":
            self.lineBuffer.insert(self.lineBufferIndex, ch)
            self.lineBufferIndex += 1
        elif self.termstate != b'tab':
            # if we are not in a bash completion mode
            self.lineBuffer[self.lineBufferIndex : self.lineBufferIndex + 1] = [ch]
            self.lineBufferIndex += 1
        log.msg(f"characterReceived: {self.lineBuffer}")

    def _cbEmptyBuf(self):
        """This is called from backend when channel is open."""
        self.shell_ready = True
        self.dataReceived(self.buf)
        self.buf = b''

    def dataReceived(self, data: bytes):
        """
        Data received from the attacker's terminal. This function is called
        from the "dataReceived" in realssh/insults/LoggingServerProtocol, a wrapper class.
        Its function is to transmit data to the backend. It serves as a proxy
        to the backend and also start making decision when a RETURN key is
        detected by calling the "makeDecision()" of the respective "shell".

        Before data, dataReceived of the LoggingServerProtocol was already
        called, which will invoke keystrokeReceived(), which will call other
        methods to handle keystroke like "_handleControlSequence()" for
        control sequences or "characterReceived()" for character received.

        It will also unhandledControlSequence() for unknown control sequence, which
        has to be implemented by this protocol.

        Args:
            data: containing data from the attacker's terminal
        """

        # if we keep receiving data from the attacker, reset the timeout
        self.resetTimeout()

        log.msg(f"dataReceived from attacker, termstate: {self.termstate}")
        log.msg(f"dataReceived from attacker, cmdState: {self.cmdState}")
        log.msg(f"dataReceived from attacker, data: {data}")
        log.msg(f"dataReceived self.return_key: {self.return_key}")

        if not self.shell_ready:
            self.buf += data
            return

        if self.termstate == b'input':
            if self.return_key:
                self.return_key = False
                line = self.attackerInput
                self.attackerInput = None
                log.msg(eventid="cowrie.command.input", input=line, format="CMD: %(input)s")
                self.makeDecision(line)
            else:
                self.backendChannel.write(data)
        elif self.termstate == b'editor':
            self.backendChannel.write(data)
        elif self.termstate == b'interactive':
            self.backendChannel.write(data)
        else:
            self.backendChannel.write(data)

    def makeDecision(self, line: str):
        """
        Args:
            line: attacker command line buffer
        """

        log.msg("we got a return, thinking...")
        log.msg(f"input line: {line}")
        self.shell.makeDecision(line)
        # we change the state after the decision is made
        self.cmdState = self.getCommandState(line)
        self.termstate = self.getTerminalState(self.cmdState)
        log.msg(f"command state: {self.cmdState}")
        log.msg(f"terminal state: {self.termstate}")

    def windowChanged(self, windowSize):
        """
        Window change request received from attacker's terminal
        """
        self.backendChannel.windowChanged(windowSize)

    def handle_RETURN(self):
        self.return_key = True
        line = b"".join(self.lineBuffer)
        self.lineBuffer = []
        self.lineBufferIndex = 0
        if self.termstate == b'tab':
            self.termstate = b'input'

        self.lineReceived(line)

    def handle_CTRL_C(self):
        if len(self.cmdstack):
            self.cmdstack[-1].handle_CTRL_C()

    def handle_CTRL_D(self):
        if len(self.cmdstack):
            self.cmdstack[-1].handle_CTRL_D()

    def handle_TAB(self):
        if self.termstate == b'input':
            self.termstate = b'tab'
            self.mode = None
        if self.termstate == b'tab' and self.substate is None:
            self.substate = b'bash_completion_first_tab'
        # if len(self.cmdstack):
        #     self.cmdstack[-1].handle_TAB()

    def handle_CTRL_K(self):
        # self.terminal.eraseToLineEnd()
        # self.lineBuffer = self.lineBuffer[0 : self.lineBufferIndex]
        pass

    def handle_CTRL_L(self):
        """
        Handle a 'form feed' byte - generally used to request a screen
        refresh/redraw.
        """
        # self.terminal.eraseDisplay()
        # self.terminal.cursorHome()
        # self.drawInputLine()
        pass

    def handle_CTRL_U(self):
        pass
        # for _ in range(self.lineBufferIndex):
        #     self.terminal.cursorBackward()
        #     self.terminal.deleteCharacter()
        # self.lineBuffer = self.lineBuffer[self.lineBufferIndex :]
        # self.lineBufferIndex = 0

    def handle_CTRL_V(self):
        pass

    def handle_ESC(self):
        pass

    def handle_UP(self):
        # self.backendChannel.write(b'\x1b[A')
        if self.termstate == b'input':
            self.termstate = b'history'

    def handle_DOWN(self):
        # self.backendChannel.write(b'\x1b[B')
        if self.termstate == b'input':
            self.termstate = b'history'

    def handle_LEFT(self):
        """
        Overwrite LEFT arrow key.
        """
        if self.lineBufferIndex > 0:
            self.lineBufferIndex -= 1
            # self.terminal.cursorBackward()

    def handle_RIGHT(self):
        """
        Overwrite RIGHT arrow key.
        """
        if self.lineBufferIndex < len(self.lineBuffer):
            self.lineBufferIndex += 1
            # self.terminal.cursorForward()

    def handle_HOME(self):
        """
        Overwrite HOME key
        """
        if self.lineBufferIndex:
            # self.terminal.cursorBackward(self.lineBufferIndex)
            self.lineBufferIndex = 0

    def handle_END(self):
        """
        Overwrite END key
        """
        offset = len(self.lineBuffer) - self.lineBufferIndex
        if offset:
            # self.terminal.cursorForward(offset)
            self.lineBufferIndex = len(self.lineBuffer)

    def handle_BACKSPACE(self):
        """
        Overwrite BACKSPACE key.
        """
        if self.lineBufferIndex > 0:
            self.lineBufferIndex -= 1
            del self.lineBuffer[self.lineBufferIndex]
            # self.terminal.cursorBackward()
            # self.terminal.deleteCharacter()

    def handle_DELETE(self):
        """
        Overwrite DELETE key.
        """
        if self.lineBufferIndex < len(self.lineBuffer):
            del self.lineBuffer[self.lineBufferIndex]
            # self.terminal.deleteCharacter()

    def unhandledControlSequence(self, seq):
        """
        Called when an unsupported control sequence is received.

        We implement this to treate the two control keys that are from
        Mac, which are the same as ARROW_UP and ARROW_DOW.

        https://github.com/Textualize/textual/wiki/Key-names-and-escape-sequences

        b'\x1bOA' 	ctrl-up (urxvt-Darwin) 	#3739
        b'\x1bOB' 	ctrl-down (urxvt-Darwin)

        But twisted also erronously adds this character b'[' to the received code.

        @type seq: L{str}
        @param seq: The whole control sequence which could not be interpreted.
        """

        # so we will compare the two just in case twisted updates it package
        if seq == b"\x1b[OA" or seq == b"\x1bOA":
            self.handle_UP()
        elif seq == b"\x1b[OB" or seq == b"\x1bOB":
            self.handle_DOWN()

class HoneyPotShellProtocol(HoneyPotExecProtocol):
    # @override
    request: str = b'shell'
    # @override
    exec_running: bool = False

    def __init__(self, user):
        """
        Override to not use execmd that was sent for exec.
        This is shell session but no pty. Commands are sent like input.
        """

        # not used, commands are received
        self.execcmd: bytes = b''
        # it starts at 1, because shell already returns a banner, at least
        # that is what real ssh does.
        self.cmdstackindex: int = 1
        # to hold commands when there is commands being executed
        self.pendingCommands: list = []

        HoneyPotExecProtocol.__init__(self, user, self.execcmd)

    def dataReceived(self, data):
        """
        @override to manage the cmdLineIndex
        Data received from attacker's terminal when bash is invoked.

        This function is only called when we are in input mode.

        params:
            data: (bytes)
        """
        # if we still keep receiving data from the attacker, reset the timeout
        self.resetTimeout()

        log.msg(f"dataReceived from attacker, data: {data}")
        log.msg(f"dataReceived from attacker, state: {self.termstate}")

        self.cmdState = self.getCommandState(data)
        self.termstate = self.getTerminalState(self.cmdState)
        if self.cmdState == b'input':
            line = data.strip(b'\n')
            line = line.decode('utf-8')
            self.pendingCommands.append(line)
            if not self.exec_running:
                self.executeNextCommand()
        elif self.cmdState == b'editor':
            self.backendChannel.write(data)
        elif self.cmdState == b'interactive':
            self.backendChannel.write(data)
        else:
            self.backendChannel.write(data)

    def eofReceived(self):
        """
        @override it is a normal super parent eofReceived.
        """

        # call parent class
        HoneyPotBaseProtocol.eofReceived(self)

    def executeNextCommand(self) -> None:
        """
        @overide

        All commands received from attackers are stored in pending commands.
        It will be executed one by one to avoid race condition, when an attacker
        keeps sending commands.

        If there is still a pending command, pop it and execute it.
        """

        if self.pendingCommands:
            self.exec_running = True
            line = self.pendingCommands.pop()
            if line != '':
                # increment the line index for each command to execute
                self.cmdstackindex += 1
                self.makeDecision(line)
            else:
                self.executeNextCommand()
        else:
            self.exec_running = False
