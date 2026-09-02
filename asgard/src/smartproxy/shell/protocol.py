# -*- test-case-name: cowrie.test.protocol -*-
# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information


import os
import socket
import sys
import time
import traceback
from typing import Any

from twisted.conch import recvline
from twisted.conch.insults import insults
from twisted.internet import error
from twisted.protocols.policies import TimeoutMixin
from twisted.python import failure, log

# import cowrie.commands
from cowrie.core.config import CowrieConfig
from cowrie.shell import command

#BEGIN SMP:
import re
from twisted.internet import reactor
from twisted.internet import defer

from smartproxy.shell import honeypot
from smartproxy.realssh import factory as clientfactory
from smartproxy.realssh import channel
from smartproxy.command import shell_simple_parsing as shell
from smartproxy.utils import common
import smartproxy.commands
#END SMP

def strip_ansi_codes(s):
    # return re.sub(b'\x1b\[([0-9,A-Z@]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?', b'', s)
    return re.sub(b'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', b'', s)

def strip_os_codes(s):
    return re.sub(b'\x1b\]?(\d;)([@\w: ~$]*)\x07', b'', s)

def strip_csi_P_codes(s):
    # CSI Ps P  Delete Ps Character(s) (default = 1) (DCH).
    # remove \x1b[XXP XX is number of characters to delete
    return re.sub(b'\x1b\[[0-9]*[P]', b'', s)

def get_text(s):
    reg = re.compile(b"[ .\w\r\n\d]*nproc@honeypot:~\$ (\w*)")
    r = reg.search(s)
    if r:
        print("get_text: ", r.groups())
        print("get_text: ", r.group(1))
        input = r.group(1)
        _r = bytes_to_array(input)
        print("get_text match: ", _r)
        return _r
    else:
        _r = list()
        print("get_text not match: ", _r)
        return list()

def bytes_to_array(b):
    l = []
    for i in b:
        l.append(i.to_bytes(1, byteorder='big'))
    return l

class HoneyPotBaseProtocol(insults.TerminalProtocol, TimeoutMixin):
    """
    Base protocol for interactive and non-interactive use
    """

    commands = {}
    for c in smartproxy.commands.__all__:
        try:
            module = __import__(
                f"smartproxy.commands.{c}", globals(), locals(), ["commands"]
            )
            commands.update(module.commands)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            log.err(
                "Failed to import command {}: {}: {}".format(
                    c,
                    e,
                    "".join(
                        traceback.format_exception(exc_type, exc_value, exc_traceback)
                    ),
                )
            )

    termstate = b"input"
    cmdState = b"input"
    substate = None
    action = 0
    fakeHistoryCommand= None
    fakeHistoryPattern = None

    def __init__(self, user):
        self.user = user
        self.environ = user.environ
        self.hostname: str = user.server.hostname
        self.fs = user.server.fs
        self.pp = None
        self.logintime = None
        self.realClientIP = None
        self.realClientPort = None
        self.kippoIP = None
        self.clientIP = None
        self.sessionno = None
        self.factory = None
        self.return_key = False
        self.shell = shell.ShellSimpleParsing()

        if self.fs.exists(user.avatar.home):
            self.cwd = user.avatar.home
        else:
            self.cwd = "/"
        self.data = b''
        self.password_input = False
        self.cmdstack = []
        self.targetHostname = bytes(CowrieConfig.get("proxy", "target_hostname"), "utf8")
        self.targetPrompt = bytes(CowrieConfig.get("proxy", "target_prompt"), "utf8")
        self.mode = "insert"
        self.expectPrompt = False

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

        self.factory = pt.factory
        self.sessionno = pt.transport.sessionno
        self.realClientIP = pt.transport.getPeer().host
        self.realClientPort = pt.transport.getPeer().port
        self.logintime = time.time()

        log.msg(eventid="cowrie.session.params", arch=self.user.server.arch)

        # timeout = CowrieConfig.getint("honeypot", "interactive_timeout", fallback=180)
        # self.setTimeout(timeout)

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
        username = CowrieConfig.get('proxy', 'backend_user')
        password = CowrieConfig.get('proxy', 'backend_pass')
        server = CowrieConfig.get('proxy', 'backend_ssh_host')
        port = CowrieConfig.getint('proxy', 'backend_ssh_port')
        self.d = defer.Deferred()
        self.d.addCallback(self._cbTargetMachineReady)
        self.d.addErrback(self._ebTargetMachineFailed)

        sshClientfactory = clientfactory.SSHClientFactory(username, password, self)
        reactor.connectTCP(server, port, sshClientfactory)
        """
        END SMP
        """
    def timeoutConnection(self):
        """
        this logs out when connection times out
        """
        ret = failure.Failure(error.ProcessTerminated(exitCode=1))
        self.terminal.transport.processEnded(ret)

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

    def lineReceived(self, line):
        """
        IMPORTANT
        Before this, all data is 'bytes'. Here it converts to 'string' and
        commands work with string rather than bytes.
        """
        line = line.decode("utf8")
        self.attackerInput = line
        # if len(self.cmdstack):
        #     self.cmdstack[-1].lineReceived(line)
        # else:
        #     log.msg(f"discarding input {line}")
        log.msg(f"protocol lineReceived: {line}")
        # self.backendChannel.write(b'\n')
        # pass

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
        # Shell received EOF, nicely exit
        """
        TODO: this should probably not go through transport, but use processprotocol to close stdin
        """
        ret = failure.Failure(error.ProcessTerminated(exitCode=0))
        self.terminal.transport.processEnded(ret)

    def _cbTargetMachineReady(self, conn):
        """
        BEGIN SMP:

        This function is called when the connection to target machine
        is ready. It is called by a defer.

        If request is 'shell-pty', we open a shell-pty request to target machine.

        If request is 'exec', we execute a bash to execute the programs.
        """

        self.backendConn = conn

        if self.request == b'shell-pty':
            self.backendConn.openChannel(channel.SSHChannelPtyShell(protocol=self, conn=self.backendConn))
            # self.backendConn.openChannel(channel.SSHChannel(protocol=self, conn=self.backendConn))
        elif self.request == b'exec':
            self.request = b'bash'
            self.backendConn.openChannel(channel.SSHChannel(protocol=self, conn=self.backendConn))
            # self.analyseInput()
        # else:
        #     self.backendConn.openChannel(channel.SSHChannel(protocol=self, conn=self.backendConn))


    def _ebTargetMachineFailed(self):
        """
        BEGIN SMP:

        This function is called when the connection to target machine
        failed. Maybe we will close connection to attacker.
        """

        log.err(f"Connect to target machine failed: {repr(failure)}")
        pt = self.getProtoTransport()
        pt.transport.loseConnection()


    def write(self, data):
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

        print("protocol received data from backend: ", data)
        # check if we receievd prompt, then reset everything
        if data.find(self.targetPrompt) >= 0:
            log.msg("prompt is detected")
            isprompt = True

        # prompt is detected and we are in TAB mode
        # if we detect \x07
        if isprompt:
            print("tab section")
            print("\tsubstate: ", self.substate)
            # tab character, bash completion
            if self.termstate == b'tab':
                _data = strip_os_codes(data)
                print("strip_os_codes: ", _data)
                _data = strip_ansi_codes(_data)
                print("strip_ansi_codes: ", _data)
                self.lineBuffer = get_text(_data)
                self.lineBufferIndex = len(self.lineBuffer)
                self.termstate = b'input'
                print("1) bash completion data: ", self.lineBuffer)
            else:
                # reset everything
                print("reset everything")
                self.termstate = b'input'
                self.return_key = False
                self.mode = 'insert'
                self.cmdState = None
        elif self.termstate == b'tab':
            # prompt is not detected and we are in TAB mode
            # if we have a string terminator ST, it means we have a full bash
            # completion
            nbspace = data.count(b' ')
            nbST = data.count(b'\x07')
            print("nbST: ", nbST)
            if nbspace == 1:
                _data = data.replace(b' ', b'')
                self.lineBuffer += bytes_to_array(_data)
                self.lineBufferIndex = len(self.lineBuffer)
                self.substate = None
                self.termstate = b'input'
                print("2) bash completion data: ", self.lineBuffer)
            elif nbST == 1 and len(data) == 1:
                self.substate = b'bash_completion_second_tab'
                # _data = data.replace(b'\x07', b'')
                # self.lineBuffer += bytes_to_array(_data)
                # self.lineBufferIndex = len(self.lineBuffer)
                self.substate = None
                self.mode = "insert"
            elif nbST == 1 and len(data) > 1:
                self.substate = b'bash_completion_second_tab'
                _data = data.replace(b'\x07', b'')
                self.lineBuffer += bytes_to_array(_data)
                self.lineBufferIndex = len(self.lineBuffer)
                self.substate = None
                self.mode = "insert"
                print("3) bash completion data: ", self.lineBuffer)

        if self.termstate == b'history':
            print("cmdState: history")
            _data = strip_os_codes(data)
            _data = strip_ansi_codes(_data)
            # _data = strip_csi_P_codes(_data)
            print("history clean data:", _data)
            # check if backspace detected
            nbBackSpaces = _data.count(b'\x08')
            print("history before linebuffer: ", self.lineBuffer)
            print("history before linebufferindex: ", self.lineBufferIndex)
            # there is backspace, some of characters in commands are replaced
            if nbBackSpaces > 0:
                print("backspace detected")
                # remove all the backspaces
                _data = _data.replace(b'\x08', b'')
                # check the offset, from which index to replace
                offset = self.lineBufferIndex - nbBackSpaces
                # offset to replace
                if offset > 0:
                    print("offset > 0:", offset)
                    self.lineBuffer = self.lineBuffer[0:offset] + bytes_to_array(_data)
                else:
                    print("offset < 0:", offset)
                # replace all
                    self.lineBuffer = bytes_to_array(_data)
            else:
            # no backspaces detected
            #TODO: NOT Working yet
                print("no backspaces detected.")
                _data = data.replace(b'\x07', b'')
                self.lineBuffer += bytes_to_array(_data)
            self.lineBufferIndex = len(self.lineBuffer)
            self.termstate = b'input'
            print("history after linebuffer: ", self.lineBuffer)
            print("history after linebufferindex: ", self.lineBufferIndex)

        # in input mode, we write data based on action taken
        if self.termstate == b'input':
            if self.action == self.shell.env.ACTION_ALLOW:
                self.terminal.write(data)
                # self.action = None
            elif self.action == self.shell.env.ACTION_BLOCK:
                print("block action, substate: ", self.substate)
                # replace any '^C' characters when we sent ^C to empty string
                # buffer
                data = data.replace(b'^C', b'')
                # replace fake history command
                data = data.replace(self.fakeHistoryPattern, b'')
                if isprompt:
                    # if we got prompt, it meant we got the reply
                    # two cases to consider
                    # substate 1, we will send the fake history command
                    if self.substate == b'send_backend_empty_buffer':
                        print("block action, write to attacker: ", data)
                        self.terminal.write(data)
                        self.substate = b'send_backend_fake_HistoryCommand'
                        self.backendChannel.write(self.fakeHistoryCommand)
                    # substate 2, we got the reply for fake history command
                    elif self.substate == b'send_backend_fake_HistoryCommand':
                        print("no output")
                        self.substate = None
                        self.action = None
                else:
                    print("block action, write to attacker: ", data)
                    self.terminal.write(data)

            elif self.action == self.shell.env.ACTION_SUBSTITUTE:
                print("substitute action, substate: ", self.substate)
                _data = data.replace(b'^C', b'')
                # we already sent "\r\n", so remove them
                _data = _data.replace(b'\r\n', b'')
                # replace fake history command
                _data = _data.replace(self.fakeHistoryPattern, b'')
                print("after: ", _data)
                if isprompt:
                    # if we got prompt, it meant we got the reply
                    # two cases to consider
                    # substate 1, we will send the fake history command
                    if self.substate == b'send_backend_empty_buffer':
                        print("substitute action, write to attacker: ", _data)
                        self.writeToAttacker(_data)
                        self.substate = b'send_backend_fake_HistoryCommand'
                        self.backendChannel.write(self.fakeHistoryCommand)
                    # substate 2, we got the reply for fake history command
                    elif self.substate == b'send_backend_fake_HistoryCommand':
                        print("no output")
                        self.substate = None
                        self.action = None
                else:
                    print("substitute action, write to attacker: ", _data)
                    self.writeToAttacker(_data)
            else:
                print("no action, write to attacker: ", data)
                self.writeToAttacker(data)

        # in editor mode, we will not intercept anything
        if self.termstate == b'editor':
            log.msg("state: editor")
            self.terminal.write(data)

        # in interactive mode, we will not intercept anything
        if self.termstate == b'interactive':
            log.msg("state: interactive")
            self.terminal.write(data)

        if self.termstate == b'tab':
            self.terminal.write(data)

        # if self.termstate == b'input':
        #     self.terminal.write(data)

    def writeToAttacker(self, data):
        """
        Write data directly to attacker without processing anything.
        """
        print("writeToAttacker:", data)
        self.terminal.write(data)

    def extWrite(self, data):
        """
        BEGIN SMP:

        This function will be called when extended data is received
        from target machine through a channel. It knows what to do with
        extended data received.
        """

        self.terminal.write(data)

    def getCommandState(self, cmd):
        """
        Get command category.
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

    def getTerminalState(self, state):
        """
        Given the type of commands, we also move the terminal
        state that allows us to know what to do with data received
        from backend.

        This terminal state can be:
        - data: no filter, everything is forwarded to attacker terminal
        - tab: bash completion
        - history: command history
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
    # input_data is static buffer for stdin received from remote client
    input_data = b""
    request = b'exec'
    cmdstackindex = 0
    cmdexecstacks = []
    index = 0

    def __init__(self, avatar, execcmd):
        """
        IMPORTANT
        Before this, execcmd is 'bytes'. Here it converts to 'string' and
        commands work with string rather than bytes.
        """
        try:
            print(execcmd)
            self.execcmd = execcmd.decode("utf8")
        except UnicodeDecodeError:
            log.err(f"Unusual execcmd: {repr(execcmd)}")

        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self):
        log.msg("XXXXXX")
        HoneyPotBaseProtocol.connectionMade(self)
        # self.setTimeout(60)
        # self.cmdstack = [honeypot.HoneyPotShell(self, interactive=False)]
        # TODO: quick and dirty fix to deal with \n separated commands
        # HoneypotShell() needs a rewrite to better work with pending input
        # self.cmdstack[0].lineReceived("; ".join(self.execcmd.split("\n")))

        self.cmdstack = self.execcmd.split("\n")

    def keystrokeReceived(self, keyID, modifier):
        self.input_data += keyID

    def dataReceived(self, data):
        """
        Data received from attacker's terminal when bash is invoked.

        This function is only called when we are in input mode.

        params:
            data: (bytes)
        """
        # print(self.targetPrompt)
        log.msg(f"dataReceived from attacker, data: {data}")
        log.msg(f"dataReceived from attacker, state: {self.termstate}")
        # self.action = self.shell.makeDecision(data)
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

    def cbAnalyseInput(self, data):
        """
        This function is invoked when when bash is executed in the target
        machine. It can be invoked by the backend channel or it can be invoked
        when unknown commands are input.

        1) ssh xxx cd\npwd\nxxx
        """

        data = data.strip(b'\n')
        log.msg(f"data received: {data}")
        if data == b'':
            log.msg("data is empty")
            self.executeNextCommand()
        else:
            hint = data.decode('utf8')
            print(hint)
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
            self.makeDecision(line)
        elif self.stackIsEmpty():
            self.closeChannel()

    def closeChannel(self):
        """
        This function is used to closed the channle that we open to
        execute command in exec mode.
        """
        self.backendChannel.write(b'exit\n')

    def lookahead(self)->str:
        """
        Return the head of the stack if stack is not empty otherwise, return
        an empty string.

        Params
        ------
        Return
        ------
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

        Params:
        ------
            cmd: (str) not used
        Return:
        ------
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
        log.msg("we got a return, thinking...")
        self.action, self.parsedcmd, self.obs = self.shell.makeDecision(line)
        # self.action = self.shell.env.ACTION_SUBSTITUTE
        self.cmdState = self.getCommandState(line)
        log.msg(f"command state: {self.cmdState}, action: {self.action}, obs: {self.obs}")

        if self.action == self.shell.env.ACTION_ALLOW:
            self._execActionAllow(self.parsedcmd, self.obs)
        elif self.action == self.shell.env.ACTION_BLOCK:
            self._execActionBlock(self.parsedcmd, self.obs)
            # self._execActionAllow(line, self.obs)
        elif self.action == self.shell.env.ACTION_SUBSTITUTE:
            self._execActionSubstitute(self.parsedcmd, self.obs)
            # self._execActionAllow(line, self.obs)

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
        if obs == self.shell.env.UNKNOWN_COMMAND_IX:
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

    def __init__(self, avatar):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self):
        # self.displayMOTD()

        HoneyPotBaseProtocol.connectionMade(self)
        recvline.HistoricRecvLine.connectionMade(self)

        # self.cmdstack = [honeypot.HoneyPotShell(self)]

        self.keyHandlers.update(
            {
                b"\x01": self.handle_HOME,  # CTRL-A
                b"\x02": self.handle_LEFT,  # CTRL-B
                b"\x03": self.handle_CTRL_C,  # CTRL-C
                b"\x04": self.handle_CTRL_D,  # CTRL-D
                b"\x05": self.handle_END,  # CTRL-E
                b"\x06": self.handle_RIGHT,  # CTRL-F
                b"\x08": self.handle_BACKSPACE,  # CTRL-H
                b"\x09": self.handle_TAB,
                b"\x0b": self.handle_CTRL_K,  # CTRL-K
                b"\x0c": self.handle_CTRL_L,  # CTRL-L
                b"\x0e": self.handle_DOWN,  # CTRL-N
                b"\x10": self.handle_UP,  # CTRL-P
                b"\x15": self.handle_CTRL_U,  # CTRL-U
                b"\x16": self.handle_CTRL_V,  # CTRL-V
                b"\x1b": self.handle_ESC,  # ESC
            }
        )

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
        self.keyHandlers = None

    def initializeScreen(self):
        """
        Overriding super to prevent terminal.reset()
        """
        # self.setInsertMode()
        pass

    # def setInsertMode(self):
    #     self.mode = "insert"
    #     self.terminal.setModes([insults.modes.IRM])

    def call_command(self, pp, cmd, *args):
        self.pp = pp
        self.setTypeoverMode()
        HoneyPotBaseProtocol.call_command(self, pp, cmd, *args)

    def characterReceived(self, ch, moreCharactersComing):
        """
        Easier way to implement password input?
        """
        print("characterReceived, cmdState:", self.termstate)
        print("received character:", ch)
        if self.mode == "insert":
            self.lineBuffer.insert(self.lineBufferIndex, ch)
            self.lineBufferIndex += 1
        elif self.termstate != b'tab':
            # if we are not in a bash completion mode
            self.lineBuffer[self.lineBufferIndex : self.lineBufferIndex + 1] = [ch]
            self.lineBufferIndex += 1
        print("characterReceived: ", self.lineBuffer)
        # if not self.password_input:
        #     self.terminal.write(ch)
        # self.backendChannel.write(ch)



    def makeDecision(self, line):
        """

        @param line: {str} attacker command line buffer
        """
        print("we got a return, thinking...")
        print("line: ", line)
        self.action, self.parsedcmd, self.obs = self.shell.makeDecision(line)
        self.cmdState = self.getCommandState(line)
        self.termstate = self.getTerminalState(self.cmdState)
        self.action = self.shell.env.ACTION_ALLOW
        log.msg(f"command state: {self.cmdState}")
        log.msg(f"terminal state: {self.termstate}")

        if self.action == self.shell.env.ACTION_ALLOW:
            self._execActionAllow(self.parsedcmd, self.obs)
        elif self.action == self.shell.env.ACTION_BLOCK:
            self._execActionBlock(self.parsedcmd, self.obs)
        elif self.action == self.shell.env.ACTION_SUBSTITUTE:
            self._execActionSubstitute(self.parsedcmd, self.obs)

    def _execActionAllow(self, parsedcmd, obs):
        """Execute action `allow`.

        Whatever it is input by attacker, it is already submitted to the backend.
        So to trigger the execution, we just need to write b'\n' to shell
        channel.
        """

        log.msg("exec action allow")
        self.backendChannel.write(b'\n')

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

        cmd = parsedcmd["cmd"]
        extdata = b'\r\n-bash: ' + bytes(cmd, 'utf8') + b': command not found'
        self.substate = b'send_error_msg'
        self.writeToAttacker(extdata)

        self.substate = b'send_backend_empty_buffer'

        # empty command buffer in the backend
        self.backendChannel.write(b'\x03')

        # use the original command string to fake the history
        cmd = parsedcmd["cmd_str"]
        # prepare fake history command, the first one is to be sent to backend
        # while the second is to used to detect when the backend replies;
        # the only different is that the backend always replies with "\r\n"
        self.fakeHistoryCommand = b'history -s "' + bytes(cmd, 'utf8') + b'"\n'
        self.fakeHistoryPattern = b'history -s "' + bytes(cmd, 'utf8') + b'"\r\n'

    def _execActionSubstitute(self, parsedcmd, obs):
        """
        Execute action `substitute`.

        - Empty command buffer in the shell on the target machine
        - Select a response from a set of pre-defined responses
        - Write a selected response to the attacker
        """
        log.msg("exec action substitute")

        cmd = parsedcmd["cmd"]
        if cmd != '':
            self.writeToAttacker(b'\r\n')
            args = parsedcmd["arg"]
            c = self.commands["nop"](self.terminal, args)
            c.start()

            self.substate = b'send_backend_empty_buffer'
            # empty command buffer in the backend
            self.backendChannel.write(b'\x03')

            # prepare fake history command, the first one is to be sent to backend
            # while the second is to used to detect when the backend replies;
            # the only different is that the backend always replies with "\r\n"
            self.fakeHistoryCommand = b'history -s "' + bytes(cmd, 'utf8') + b'"\n'
            self.fakeHistoryPattern = b'history -s "' + bytes(cmd, 'utf8') + b'"\r\n'

    def dataReceived(self, data):
        """
        Data received from attacker's terminal.
        """

        log.msg(f"dataReceived from attacker, termstate: {self.termstate}")
        log.msg(f"dataReceived from attacker, cmdState: {self.cmdState}")
        print("dataReceived from attacker, data: ", data)
        print("dataReceived self.return_key: ", self.return_key)
        if self.termstate == b'input':
            if self.return_key:
                self.return_key = False
                line = self.attackerInput
                self.attackerInput = None
                print("before makeDecision dataReceived self.return_key: ", self.return_key)
                self.makeDecision(line)
                print("after makeDecision dataReceived self.return_key: ", self.return_key)
            else:
                self.backendChannel.write(data)
        elif self.termstate == b'editor':
            self.backendChannel.write(data)
        elif self.termstate == b'interactive':
            self.backendChannel.write(data)
        else:
            self.backendChannel.write(data)

        # self.backendChannel.write(data)

    def windowChanged(self, windowSize):
        """
        Window change request received from attacker's terminal
        """
        self.backendChannel.windowChanged(windowSize)

    def handle_RETURN(self):
        print("before handle_RETURN self.return_key: ", self.return_key)
        self.return_key = True
        line = b"".join(self.lineBuffer)
        self.lineBuffer = []
        self.lineBufferIndex = 0
        if self.termstate == b'tab':
            self.termstate = b'input'
        print("after handle_RETURN self.return_key: ", self.return_key)
        # self.terminal.nextLine()
        self.lineReceived(line)


        # if len(self.cmdstack) == 1:
        #     if self.lineBuffer:
        #         self.historyLines.append(b"".join(self.lineBuffer))
        #     self.historyPosition = len(self.historyLines)
        # return recvline.RecvLine.handle_RETURN(self)

    def handle_CTRL_C(self):
        if len(self.cmdstack):
            self.cmdstack[-1].handle_CTRL_C()

    def handle_CTRL_D(self):
        if len(self.cmdstack):
            self.cmdstack[-1].handle_CTRL_D()

    def handle_TAB(self):
        print("TAB")
        if self.termstate == b'input':
            self.termstate = b'tab'
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

    # def keystrokeReceived(self, keyID, modifier):
    #     self.backendChannel.write(keyID)

    # def dataReceived(self, data):
    #     self.backendChannel.write(data)

class HoneyPotInteractiveTelnetProtocol(HoneyPotInteractiveProtocol):
    """
    Specialized HoneyPotInteractiveProtocol that provides Telnet specific
    overrides.
    """

    def __init__(self, avatar):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotInteractiveProtocol.__init__(self, avatar)

    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need to override how we grab
        the proper transport to access underlying Telnet information.
        """
        return self.terminal.transport.session.transport
