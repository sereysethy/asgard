# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import time
import shlex
from zope.interface import implementer

from twisted.conch.interfaces import ISession
from twisted.conch.ssh import session
from twisted.python import log

from smartproxy.realssh.insults import insults
from smartproxy.shell import protocolv3 as protocol
from smartproxy.shell.scp import HoneyPotScpProtocol

@implementer(ISession)
class SSHSessionForCowrieUser:
    def __init__(self, avatar, reactor=None):
        """
        Construct an C{SSHSessionForCowrieUser}.

        @param avatar: The L{CowrieUser} for whom this is an SSH session.
        @param reactor: An L{IReactorProcess} used to handle shell and exec
            requests. Uses the default reactor if None.
        """
        self.protocol = None
        self.avatar = avatar
        self.server = avatar.server
        self.uid = avatar.uid
        self.gid = avatar.gid
        self.username = avatar.username
        self.environ = {
            "LOGNAME": self.username,
            "SHELL": "/bin/bash",
            "USER": self.username,
            "HOME": self.avatar.home,
            "TMOUT": "1800",
            "UID": str(self.uid),
        }
        if self.uid == 0:
            self.environ[
                "PATH"
            ] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        else:
            self.environ[
                "PATH"
            ] = "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"

        self.server.initFileSystem(self.avatar.home)

        if self.avatar.temporary:
            self.server.fs.mkdir(self.avatar.home, self.uid, self.gid, 4096, 755)

        """
        BEGIN SMP: attach terminal to session
        """
        self.channel  = None
        self.request  = None
        self.cmd      = None
        self.terminal = None    # terminal name from client
        self.attrs    = None
        self.sessionId = avatar.conn.transport.transport.sessionno
        self.sessionno = "S{}".format(avatar.conn.transport.transport.sessionno)
        self.transportId = avatar.conn.transport.transportId
        self.reqEnv = []

        # this will hold info related to remote client: remoteWindow and remoteMaxPacket
        # set in the Session in the avatar.
        self.remote = avatar.remote
        """
        END SMP
        """

    def openShell(self, processprotocol):
        if self.terminal:
            self.protocol = insults.LoggingServerProtocol(
                protocol.HoneyPotInteractiveProtocol, self
            )
        else:
            self.protocol = insults.LoggingServerProtocol(
                protocol.HoneyPotShellProtocol, self
            )
        self.protocol.makeConnection(processprotocol)
        processprotocol.makeConnection(session.wrapProtocol(self.protocol))

    def getPty(self, terminal, windowSize, attrs):
        self.environ["TERM"] = terminal.decode("utf-8")
        log.msg(
            eventid="cowrie.client.size",
            width=windowSize[1],
            height=windowSize[0],
            format="Terminal Size: %(width)s %(height)s",
        )
        self.windowSize = windowSize
        self.terminal = terminal
        self.attrs = attrs
        return None

    def execCommand(self, processprotocol, cmd):
        # SMP: scp is executed differently with the other commands
        tokens = shlex.split(cmd.decode('utf-8'))
        if tokens[0] == 'scp':
            log.msg("opening a shell session to backend for scp")
            self.dest = tokens[len(tokens) - 1]
            self.protocol = insults.LoggingServerProtocol(
                HoneyPotScpProtocol, self, cmd)
        else:
            log.msg("opening a shell session to backend for exec")
            self.protocol = insults.LoggingServerProtocol(
            protocol.HoneyPotExecProtocol, self, cmd
        )

        self.protocol.makeConnection(processprotocol)
        processprotocol.makeConnection(session.wrapProtocol(self.protocol))

    def closed(self):
        """
        this is reliably called on both logout and disconnect
        we notify the protocol here we lost the connection
        """
        if self.protocol and self.protocol.terminalProtocol:
            # self.protocol.connectionLost("disconnected")
            # self.protocol = None
            self.protocol.terminalProtocol.closed()

    def eofReceived(self):
        if self.protocol:
            self.protocol.eofReceived()

    def windowChanged(self, windowSize):
        (height, width, xpixel, ypixel) = windowSize
        log.msg(eventid='cowrie.session.windowChanged', width=width, height=height, xpixel=xpixel, ypixel=ypixel)
        self.windowSize = windowSize

        """
        BEGIN SMP

        Notify SSH backend channel when window changed.
        """
        if self.protocol:
            self.protocol.windowChanged(windowSize)
        """
        END SMP
        """
