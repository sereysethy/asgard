# Copyright (c) 2009-2014 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
This module contains code for handling SSH direct-tcpip connection requests
"""

from __future__ import annotations
from twisted.conch.ssh import forwarding
from twisted.internet import defer, protocol, reactor
from twisted.python import log
from cowrie.core.config import CowrieConfig
from twisted.protocols.policies import TimeoutMixin

#BEGIN SMP
from smartproxy.realssh.forwarding import SSHConnectForwardingChannel, SSHListenClientForwardingChannel
from cowrie.ssh import forwarding as cowriefowarding
from smartproxy.realssh import factory as clientfactory
from container_pool.container import DockerExistingContainer
#END SMP

class TCPPortFowardingProtocol(protocol.Protocol, TimeoutMixin):
    tcp_forward_timeout: int = CowrieConfig.getint(
        "honeypot", "tcp_forward_timeout", fallback=10
    )
    def __init__(self, remoteWindow, remoteMaxPacket, data, avatar, attackerChannel):
        self.data = data
        self.remoteWindow = remoteWindow
        self.remoteMaxPacket = remoteMaxPacket
        self.remoteHP, self.origHP = forwarding.unpackOpen_direct_tcpip(self.data)
        self.user = avatar
        self.request = b'direct-tcpip'
        self.username = self.user.username
        self.attackerChannel = attackerChannel
        super().__init__()

    def connectionMade(self):
        pt = self.transport
        self.transportId = pt.transportId
        self.password = pt.transport.password.decode("utf8")
        containerName = CowrieConfig.get("docker", "container_name")
        container = DockerExistingContainer()
        container.connect(containerName)
        accountCreationIsDone = container.createUser(bytes(self.username, "utf8"), bytes(self.password, "utf8"))

        if accountCreationIsDone:
            username = self.username
            password = self.password
            server = CowrieConfig.get('proxy', 'backend_ssh_host')
            port = CowrieConfig.getint('proxy', 'backend_ssh_port')
            self.d = defer.Deferred()
            self.d.addCallback(self._cbTargetMachineReady)
            self.d.addErrback(self._ebTargetMachineFailed)

            sshClientfactory = clientfactory.SSHClientFactory(username, password, self)
            reactor.connectTCP(server, port, sshClientfactory)
        else:
            pt.transport.loseConnection()

    def connectionLost(self, reason)->None:
        """
        Called when the connection is shut down. It will be called from
        the cowrie/ssh/transport when a connection is lost.

        Clear any circular references here, and any external references
        to this Protocol.  The connection has been closed.
        """
        self.directTCPbackendTransport.loseConnection()
        self.transport = None
        self.directTCPbackendTransport = None

    def timeoutConnection(self):
        if hasattr(self, "transport") and self.transport:
            self.transport.loseConnection()
        if hasattr(self, "directTCPbackendTransport") and self.directTCPbackendTransport:
            self.directTCPbackendTransport.loseConnection()

    def _cbTargetMachineReady(self, conn):
        """
        callback when the connection to backend is ready. conn is the connection
        to the backend, it is used to open channel for doing port forwarding.

        Params
        ------
            conn: connection to backend.

        Returns
        -------
            None
        """

        # set the backend connection for later use
        self.transport.directTCPBackendConn = conn
        # this protocol
        self.transport.directTCPbackendProtocol = self
        # this is the reference to the transport to the backend
        self.directTCPbackendTransport = conn.transport

        # create a backend channel to real ssh server
        backendChannel = SSHListenClientForwardingChannel(self.remoteWindow, self.remoteMaxPacket, conn, self.data, self.remoteHP)
        backendChannel.setClient(self.attackerChannel)
        conn.openChannel(backendChannel, self.data)

        # save this protocol to connection, it is used to reset the timeout
        conn.tcpPortFowardingProtocol = self

        self.attackerChannel.setClient(backendChannel)
        # writing pending data from attacker to backend, it contains the query
        self.attackerChannel.start()
        self.setTimeout(self.tcp_forward_timeout)

    def _ebTargetMachineFailed(self, error):
        self.transport.loseConnection()

def cowrieOpenConnectForwardingClient(remoteWindow, remoteMaxPacket, data, avatar):
    """
    @override

    We override the function from Cowrie, that will create two channels, one
    from attacker to SSH server and another one to the backend ssh server.
    The two are linked together, so that all the tcp requests are forwarded
    to the backend, and from backend to the attacker.

    If the forward_redirect is not enabled, we return the fake forward as
    implemented by Cowrie, in other words, the request will be logged and the
    connection will be closed.
    """
    remoteHP, origHP = forwarding.unpackOpen_direct_tcpip(data)

    log.msg(
        eventid="cowrie.direct-tcpip.request",
        format="direct-tcp connection request to %(dst_ip)s:%(dst_port)s from %(src_ip)s:%(src_port)s",
        dst_ip=remoteHP[0],
        dst_port=remoteHP[1],
        src_ip=origHP[0],
        src_port=origHP[1],
    )

    redirectEnabled: bool = CowrieConfig.getboolean(
        "ssh", "forward_redirect", fallback=False
    )
    if redirectEnabled:
        # get the connection to the backend, if the user already has a backend
        # connection.
        if hasattr(avatar.conn.transport, 'directTCPBackendConn'):
            backendConn = avatar.conn.transport.directTCPBackendConn

            # create a channel to request remote port forwarding
            backendChannel = SSHListenClientForwardingChannel(
                data=data,
                remoteWindow=remoteWindow,
                remoteMaxPacket=remoteMaxPacket,
                remoteHP=remoteHP,
                conn=backendConn)
            # open the channel to the backend
            backendConn.openChannel(backendChannel, data)

            # create a channel to the attacker that requested local port forwarding
            attackerChannel = SSHConnectForwardingChannel(
                remoteWindow=remoteWindow,
                remoteMaxPacket=remoteMaxPacket,
                remoteHP=remoteHP)
            attackerChannel.ready = 1
            attackerChannel.setClient(backendChannel)
            backendChannel.setClient(attackerChannel)
        else:
            # create a channel to the attacker that requested local port forwarding
            attackerChannel = SSHConnectForwardingChannel(
                remoteWindow=remoteWindow,
                remoteMaxPacket=remoteMaxPacket,
                remoteHP=remoteHP)
            pt = TCPPortFowardingProtocol(remoteWindow, remoteMaxPacket, data, avatar, attackerChannel)
            pt.makeConnection(avatar.conn.transport)

        return attackerChannel

    return cowriefowarding.FakeForwardingChannel(
        remoteHP, remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket
    )