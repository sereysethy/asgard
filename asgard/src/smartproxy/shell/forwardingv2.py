# Copyright (c) 2009-2014 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
This module contains code for handling SSH direct-tcpip connection requests
"""

from __future__ import annotations
from twisted.conch.ssh import forwarding
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.ssh import forwarding as cowriefowarding

from smartproxy.realssh.forwardingv2 import SSHConnectForwardingChannel, SSHListenClientForwardingChannel

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
        # get the connection to the backend
        backendConn = avatar.conn.transport.transport.backendConn

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
        
        return attackerChannel

    return cowriefowarding.FakeForwardingChannel(
        remoteHP, remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket
    )