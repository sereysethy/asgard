"""
Smart Proxy
-----------

We use this classes to create a channel to send back to the attacker and
also create another channel to the backend. Where there is data coming from each
side, we forward it back and forward.

If one channel got eof from the remote, it will notify the other accordingly. So
that every channels are closed properly.
"""

from twisted.conch.ssh import channel
from smartproxy import log

class SSHListenClientForwardingChannel(channel.SSHChannel):
    """
    Channel used to handle data received from backend.
    Data will be sent back to the attackers.

    It acts as a client to the backend server.
    """

    name = b"direct-tcpip"

    def __init__(self,
        remoteWindow=0,
        remoteMaxPacket=0,
        conn=None,
        data=None,
        remoteHP=None):
        super().__init__(
            remoteWindow=remoteWindow,
            remoteMaxPacket=remoteMaxPacket,
            conn=conn
            )
        self.hostport = remoteHP
        self.ready = 0
        self.clientBuf = b''
        self.alreadyClosed = 0
        self.data = b''

    def channelOpen(self, specificData):
        log.info("backend connecting to {host}:{port}", host=self.hostport[0], port=self.hostport[1])
        log.info("backend opened forwarding channel {id}", id=self.id)
        self.ready = 1
        if len(self.clientBuf) > 0:
            self.write(self.clientBuf)
            self.clientBuf = b''
        self.client.write(specificData)

    def openFailed(self, reason):
        """
        called when the channel failed to open. This channel is not yet
        registered in the connection.
        """
        log.error("backend failed to connect to {host}:{port}", host=self.hostport[0], port=self.hostport[1])
        self.loseConnectionWhenOpenFailed()

    def setClient(self, client):
        """
        Set the attacker channel, to receive data from backend.
        """
        self.client = client

    def dataReceived(self, data):
        """
        Data received from backend, if client is set, we will write to
        the attacker channel.
        """
        if self.client:
            self.client.write(data)
        else:
            self.data += data

        # reset timeout the protocol that control this connection to backend
        if hasattr(self.conn, "tcpPortFowardingProtocol"):
            self.conn.tcpPortFowardingProtocol.resetTimeout()

    def write(self, data):
        if not self.ready:
            self.clientBuf += data
        else:
            if self.clientBuf:
                super().write(self.clientBuf)
                self.clientBuf = b''
            else:
                super().write(data)

    def eofReceived(self):
        if hasattr(self, 'client') and not self.client.alreadyClosed:
            self.client.loseConnection()
        self.loseConnection()

    def loseConnectionWhenOpenFailed(self):
        """
        Same like loseConnection but the channel is not yet registered, so
        we will proceed to close the connection without deregister the channel.
        """
        self.alreadyClosed = 1

        # notify the client (attacker) to lose its connection, if there
        # is a reason to close, set it.
        if hasattr(self, "client") and not self.client.alreadyClosed:
            self.client.loseConnection()
            del self.client

        self.closed()

    def loseConnection(self):
        """
        Close the channel if there is no buferred data.  Otherwise, note the
        request and return.
        """

        self.alreadyClosed = 1

        # notify the client (attacker) to lose its connection, if there
        # is a reason to close, set it.
        if hasattr(self, "client") and not self.client.alreadyClosed:
            self.client.loseConnection()
            del self.client

        self.conn.sendClose(self)

    def closed(self):
        log.info("backend closed remote forwarding channel {id}", id=self.id)
        # self.conn.transport.loseConnection()
        # if hasattr(self, "client") and not self.client.alreadyClosed:
        #     self.client.loseConnection()
        #     del self.client

class SSHConnectForwardingChannel(channel.SSHChannel):
    """
    Channel used for receiving data from the attacker.
    It handles server side of the proxy.

    All data received will be written to the client which is an open channel to
    to the backend system.
    """
    def __init__(self, remoteWindow=0, remoteMaxPacket=0, data=None, remoteHP=None):
        super().__init__(
            remoteWindow=remoteWindow,
            remoteMaxPacket=remoteMaxPacket,
            data=data
            )
        self.hostport = remoteHP
        self.clientBuf = b''
        self.ready = 0
        self.alreadyClosed = 0
        self.data = b''

    def channelOpen(self, specificData):
        """
        See: L{channel.SSHChannel}
        """
        log.info("connecting from {host}:{port}", host=self.hostport[0], port=self.hostport[1])
        self.ready = 1

    def openFailed(self, reason):
        """
        @override
        It is called by the remote client, when the real ssh server cannot
        open a channel to the romote server.
        """
        log.error(
            "failed to connect from {host}:{port}: {reason}",
            host=self.hostport[0],
            port=self.hostport[1],
            reason=reason,
        )
        # if hasattr(self, "reason"):
        #     reason, desc = self.reason.data, self.reason.value
        #     self.conn.transport.sendDisconnect(reason, desc)
        # reason, desc = reason.data, reason.value
        # self.conn.transport.write(b'Connection reset by peer')
        # self.conn.transport.sendDisconnect(reason, desc)

        # we cannot delete this channel from the connection, because it is not
        # registered yet, so will just close the connection entirely.

    def setClient(self, client):
        """
        Called when the connection was established to the forwarding
        destination.

        @param client: Client protocol connected to the forwarding destination.
        @type  client: L{protocol.Protocol}
        """
        self.client = client

    def eofReceived(self):
        if hasattr(self, 'client') and not self.client.alreadyClosed:
            self.client.loseConnection()
        self.loseConnection()

    def dataReceived(self, data):
        """
        See: L{channel.SSHChannel}
        """
        log.info(
            eventid="cowrie.direct-tcpip.data",
            format="forwarded direct-tcp forward request {id} to {dst_ip}:{dst_port} with data {data}",
            dst_ip=self.hostport[0],
            dst_port=self.hostport[1],
            data=repr(data),
            id=self.id,
        )
        if hasattr(self, 'client'):
            self.client.write(data)
        else:
            self.data += data

    def start(self):
        """
        Write buffering data that was sent from the attacker to the backend,
        it was buffered because the backend channel was not yet ready.
        """
        if self.data:
            self.client.write(self.data)
            self.data = b''

    def write(self, data):
        if not self.ready:
            self.clientBuf += data
        else:
            if self.clientBuf:
                super().write(self.clientBuf)
                self.clientBuf = b''
            else:
                super().write(data)

    def loseConnection(self):
        """
        Close the channel if there is no buferred data.  Otherwise, note the
        request and return.
        """
        self.alreadyClosed = 1
        if hasattr(self, "client") and not self.client.alreadyClosed:
            self.client.loseConnection()
            del self.client

        # delete this channel from the connection and close this channel
        # check the conch.ssh.connection, it will call closed()
        self.conn.sendClose(self)

    def closed(self):
        """
        See: L{channel.SSHChannel}
        """
        log.info("closed local forwarding channel {id}", id=self.id)
        # self.conn.transport.loseConnection()
        # if hasattr(self, "client") and not self.client.alreadyClosed:
        #     self.client.loseConnection()
        #     del self.client
