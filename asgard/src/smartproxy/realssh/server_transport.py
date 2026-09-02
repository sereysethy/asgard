# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
The lowest level SSH protocol. This handles the key negotiation, the
encryption and the compression. The transport layer is described in
RFC 4253.
"""

from __future__ import annotations

import re
import struct
import time
import uuid
import zlib
from hashlib import md5
from typing import Any

from twisted.internet import reactor, defer
from twisted.conch.ssh import transport
from twisted.conch.ssh.common import getNS
from twisted.protocols.policies import TimeoutMixin
from twisted.python import log, randbytes

from cowrie.core.config import CowrieConfig

from smartproxy.realssh import factoryv2 as clientfactory
from container_pool.container import DockerExistingContainer

class HoneyPotSSHTransport(transport.SSHServerTransport, TimeoutMixin):
    """
    SSH client transport to handle the connection to the target system.

    This class was originally taken from the Cowrie's project.
    It was modified to prepare the user account on the target system
    before the actual SSH connection takes place to the target system.

    The instance of this class is created when the user is connected
    to the proxy. It prepares a connection to the target system, and
    coordinate the communicaiton between them.

    It also closes the connection to the target system if the timeout
    for both `authenticaiton_timeout` or `interactive_timeout` expires.

    Attributes:
        startTime: records the starting duration.
        buf: buffer to store sent/received packages.
        transportId: a unique id attributed to this transport
        auth_timeout: an authentication timeout. If it is not set, it
            defaults to 120 seconds.
        interactive_timeout: an interactive timeout. If it is not set,
            it defaults to 300 seconds.
    """
    startTime: float = 0.0
    gotVersion: bool = False
    buf: bytes
    transportId: str
    ipv4rex = re.compile(r"^::ffff:(\d+\.\d+\.\d+\.\d+)$")
    auth_timeout: int = CowrieConfig.getint(
        "honeypot", "authentication_timeout", fallback=120
    )
    interactive_timeout: int = CowrieConfig.getint(
        "honeypot", "interactive_timeout", fallback=300
    )
    ourVersionString: bytes  # set by factory
    transport: Any
    outgoingCompression: Any
    _blockedByKeyExchange: Any

    def __init__(self) -> None:
        # SMP
        self.backendConnected: bool = False
        self.frontendAuthenticated: bool = False
        self.delayedPackets: list = []
        self.closed: bool = False
        self.requestSession: bool = False
        self.requestExec: bool = False
        self.requestEOF: bool = False

    def __repr__(self) -> str:
        """
        Return a pretty representation of this object.

        Returns:
            Pretty representation of this object as a string
        """
        return f"Cowrie SSH Transport to {self.transport.getPeer().host}"

    def connectionMade(self) -> None:
        """
        Called when the connection is made from the other side.
        We send our version, but wait with sending KEXINIT
        """
        self.buf = b""

        self.transportId = uuid.uuid4().hex[:12]
        src_ip: str = self.transport.getPeer().host

        ipv4_search = self.ipv4rex.search(src_ip)
        if ipv4_search is not None:
            src_ip = ipv4_search.group(1)

        log.msg(
            eventid="cowrie.session.connect",
            format="New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(session)s]",
            src_ip=src_ip,
            src_port=self.transport.getPeer().port,
            dst_ip=self.transport.getHost().host,
            dst_port=self.transport.getHost().port,
            session=self.transportId,
            sessionno=f"S{self.transport.sessionno}",
            protocol="ssh",
        )

        self.transport.write(self.ourVersionString + b"\r\n")
        self.currentEncryptions = transport.SSHCiphers(
            b"none", b"none", b"none", b"none"
        )
        self.currentEncryptions.setKeys(b"", b"", b"", b"", b"", b"")

        self.startTime: float = time.time()
        self.setTimeout(self.auth_timeout)

    def sendKexInit(self) -> None:
        """
        Don't send key exchange prematurely
        """
        if not self.gotVersion:
            return
        transport.SSHServerTransport.sendKexInit(self)

    def _unsupportedVersionReceived(self, remoteVersion: bytes) -> None:
        """
        Change message to be like OpenSSH
        """
        self.transport.write(b"Protocol major versions differ.\n")
        self.transport.loseConnection()

    def dataReceived(self, data: bytes) -> None:
        """
        First, check for the version string (`SSH-2.0-*`). After that has been
        received, this method adds data to the buffer, and pulls out any
        packets.
        """
        self.buf = self.buf + data
        if not self.gotVersion:
            if b"\n" not in self.buf:
                return
            self.otherVersionString: bytes = self.buf.split(b"\n")[0].strip()
            log.msg(
                eventid="cowrie.client.version",
                version=self.otherVersionString.decode(
                    "utf-8", errors="backslashreplace"
                ),
                format="Remote SSH version: %(version)s",
            )
            m = re.match(rb"SSH-(\d+\.\d+)-(.*)", self.otherVersionString)
            if m is None:
                log.msg(
                    f"Bad protocol version identification: {self.otherVersionString!r}"
                )
                # OpenSSH sending the same message
                self.transport.write(b"Invalid SSH identification string.\n")
                self.transport.loseConnection()
                return
            self.gotVersion = True
            remote_version = m.group(1)
            if remote_version not in self.supportedVersions:
                self._unsupportedVersionReceived(self.otherVersionString)
                return
            i = self.buf.index(b"\n")
            self.buf = self.buf[i + 1 :]
            self.sendKexInit()
        packet = self.getPacket()
        while packet:
            messageNum = ord(packet[0:1])
            self.dispatchMessage(messageNum, packet[1:])
            packet = self.getPacket()

    def dispatchMessage(self, messageNum, payload):
        # overriden dispatchMessage sets services, we do that here too then
        # we're particularly interested in userauth, since Twisted does most of that for us
        if messageNum == 5:
            self.ssh_SERVICE_REQUEST(payload)
        elif 50 <= messageNum <= 79:  # userauth numbers
            self.frontendAuthenticated = False
            transport.SSHServerTransport.dispatchMessage(
                self, messageNum, payload
            )  # let userauth deal with it

        # # TODO delay userauth until backend is connected?
        # elif messageNum == 98 and not self.request_session:
        #     # request channel open
        #     self.packet_buffer(messageNum, payload)

        elif transport.SSHServerTransport.isEncrypted(self, "both"):
            self.packet_buffer(messageNum, payload)
        else:
            transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)

    def sendPacket(self, messageType: int, payload: bytes) -> None:
        """
        Override because OpenSSH pads with 0 on KEXINIT
        """
        if self._keyExchangeState != self._KEY_EXCHANGE_NONE:
            if not self._allowedKeyExchangeMessageType(messageType):
                self._blockedByKeyExchange.append((messageType, payload))
                return

        payload = bytes((messageType,)) + payload
        if self.outgoingCompression:
            payload = self.outgoingCompression.compress(
                payload
            ) + self.outgoingCompression.flush(2)
        bs = self.currentEncryptions.encBlockSize
        # 4 for the packet length and 1 for the padding length
        totalSize = 5 + len(payload)
        lenPad = bs - (totalSize % bs)
        if lenPad < 4:
            lenPad = lenPad + bs
        padding: bytes
        if messageType == transport.MSG_KEXINIT:
            padding = b"\0" * lenPad
        else:
            padding = randbytes.secureRandom(lenPad)

        packet = struct.pack(b"!LB", totalSize + lenPad - 4, lenPad) + payload + padding
        encPacket = self.currentEncryptions.encrypt(
            packet
        ) + self.currentEncryptions.makeMAC(self.outgoingPacketSequence, packet)
        self.transport.write(encPacket)
        self.outgoingPacketSequence += 1

    def ssh_KEXINIT(self, packet: bytes) -> Any:
        k = getNS(packet[16:], 10)
        strings, _ = k[:-1], k[-1]
        (kexAlgs, keyAlgs, encCS, _, macCS, _, compCS, _, langCS, _) = (
            s.split(b",") for s in strings
        )

        # hassh SSH client fingerprint
        # https://github.com/salesforce/hassh
        ckexAlgs = ",".join([alg.decode("utf-8") for alg in kexAlgs])
        cencCS = ",".join([alg.decode("utf-8") for alg in encCS])
        cmacCS = ",".join([alg.decode("utf-8") for alg in macCS])
        ccompCS = ",".join([alg.decode("utf-8") for alg in compCS])
        hasshAlgorithms = f"{ckexAlgs};{cencCS};{cmacCS};{ccompCS}"
        hassh = md5(hasshAlgorithms.encode("utf-8")).hexdigest()

        log.msg(
            eventid="cowrie.client.kex",
            format="SSH client hassh fingerprint: %(hassh)s",
            hassh=hassh,
            hasshAlgorithms=hasshAlgorithms,
            kexAlgs=kexAlgs,
            keyAlgs=keyAlgs,
            encCS=encCS,
            macCS=macCS,
            compCS=compCS,
            langCS=langCS,
        )

        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def timeoutConnection(self) -> None:
        """
        Make sure all sessions time out eventually.
        Timeout is reset when authentication succeeds.
        """
        log.msg("Timeout reached in HoneyPotSSHTransport")
        self.transport.loseConnection()

    def setService(self, service):
        """
        Remove login grace timeout, set zlib compression after auth
        """

        if service.name == b"ssh-connection":
            # Reset timeout. Not everyone opens shell so need timeout at transport level
            self.setTimeout(self.interactive_timeout)
            if self.outgoingCompressionType == b"zlib@openssh.com":
                self.outgoingCompression = zlib.compressobj(6)
            if self.incomingCompressionType == b"zlib@openssh.com":
                self.incomingCompression = zlib.decompressobj()

            self.pendingService = service
            # make a connection to backend by creating a new ssh client
            self.connectToBackend()
        else:
            transport.SSHServerTransport.setService(self, service)

    def connectionLost(self, reason):
        """
        This seems to be the only reliable place of catching lost connection
        """
        self.setTimeout(None)
        transport.SSHServerTransport.connectionLost(self, reason)
        self.transport.connectionLost(reason)
        self.closed = True

        if hasattr(self.transport, "backendTransport") and \
            not self.transport.backendTransport.closed:
            self.transport.backendTransport.loseConnection()
            self.transport.backendTransport = None
            self.transport.backendConn = None

        self.transport = None
        duration = time.time() - self.startTime
        log.msg(
            eventid="cowrie.session.closed",
            format="Connection lost after %(duration)d seconds",
            duration=duration,
        )

        #SMP: call save RL model after each lost connection.
        self.factory.saveModel()
        self.factory.loseConnection()
        self.factory = None

    def sendDisconnect(self, reason, desc):
        """
        http://kbyte.snowpenguin.org/portal/2013/04/30/kippo-protocol-mismatch-workaround/
        Workaround for the "bad packet length" error message.

        Args:
            reason (int): the reason for the disconnect.  Should be one of the
                `DISCONNECT_*` values.
            desc (str): a description of the reason for the disconnection.
        """
        if b"bad packet length" not in desc:
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            # this message is used to detect Cowrie behaviour
            # self.transport.write(b"Packet corrupt\n")
            log.msg(
                f"[SERVER] - Disconnecting with error, code {reason} reason: {desc}"
            )
            self.transport.loseConnection()

    def receiveError(self, reasonCode, description):
        """
        Called when we receive a disconnect error message from the other side.

        Args:
            reasonCode (int): the reason for the disconnect, one of the
                `DISCONNECT_` values.
            description (str): a human-readable description of the
                disconnection.
        """
        log.msg(f"Got remote error, code {reasonCode} reason: {description}")

    def packet_buffer(self, messageNum: int, payload: bytes) -> None:
        """
        We have to wait until we have a connection to the backend is ready.
        Meanwhile, we hold packets from client to server in here.
        """
        if not self.backendConnected:
            # wait till backend connects to send packets to them
            log.msg("Connection to backend not ready, buffering packet from frontend")
            self.delayedPackets.append([messageNum, payload])
        else:
            if messageNum == 98 and not self.requestSession:
                self.delayedPackets.append([messageNum, payload])
            elif len(self.delayedPackets) > 0:
                self.delayedPackets.append([messageNum, payload])
            else:
                transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)

    def connectToBackend(self):
        """
        It establishes the connection to the target system by using an SSH client.

        The SSH client is created using the SSH factory 
        :class:`smartproxy.realssh.factoryv2.SSHClientFactory`.
        First, it creates a user on the target system, if it does not exist.
        In the case where the user already exists, it modifies its password to match
        that of the new password for that account.
        The creation and the modification of the user account is made
        via Docker command `exec`, see more detail in :class:`container_pool.container.DockerExistingContainer`.

        Once the account is successfully created, it calls the SSH factory
        to create an SSH client and user the provided username and password
        to connect to the target system.
        """
        userinfo = {
            "username": self.transport.username,
            "password": self.transport.password
        }

        containerName = CowrieConfig.get("docker", "container_name")
        # use an existing container which is already started
        #TODO: this name of class is not correct.
        container = DockerExistingContainer()
        if container.connect(containerName):
            accountCreationIsDone, uid, gid = container.createUser(userinfo["username"], userinfo["password"])

            if accountCreationIsDone:
                userinfo["uid"] = uid
                userinfo["gid"] = gid
                self.transport.userinfo = userinfo
                server = CowrieConfig.get('proxy', 'backend_ssh_host')
                port = CowrieConfig.getint('proxy', 'backend_ssh_port')

                self.d = defer.Deferred()
                self.d.addCallback(self._cbTargetMachineReady)
                self.d.addErrback(self._ebTargetMachineFailed)

                sshClientfactory = clientfactory.SSHClientFactory(userinfo["username"], userinfo["password"], self)
                reactor.connectTCP(server, port, sshClientfactory)
            else:
                self.transport.loseConnection()
        else:
            self.transport.loseConnection()

    def _cbTargetMachineReady(self, backendConn):
        """
        Call when the connection to backend is ready. Now we can continue to
        request the service.

        Args:
            backendConn: it is the connection to backend, after ssh client is created
        """

        log.msg("Backend connection is ready, start service connection")
        self.transport.backendTransport = backendConn.transport
        self.transport.backendConn = backendConn
        self.backendConnected = True

        # set the pending service, it is a "connection" service
        transport.SSHServerTransport.setService(self, self.pendingService)
        self.pendingService = None

        # dispatch all delayed packets
        for packet in self.delayedPackets:
            transport.SSHServerTransport.dispatchMessage(self, packet[0], packet[1])
        self.delayedPackets = []

    def _ebTargetMachineFailed(self, error):
        """
        Call when the connection to the target marchine fails.
        
        Args:
            error: contains description of the error
        """
        if self.transport:
            self.transport.loseConnection()

    def resumeRequestSession(self):
        """
        Resume channel request session messageNum: 98

        SSH_MSG_CHANNEL_REQUEST: 98
        """
        # dispatch all delayed packets
        self.requestSession = True
        for packet in self.delayedPackets:
            # if packet[0] == 90:
                # open a session too
            transport.SSHServerTransport.dispatchMessage(self, packet[0], packet[1])
        self.delayedPackets = []

    def ssh_DISCONNECT(self, packet):
        """
        Called when we receive a MSG_DISCONNECT message.  Payload::
            long code
            string description

        This means that the other side has disconnected.  Pass the message up
        and disconnect ourselves.

        Args:
            packet (bytes): packet: The message data.
        """
        reasonCode = struct.unpack(">L", packet[:4])[0]
        description, foo = getNS(packet[4:])
        self.receiveError(reasonCode, description)
        # override, check the transport to prevent crash when backend called
        # to disconnect, it happens when resumeRequestSession is called
        if self.transport:
            self.transport.loseConnection()
