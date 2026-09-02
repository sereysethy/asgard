import os
import os.path
import struct
import shlex
import hashlib

from twisted.conch.ssh import channel, session, common
from twisted.conch.endpoints import _CommandChannel

from twisted.python import log
from twisted.internet import error
from cowrie.core.config import CowrieConfig

from pprint import pprint


class CommandChannel(_CommandChannel):
    def extReceived(self, dataType, data):
        """
        When the command's extended data (usually standard error) arrives,
        deliver it to the protocol instance.

        @type dataType: L{int}
        @type data:     L{str}
        """
        self._protocol.extReceived(dataType, data)

class SimpleChannel(channel.SSHChannel):
    name = 'session'
    def __init__(self, shell, cmd, execcmd, delayedCall, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.shell = shell
        self.execcmd = execcmd
        self.cmd = cmd
        self.delayedCall = delayedCall

    def channelOpen(self, data):
        """
        by this time id is set, id represents the channel number in the same
        connection, thinking of using id to track the execution of a program
        that is still running so that we can kill it later
        """
        self._log.info(f'execute command: ', self.execcmd)
        self.conn.sendRequest(self, 'exec', common.NS(self.execcmd),
                                  wantReply=False)

    def openFailed(self, reason):
        """
        Called when the open failed for some reason.
        reason.desc is a string descrption, reason.code the SSH error code.

        @type reason: L{error.ConchError}
        """
        log.msg('other side refused open\nreason: %s'% reason)
        self.shell.sessionEnd()

    def dataReceived(self, data):
        self.shell.execDataReceived(data)

    def extReceived(self, dataType, data):
        self.shell.extDataReceived(dataType, data)

    def request_exit_signal(self, data):
        log.msg("got request exit-signal")
        return 1

    def request_exit_status(self, data):
        log.msg("got request exit-status")
        status = struct.unpack('>L', data)[0]
        return 1

    def closed(self):
        """channel is closed but a delayed call is sceduled, cancel it first if
        it is still active and call next command input".
        """
        log.msg("got closed")
        try:
            # check if delayedCall is still active
            if self.delayedCall.active():
                self.delayedCall.cancel()
                # call next command input
                self.shell.next(self.cmd)
        except error.AlreadyCalled as alreadyCalled:
            # in case that we try to cancel it, and it was already called
            # log it, and remove it from channels list but we will not call next
            # because if it was called, then the other execution thread will
            # call next()
            log.msg(str(alreadyCalled))
        except Exception as e:
            log.msg(e)


class PSChannel(channel.SSHChannel):
    name = 'session'
    def __init__(self, shell, execcmd, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.shell = shell
        self.execcmd = execcmd
        self.data = b''
        self.extData = b''
        # self.id is set later by the connection when the channel is openned

    def channelOpen(self, data):
        log.msg('execute command: ', self.execcmd)
        self.conn.sendRequest(self, 'exec', common.NS(self.execcmd),
                                  wantReply=False)

    def dataReceived(self, data):
        channel.SSHChannel.dataReceived(self, data)
        self.data += data

    def extReceived(self, dataType, data):
        channel.SSHChannel.extReceived(self, dataType, data)
        self.extData += data

    def request_exit_signal(self, data):
        log.msg("got request exit-signal")
        return 1

    def request_exit_status(self, data):
        log.msg("got request exit-status")
        status = struct.unpack('>L', data)[0]
        return 1

    def closed(self):
        log.msg('got closed')
        self.shell.processContainerProcessesData(self.data, self.extData)
        self.shell = None
        return 1

class ProcessChannel(channel.SSHChannel):
    name = 'session'
    def __init__(self, shell, cmd, execcmd, *args, **kwargs):
        """
        channelID: id of channel we need to track
        """
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.shell = shell
        self.execcmd = execcmd
        self.cmd = cmd
        self.data = b''
        self.extData = b''

    def channelOpen(self, data):
        """
        by this time id is set, id represents the channel number in the same
        connection, thinking of using id to track the execution of a program
        that is still running so that we can kill it later
        """
        log.msg('execute command: ', self.execcmd)
        self.conn.sendRequest(self, 'exec', common.NS(self.execcmd),
                                  wantReply=False)

    def dataReceived(self, data):
        self.data += data

    def extReceived(self, dataType, data):
        self.extData += data

    def request_exit_signal(self, data):
        log.msg("got request exit-signal")
        return 1

    def request_exit_status(self, data):
        log.msg("got request exit-status")
        status = struct.unpack('>L', data)[0]
        return 1

    def closed(self):
        log.msg('got closed')
        self.shell.processPidDataReceived(self.cmd, self.data, self.extData)
        self.shell = None
        self.cmd = None

class KillProcessChannel(channel.SSHChannel):
    name = 'session'
    def __init__(self, shell, pid, execcmd, cmd, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.shell = shell
        self.execcmd = execcmd
        self.pid = pid
        self.cmd = cmd
        self.data = b''
        self.extData = b''

    def channelOpen(self, data):
        """
        by this time id is set, id represents the channel number in the same
        connection.
        """
        log.msg('execute command: ', self.execcmd)
        self.conn.sendRequest(self, 'exec', common.NS(self.execcmd),
                                  wantReply=False)

    def dataReceived(self, data):
        self.data += data

    def extReceived(self, dataType, data):
        self.extData += data

    def request_exit_signal(self, data):
        log.msg("got request exit-signal")
        return 1

    def request_exit_status(self, data):
        log.msg("got request exit-status")
        status = struct.unpack('>L', data)[0]
        return 1

    def closed(self):
        log.msg('got closed')
        self.shell.processPidKilledDataReceived(self.cmd, self.data, self.extData)
        self.shell = None

class EchoChannel(channel.SSHChannel):
    """We use command echo to expand commands."""

    name = 'session'
    def __init__(self, execcmd, d, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.defer = d
        self.execcmd = execcmd

        self.data = b''
        self.extData = b''
        self.status = None

    def channelOpen(self, specificData):
        self._log.info(f"expand command: {self.execcmd}")
        self.conn.sendRequest(self, 'exec', common.NS(self.execcmd),
                                  wantReply=False)

    def dataReceived(self, data):
        self.data += data

    def extReceived(self, dataType, data):
        self.extData += data

    def request_exit_signal(self, data):
        return 1

    def request_exit_status(self, data):
        self.status = struct.unpack('>L', data)[0]
        return 1

    def closed(self):
        _expandCmd = None
        if self.status == 0:
            _expandCmd = self.data.decode('utf8')
            self.defer.callback(_expandCmd)
        else:
            self.defer.errback(Exception('failed to expand variables'))

class ChangePasswordChannel(channel.SSHChannel):
    """We use command echo to expand commands."""

    name = 'session'
    def __init__(self, execcmd, d, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.defer = d
        self.execcmd = execcmd

        self.data = b''
        self.extData = b''
        self.status = None

    def channelOpen(self, specificData):
        self._log.info(f"update password command: {self.execcmd}")
        self.conn.sendRequest(self, 'exec', common.NS(self.execcmd),
                                  wantReply=False)

    def dataReceived(self, data):
        channel.SSHChannel.dataReceived(self, data)

    def extReceived(self, dataType, data):
        channel.SSHChannel.extReceived(self, dataType, data)

    def request_exit_signal(self, data):
        return 1

    def request_exit_status(self, data):
        self.status = struct.unpack('>L', data)[0]
        return 1

    def closed(self):
        if self.status == 0:
            self.defer.callback("success")
        else:
            self.defer.errback(Exception('failed to update password'))

class SSHChannel(channel.SSHChannel):
    """
    BEGIN SMP: A new channel class used for request to backend ssh server
    """
    name = 'session'

    def __init__(self, protocol, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.protocol = protocol
        self.request = protocol.request
        # self.backendUsername = bytes(CowrieConfig().get('proxy', 'backend_user'), 'utf-8')
        # self.isftp = False
        self.user = protocol.user
        # self.username = bytes(protocol.user.username, 'utf-8')
        self.data = b''
        protocol.backendChannel = self

    def channelOpen(self, specificData):
        self._log.info(f"connect to backend, request is: {self.request}")
        modes = b''

        if self.request == b'shell-pty':
            # set terminal, window size and modes
            for i in range(0, len(self.user.attrs)):
                mode = self.user.attrs[i:i+1]
                modes += struct.pack('>B', mode[0][0]) + struct.pack('>L', mode[0][1])
            modes += struct.pack('>B', 0)
            term = session.packRequest_pty_req(self.user.terminal, self.user.windowSize, modes)

            # send env-req
            for env in self.user.reqEnv:
                self.conn.sendRequest(self, 'env', env)
                # self.conn.sendRequest(self, 'env', b'\x00\x00\x00\x06LC_ALL\x00\x00\x00\x0ben_US.UTF-8')

            # send pty-req
            self.conn.sendRequest(self, 'pty-req', term)
            # send shell-req
            self.conn.sendRequest(self, 'shell', b'')
        elif self.request == b'shell':
            self.conn.sendRequest(self, 'shell', b'', wantReply=True)
        elif self.request == b'exec':
            self.conn.sendRequest(self, 'exec', common.NS(self.protocol.execcmd),
                                  wantReply=True).addCallback(self._gotResponse)
        elif self.request == b'bash':
            self.conn.sendRequest(self, 'exec', common.NS('bash'),
                                  wantReply=True).addCallback(self._gotResponse)
        elif self.request == b'subsystem':
            self.isftp = True
            self.conn.sendRequest(self, 'subsystem', common.NS('sftp'))
            #FIXME more like a hack, we sent this to initiate sftp got it from
            #real client but it was sent earlier than expected
            self.write(b'\x00\x00\x00\x05\x01\x00\x00\x00\x03')

    def _gotResponse(self, data):
        self._log.info("_gotResponse, callback cbAnalyseInput")
        self.protocol.cbAnalyseInput(b'')

    def write(self, data):
        self._log.info("frontend write to backend")
        channel.SSHChannel.write(self, data)

    def dataReceived(self, data):
        # if not self.isftp:
        #     data = data.replace(self.backendUsername, self.username)
        self._log.debug("backend dataReceived")
        i = data.find(b'XXXXXXX')
        self._log.debug('found XXXXX at ', i)

        if i == 0:
            self.protocol.cbAnalyseInput(data)
            self.data = b''
        elif i > 0:
            motif = data[i:-1]
            _data = data[0:i]
            self.protocol.write(_data)
            self.protocol.cbAnalyseInput(motif)
            self.data = b''
        else:
            self.protocol.write(data)

    def extReceived(self, dataType, data):
        """
        Called when we receive extended data (usually standard error).

        @type dataType: L{int}
        @type data:     L{str}
        """

        self._log.debug("backend extReceieved")
        self.protocol.extWrite(data)

    def request_exit_signal(self, data):
        self._log.info("got request exit-signal")
        return 1

    def request_exit_status(self, data):
        self._log.info("got request exit-status")
        return 1

    def closeConnection(self):
        self._log.info('got closeConnection')
        self.conn.sendEOF(self)
        self.loseConnection()

    def closed(self):
        self._log.info('got closed')
        self.conn.transport.loseConnection()
        """
        notify protocol to close connection with client
        """
        if self.protocol:
            self.protocol.eofReceived()
            self.protocol = None
            self.request = b''
            self.username = b''
            self.backendUsername = b''
            self.user = None

    def windowChanged(self, windowSize):
        self._log.info('got windowChanged from session')
        size = session.packRequest_window_change(windowSize)
        self.conn.sendRequest(self, 'window-change', size)

class SSHChannelShell(channel.SSHChannel):
    """
    A new channel class used to request shell only.
    """
    name = 'session'

    def __init__(self, protocol, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.protocol = protocol
        self.request = protocol.request
        self.user = protocol.user
        self.data = b''
        protocol.backendChannel = self
        protocol.shell.addbackend(self, protocol)

    def channelOpen(self, specificData):
        self._log.info(f"connect to backend, request is: {self.request}")

        # send shell-req
        self.conn.sendRequest(self, 'shell', b'')

    def write(self, data):
        channel.SSHChannel.write(self, data)

    def dataReceived(self, data):
        if hasattr(self.protocol, "shell") and self.protocol.shell:
            self.protocol.shell.dataReceivedFromBackend(data)
        else:
            self.closeConnection()
            del self.protocol

    def extReceived(self, dataType, data):
        """
        Called when we receive extended data (usually standard error).

        @type dataType: L{int}
        @type data:     L{str}
        """
        if hasattr(self.protocol, "shell") and self.protocol.shell:
            self.protocol.shell.extDataReceivedFromBackend(data)
        else:
            self.closeConnection()
            del self.protocol

    def request_exit_signal(self, data):
        return 1

    def request_exit_status(self, data):
        return 1

    def closeConnection(self):
        self.conn.sendEOF(self)
        self.loseConnection()

    def eofReceived(self):
        """
        Called when the other side will send no more data.
        """
        self._log.info("remote eof")

    def closeReceived(self):
        """
        Called when the other side has closed the channel.
        """
        self._log.info("remote close")
        self.loseConnection()

    def closed(self):
        """
        notify protocol to close connection with client
        """
        if self.protocol:
            self.protocol.eofReceived()
            self.protocol = None
            self.request = b''
            self.username = b''
            self.backendUsername = b''
            self.user = None

class SSHChannelPtyShell(channel.SSHChannel):
    """
    BEGIN SMP: A new channel class used for request to backend ssh server
    """
    name = 'session'

    def __init__(self, protocol, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.protocol = protocol
        self.request = protocol.request
        # self.backendUsername = bytes(CowrieConfig().get('proxy', 'backend_user'), 'utf-8')
        # self.isftp = False
        self.user = protocol.user
        # self.username = bytes(protocol.user.username, 'utf-8')
        self.data = b''
        protocol.backendChannel = self
        # testing protocol 2, channel is added to shell
        protocol.shell.addbackend(self, protocol)

    def channelOpen(self, specificData):
        self._log.info(f"connect to backend, request is: {self.request}")
        modes = b''

        if self.request == b'shell-pty':
            # set terminal, window size and modes
            if hasattr(self.user, 'attrs') and self.user.attrs:
                for i in range(0, len(self.user.attrs)):
                    mode = self.user.attrs[i:i+1]
                    modes += struct.pack('>B', mode[0][0]) + struct.pack('>L', mode[0][1])
            modes += struct.pack('>B', 0)

            # send env-req
            for env in self.user.reqEnv:
                self.conn.sendRequest(self, 'env', env)
                # self.conn.sendRequest(self, 'env', b'\x00\x00\x00\x06LC_ALL\x00\x00\x00\x0ben_US.UTF-8')

            # send pty-req
            if hasattr(self.user, 'terminal') and hasattr(self.user, 'windowSize'):
                term = session.packRequest_pty_req(self.user.terminal, self.user.windowSize, modes)
                self.conn.sendRequest(self, 'pty-req', term)

            # send shell-req
            self.conn.sendRequest(self, 'shell', b'',wantReply=True).addCallback(self._gotResponse)

    def _gotResponse(self, data):
        """
        Call this function processed received data that were before shell open
        is finished.
        """
        self.protocol._cbEmptyBuf()

    def write(self, data):
        channel.SSHChannel.write(self, data)

    def dataReceived(self, data):
        if hasattr(self.protocol, "shell") and self.protocol.shell:
            self.protocol.shell.dataReceivedFromBackend(data)
        else:
            self.closeConnection()
            del self.protocol

    def extReceived(self, dataType, data):
        """
        Called when we receive extended data (usually standard error).

        @type dataType: L{int}
        @type data:     L{str}
        """

        if hasattr(self.protocol, "shell") and self.protocol.shell:
            self.protocol.shell.extDataReceivedFromBackend(data)
        else:
            self.closeConnection()
            del self.protocol

    def request_exit_signal(self, data):
        return 1

    def request_exit_status(self, data):
        return 1

    def closeConnection(self):
        self.conn.sendEOF(self)
        self.loseConnection()

    def closed(self):
        self._log.info('got closed')
        # notify protocol to close connection with client
        if self.protocol:
            self.protocol.eofReceived()
            self.protocol = None
            self.request = b''
            self.username = b''
            self.backendUsername = b''
            self.user = None

    def windowChanged(self, windowSize):
        self._log.info('got windowChanged from session')
        size = session.packRequest_window_change(windowSize)
        self.conn.sendRequest(self, 'window-change', size)

class SSHChannelExecBash(channel.SSHChannel):
    """
    We open a session by invoking bash only.
    """
    name = 'session'

    def __init__(self, protocol, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.protocol = protocol
        self.request = protocol.request
        self.user = protocol.user
        self.data = b''
        protocol.backendChannel = self
        protocol.shell.addbackend(self, protocol)

    def channelOpen(self, specificData):
        self._log.info(f"connect to backend, request is: {self.request}")

        if self.request == b'bash':
            self.conn.sendRequest(self, 'exec', common.NS('bash'),
                                  wantReply=True).addCallback(self._gotResponse)

    def openFailed(self, reason):
        """
        Called when the open failed for some reason.
        reason.desc is a string descrption, reason.code the SSH error code.

        @type reason: L{error.ConchError}
        """
        super().openFailed(reason)
        self.conn.transport.loseConnection()

    def _gotResponse(self, data):
        self._log.info("_gotResponse, callback cbAnalyseInput")
        self.protocol.cbAnalyseInput(b'')

    def write(self, data):
        self._log.info("frontend write to backend")
        channel.SSHChannel.write(self, data)

    def dataReceived(self, data):
        self._log.debug("backend dataReceived")

        if self.protocol and hasattr(self.protocol, "shell") and self.protocol.shell:
            self.protocol.shell.dataReceivedFromBackend(data)
        else:
            # the other side may close the connection,
            # inform the protocol to close this channel,
            # in case the protocol has to perfom other stuff.
            if self.protocol:
                self.protocol.closeChannel()
            self.protocol = None

    def extReceived(self, dataType, data):
        """
        Called when we receive extended data (usually standard error).

        @type dataType: L{int}
        @type data:     L{str}
        """

        self._log.debug("backend extReceived")
        if self.protocol and hasattr(self.protocol, "shell") and self.protocol.shell:
            self.protocol.shell.extDataReceivedFromBackend(data)
        else:
            # the other side may close the connection,
            # inform the protocol to close this channel,
            # in case the protocol has to perfom other stuff.
            if self.protocol:
                self.protocol.closeChannel()
            self.protocol = None

    def request_exit_signal(self, data):
        return 1

    def request_exit_status(self, data):
        return 1

    def closeConnection(self):
        self.conn.sendEOF(self)
        self.loseConnection()

    def closed(self):
        # notify protocol to close connection with client
        if self.protocol:
            self.protocol.closed()
            self.protocol = None
            self.request = b''
            self.username = b''
            self.backendUsername = b''
            self.user = None

    def windowChanged(self, windowSize):
        self._log.info('got windowChanged from session')
        size = session.packRequest_window_change(windowSize)
        self.conn.sendRequest(self, 'window-change', size)

class SSHChannelExecScp(channel.SSHChannel):
    """
    This channel is used to execute scp command.
    """
    name = 'session'

    def __init__(self, protocol, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.protocol = protocol
        self.request = protocol.request
        self.user = protocol.user
        self.data = b''
        protocol.backendChannel = self

    def channelOpen(self, specificData):
        self._log.info(f"connect to backend, request is: {self.request}")

        self.conn.sendRequest(self, 'exec', common.NS(self.protocol.execcmd),
                                    wantReply=False)

    def write(self, data):
        channel.SSHChannel.write(self, data)

    def dataReceived(self, data):
        """
        When data is received from backend, it will be passed directly
        to the protocol without going through shell, because there is no
        decision is made for scp command.

        @type data:     L{str}
        """

        self.protocol.dataReceivedFromBackend(data)

    def extReceived(self, dataType, data):
        """
        Called when we receive extended data (usually standard error).

        @type dataType: L{int}
        @type data:     L{str}
        """
        self.protocol.extWrite(data)

    def request_exit_signal(self, data):
        return 1

    def request_exit_status(self, data):
        return 1

    def closeConnection(self):
        self.conn.sendEOF(self)
        self.loseConnection()

    def closed(self):
        """
        notify protocol to close connection with client
        """
        self.conn.transport.loseConnection()
        if self.protocol:
            self.protocol.eofReceived()
            self.protocol = None
            self.request = b''
            self.username = b''
            self.user = None

class SFTPChannel(channel.SSHChannel):
    """
    BEGIN SMP: A new channel class used for request to backend ssh server
    """
    name = 'session'

    def __init__(self, protocol, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.protocol = protocol
        self.request = protocol.request
        self.isftp = True
        self.data = b''
        protocol.backendChannel = self

    def channelOpen(self, specificData):
        self._log.info(f"connect to backend, request is: {self.request}")

        self.isftp = True
        self.conn.sendRequest(self, 'subsystem', common.NS('sftp'), wantReply=True).addCallback(self._gotResponse)

    def _gotResponse(self, data):
        self.protocol.d.callback(data)

    def write(self, data):
        channel.SSHChannel.write(self, data)

    def dataReceived(self, data):
        self.protocol.write(data)

    def extReceived(self, dataType, data):
        """
        Called when we receive extended data (usually standard error).

        @type dataType: L{int}
        @type data:     L{str}
        """
        self.protocol.extWrite(data)

    def request_exit_signal(self, data):
        return 1

    def request_exit_status(self, data):
        return 1

    def closeConnection(self):
        self._log.info('got closeConnection')
        self.conn.sendEOF(self)
        self.loseConnection()

    def closed(self):
        self._log.info('got closed')
        # notify protocol to close connection with client
        if self.protocol:
            self.protocol.eofReceived()
            self.protocol = None
            self.request = b''
            self.username = b''
            self.backendUsername = b''
            self.user = None

    def windowChanged(self, windowSize):
        self._log.info('got windowChanged from session')
        size = session.packRequest_window_change(windowSize)
        self.conn.sendRequest(self, 'window-change', size)
