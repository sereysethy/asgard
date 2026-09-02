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
        log.msg('execute command: ', self.execcmd)
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

    def channelOpen(self, data):
        log.msg('expand command: ', self.execcmd)
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

    def channelOpen(self, data):
        log.msg('update password command: ', self.execcmd)
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
        self.backendUsername = bytes(CowrieConfig().get('proxy', 'backend_user'), 'utf-8')
        self.isftp = False
        self.user = protocol.user
        self.username = bytes(protocol.user.username, 'utf-8')
            
        protocol.backendChannel = self

    def channelOpen(self, data):
        log.msg('connect to backend, request is: %s'% (self.request))
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
            # self.conn.sendRequest(self, 'pty-req', term)
            # send shell-req
            self.conn.sendRequest(self, 'shell', b'')
        elif self.request == b'shell':
            self.conn.sendRequest(self, 'shell', b'', wantReply=True)
        elif self.request == b'exec':
            self.conn.sendRequest(self, 'exec', common.NS(self.protocol.execcmd), 
                                  wantReply=True).addCallback(self._gotResponse)
        elif self.request == b'subsystem':
            self.isftp = True
            self.conn.sendRequest(self, 'subsystem', common.NS('sftp'))
            #FIXME more like a hack, we sent this to initiate sftp got it from
            #real client but it was sent earlier than expected
            self.write(b'\x00\x00\x00\x05\x01\x00\x00\x00\x03')
        
    def _gotResponse(self, data):
        # log.msg(eventid="smp.backend.response", output=data, sessionno=self.session.sessionno, format='Response Data: %(output)s')
        pass

    def write(self, data):
        print('write: ', data)
        channel.SSHChannel.write(self, data)
        
    def dataReceived(self, data):
        if not self.isftp:
            data = data.replace(self.backendUsername, self.username)
        print('dataReceived: ', data)
        self.protocol.write(data)

    def extReceived(self, dataType, data):
        """
        Called when we receive extended data (usually standard error).

        @type dataType: L{int}
        @type data:     L{str}
        """
        if not self.isftp:
            data = data.replace(self.backendUsername, self.username)
        print('extReceieved: ', data)
        self.protocol.extWrite(data)

    def request_exit_signal(self, data):
        log.msg("got request exit-signal")
        return 1

    def request_exit_status(self, data):
        log.msg("got request exit-status")
        return 1
        
    def closeConnection(self):
        log.msg('got closeConnection')
        self.conn.sendEOF(self)
        self.loseConnection()

    def closed(self):
        log.msg('got closed')
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
        log.msg('got windowChanged from session')
        size = session.packRequest_window_change(windowSize)
        self.conn.sendRequest(self, 'window-change', size)

class SSHChannelShell(SSHChannel):
    def __init__(self, shell, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.shell = shell
        # self.protocol = protocol
        # self.request = protocol.request
        # self.backendUsername = bytes(CONFIG.get('proxy', 'username'), 'utf-8')
        # self.isftp = False
        # self.user = protocol.user
        # self.username = bytes(protocol.user.username, 'utf-8')
        # protocol.backendChannelShell = self
        shell.backendChannel = self
        
    def channelOpen(self, data):
        log.msg('connect to backend, request is: %s'% ('shell'))
        self.conn.sendRequest(self, 'shell', b'', wantReply=True)

    def _gotResponse(self, data):
        print('FFFFF')

    def dataReceived(self, data):
        print('dataReceived shell: ', data)
        self.shell.dataReceived(data)

    def extReceived(self, dataType, data):
        print('extReceived: ', data)
        self.shell.extReceieved(dataType, data)

class SSHChannelPtyShell(SSHChannel):
    def __init__(self, shell, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.shell = shell
        self.protocol = shell.protocol
        self.request = self.protocol.request
        self.backendUsername = bytes(CowrieConfig().get('proxy', 'backend_user'), 'utf-8')
        self.isftp = False
        self.user = self.protocol.user
        self.username = bytes(self.protocol.user.username, 'utf-8')

        shell.backendChannel = self

    def channelOpen(self, data):
        log.msg('connect to backend, request is: %s'% ('shell-pty'))
        modes = b''
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

    def dataReceived(self, data):
        print('dataReceived pty-shell: ', data)
        self.shell.interactiveDataReceived(data)

    def extReceived(self, dataType, data):
        print('extReceived pty-shell: ', data)
        self.shell.dataReceived(data)
        
    def write(self, data):
        print('write shell-pty: ', data)
        channel.SSHChannel.write(self, data)