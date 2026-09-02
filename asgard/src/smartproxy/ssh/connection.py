from twisted.conch.ssh import connection
from twisted.python import log
from smartproxy.ssh import channel

class SSHConnection(connection.SSHConnection):
    """
    A new connection used to open a channel to SSH backend server
    """
    def __init__(self, *args, **kwargs):
        connection.SSHConnection.__init__(self)

    def serviceStarted(self):
        self.transport.shell.start(self)
        
        # if self.shell.request == b'exec':
        #     # self.shell.start(self)
        #     self.shell.callback(self)
        #     # self.shell.defer.callback(self)
            
        # elif self.shell.request == b'shell-pty':
        #     # self.shell.defer.callback(self)
        #     pass
        # else:
        #     pass
        #     # self.openChannel(channel.SSHChannel(protocol=self.shell, conn=self))