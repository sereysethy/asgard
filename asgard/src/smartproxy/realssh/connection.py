from twisted.conch.ssh import connection
from twisted.python import log
from smartproxy.ssh import channel

class SSHConnection(connection.SSHConnection):
    """
    A new connection used to open a channel to SSH backend server
    """
    def __init__(self, frontend, *args, **kwargs):
        connection.SSHConnection.__init__(self)
        self.frontend = frontend

    def serviceStarted(self):
        log.msg("self.frontend.request: ", self.frontend.request)
        if self.frontend.request == b'exec':
            self.frontend.d.callback(self)
        elif self.frontend.request == b'shell-pty':
            self.frontend.d.callback(self)
        elif self.frontend.request == b'exec-scp':
            self.frontend.d.callback(self)
        elif self.frontend.request == b'subsystem':
            self.frontend.d.callback(self)
        elif self.frontend.request == b'direct-tcpip':
            self.frontend.d.callback(self)

    def serviceStopped(self):
        """
        Called when the connection is stopped.
        """
        if hasattr(self, "tcpPortFowardingProtocol"):
            self.tcpPortFowardingProtocol = None

        connection.SSHConnection.serviceStopped(self)
