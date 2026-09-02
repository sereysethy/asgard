from twisted.conch.ssh import connection
from twisted.python import log
from smartproxy.ssh import channel
from twisted.conch.ssh import common

class SSHConnection(connection.SSHConnection):
    """
    A new connection used to open a channel to SSH backend server
    """
    def __init__(self, frontend, *args, **kwargs):
        connection.SSHConnection.__init__(self)
        # frontend is the server transport
        self.frontend = frontend

    def serviceStarted(self):
        """
        When a the connection (service) is started, we can call back the frontend,
        and along with the connection. This will notify the server_transport.
        """
        self.frontend.d.callback(self)

    def gotGlobalRequest(self, requestType, data):
        """
        we hold some information to delay the channel Session and request exec
        """
        connection.SSHConnection.gotGlobalRequest(self, requestType, data)
        self.frontend.resumeRequestSession()
