from twisted.internet.protocol import ClientFactory
from twisted.python import log
from smartproxy.realssh.transportv2 import SSHClientTransport

class SSHClientFactory(ClientFactory):
    """
    SSH Client Factory used to build a ssh client factory

    Attributes:
        username: username from the frontend
        password: password from the frontend
        frontend: frontend transport
    """
    def __init__(self, username, password, frontend):
        self.username = username
        self.password = password
        self.frontend = frontend

    def buildProtocol(self, addr):
        """
        Create the SSH protocol to handle SSH connection

        Args:
            addr: client address (IP, port)
        """
        protocol = SSHClientTransport(
            username=self.username,
            password=self.password,
            pubKeyPath=None,
            privKeyPath = None,
            frontend=self.frontend)
        return protocol

    def clientConnectionFailed(self, connector, reason):
        """
        Called when a connection has failed to connect.

        It may be useful to call connector.connect() - this will reconnect.

        Args:
            reason (twisted.python.failure.Failure): reason of failure
        """
        log.msg('clientConnectionFailed reason: ', reason)
        # if not self.shell.done:
        #     log.msg('trying to reconnect...')
        #     connector.connect()


    def clientConnectionLost(self, connector, reason):
        """
        Called when an established connection is lost.

        It may be useful to call connector.connect() - this will reconnect.

        Args:
            reason (twisted.python.failure.Failure): reason of failure
        """
        log.msg('clientConnectionLost reason: ', reason)
        # if not self.shell.done:
        #     log.msg('trying to reconnect...')
        #     connector.connect()
        
    def stopFactory(self):
        """
        This will be called before I stop listening on all Ports/Connectors.

        This can be overridden to perform 'shutdown' tasks such as disconnecting
        database connections, closing files, etc.

        It will be called, for example, before an application shuts down,
        if it was connected to a port. User code should not call this function
        directly.
        """
        self.frontend = None