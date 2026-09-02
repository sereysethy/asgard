from twisted.internet.protocol import ClientFactory
from twisted.python import log
from smartproxy.ssh.transport import SSHClientTransport

class SSHClientFactory(ClientFactory):
    """
    SSH Client Factory used to build a ssh client factory
    """
    def __init__(self, shell, username, password, container=None):
        self.shell = shell
        self.username = username
        self.password = password
        self.container = container

    def buildProtocol(self, addr):
        protocol = SSHClientTransport(
            username=self.username,
            password=self.password,
            pubKeyPath=None,
            privKeyPath = None,
            shell = self.shell)
        return protocol

    def clientConnectionFailed(self, connector, reason):
        """
        Called when a connection has failed to connect.

        It may be useful to call connector.connect() - this will reconnect.

        @type reason: L{twisted.python.failure.Failure}
        """
        log.msg('clientConnectionFailed reason: ', reason)
        if not self.shell.done:
            log.msg('trying to reconnect...')
            connector.connect()


    def clientConnectionLost(self, connector, reason):
        """
        Called when an established connection is lost.

        It may be useful to call connector.connect() - this will reconnect.

        @type reason: L{twisted.python.failure.Failure}
        """
        log.msg('clientConnectionLost reason: ', reason)
        if not self.shell.done:
            log.msg('trying to reconnect...')
            connector.connect()