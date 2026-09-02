from twisted.conch.ssh import transport, connection, userauth, channel, common, keys
from twisted.internet import defer
from twisted.python import log

from smartproxy.realssh.connection import SSHConnection

class SSHClientTransport(transport.SSHClientTransport):
    def __init__(self, username, password, pubKeyPath, privKeyPath, frontend):
        self.username = username
        self.password = password
        self.pubKeyPath = pubKeyPath
        self.privKeyPath = privKeyPath
        self.frontend = frontend

    def verifyHostKey(self, pubKey, fingerprint):
        # in a real app, you should verify that the fingerprint matches
        # the one you expected to get from this server
        return defer.succeed(True)

    def connectionSecure(self):
        self.requestService(
            SSHUserAuthClient(self.username, self.password,
                              self.pubKeyPath, self.privKeyPath,
                              SSHConnection(self.frontend)))

    def receiveError(self, reasonCode, description):
        """
        Called when we receive a disconnect error message from the other
        side.

        @param reasonCode: the reason for the disconnect, one of the
                           DISCONNECT_ values.
        @type reasonCode: L{int}
        @param description: a human-readable description of the
                            disconnection.
        @type description: L{str}
        """
        log.msg('Got remote error, code %s\nreason: %s' % (reasonCode,
                                                           description))
        # if reasonCode == 2:
        #     self.shell.deferred.errback(Exception("Too many authentication failures"))

    def loseConnection(self):
        """Send a disconnect message to the server."""

        transport.SSHClientTransport.loseConnection(self)
        # if self.shell:
        #     self.shell.conn = None
        # self.shell = None

    def connectionLost(self, reason):
        """Connection to the server was lost."""

        transport.SSHClientTransport.connectionLost(self, reason)
        # if self.shell:
        #     self.shell.conn = None
        # self.shell = None

class SSHUserAuthClient(userauth.SSHUserAuthClient):
    """This is just the name, this class will implement all auth methods
    supported by server.
    """
    def __init__(self, username=None, password=None, pubKeyPath=None, privKeyPath=None, connection=None):
        userauth.SSHUserAuthClient.__init__(self, username, connection)

        if privKeyPath is not None:
            self.privateKey = keys.Key.fromFile(filename=privKeyPath)
        else:
            self.privateKey = None

        if pubKeyPath is not None:
            self.publicKey = keys.Key.fromFile(filename=pubKeyPath)
        else:
            self.publicKey = None

        self.password = password

    def getPublicKey(self):
        log.msg("returned public key")
        if self.publicKey:
            return defer.succeed(self.publicKey)
        else:
            return None

    def getPrivateKey(self):
        log.msg("returned a private key")
        if self.privateKey:
            return defer.succeed(self.privateKey)
        else:
            return None

    def getPassword(self, prompt=None):
        log.msg('returned a password')
        return defer.succeed(self.password)
