# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""


from twisted.conch.ssh import session
from twisted.conch.ssh.common import getNS
from twisted.python import log


class HoneyPotSSHSession(session.SSHSession):
    """
    This is an SSH channel that's used for SSH sessions
    """

    def __init__(self, *args, **kw):
        """
        The session is a channel that was open by the connection, it was set
        in the avatar. The kw (dict) parameters contains information sent from the
        attacker terminal (client) which consists of:

        Args:
            remoteWindow (int): how many bytes are left in the remote window
            remoteMaxPacket (int): the maximum size of a packet the remote side will
            data (bytes):
            avatar (avatar.CowrieUser): the connected user
        """
        session.SSHSession.__init__(self, *args, **kw)
        user = kw.get('avatar')
        print("avatar in session", user)
        user.remote = {}

        if 'remoteWindow' in kw:
            user.remote['remoteWindow'] = kw.get('remoteWindow')
        else:
            user.remote['remoteMaxPacket'] = 0
        if 'remoteMaxPacket' in kw:
            user.remote['remoteMaxPacket'] = kw.get('remoteMaxPacket')
        else:
            user.remote['remoteMaxPacket'] = 0

    def request_env(self, data: bytes) -> int:
        """
        Process a request to pass an environment variable.

        Args:
            data: The environment variable name and value, each encoded
                as an SSH protocol string and concatenated.

        Returns:
            A ``true`` value if the request to pass this environment
            variable was accepted, otherwise a false value.
        """
        name, rest = getNS(data)
        value, rest = getNS(rest)
        if rest:
            raise ValueError("Bad data given in env request")
        log.msg(
            eventid="cowrie.client.var",
            format="request_env: %(name)s=%(value)s",
            name=name.decode("utf-8"),
            value=value.decode("utf-8"),
        )
        # FIXME: This only works for shell, not for exec command
        if self.session:
            self.session.reqEnv.append(data)
            self.session.environ[name.decode("utf-8")] = value.decode("utf-8")
        return 0

    def request_agent(self, data: bytes) -> int:
        log.msg(f"request_agent: {repr(data)}")
        return 0

    def request_x11_req(self, data: bytes) -> int:
        log.msg(f"request_x11: {repr(data)}")
        return 0

    def closed(self) -> None:
        """
        This is reliably called on session close/disconnect and calls the avatar
        """
        session.SSHSession.closed(self)
        self.client = None

    def eofReceived(self) -> None:
        """
        Redirect EOF to emulated shell. If shell is gone, then disconnect
        """
        if self.session:
            self.session.eofReceived()
        else:
            self.loseConnection()

    def sendEOF(self) -> None:
        """
        Utility function to request to send EOF for this session
        """
        self.conn.sendEOF(self)

    def sendClose(self) -> None:
        """
        Utility function to request to send close for this session
        """
        self.conn.sendClose(self)

    def channelClosed(self) -> None:
        log.msg("Called channelClosed in SSHSession")
