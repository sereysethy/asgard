# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import annotations

from os import path
from sys import modules

from zope.interface import implementer

from twisted.conch import error
from twisted.conch.ssh import keys
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import ISSHPrivateKey
from twisted.cred.error import UnauthorizedLogin, UnhandledCredentials
from twisted.internet import defer
from twisted.python import failure, log

import docker

from cowrie.core import auth
from cowrie.core import credentials as conchcredentials
from cowrie.core.config import CowrieConfig

from container_pool.container import DockerExistingContainer

@implementer(ICredentialsChecker)
class HoneypotPublicKeyChecker:
    """
    Checker that accepts, logs and denies public key authentication attempts

    SMP:
    Checker that authenticates SSH public keys, based on public keys listed in
    authorized_keys and authorized_keys2 files in user .ssh/ directories.

    @since: 15.0
    """

    credentialInterfaces = (ISSHPrivateKey,)

    def requestAvatarId(self, credentials):
        _pubKey = keys.Key.fromString(credentials.blob)
        log.msg(
            eventid="cowrie.client.fingerprint",
            format="public key attempt for user %(username)s of type %(type)s with fingerprint %(fingerprint)s",
            username=credentials.username,
            fingerprint=_pubKey.fingerprint(),
            key=_pubKey.toString("OPENSSH"),
            type=_pubKey.sshType(),
        )

        authPubkey = CowrieConfig.getboolean('ssh', 'auth_pubkey', fallback=False)
        if authPubkey:
            d = defer.maybeDeferred(self._sanityCheckKey, credentials)
            d.addCallback(self._checkKey, credentials)
            d.addCallback(self._verifyKey, credentials)
            return d
        else:
            return failure.Failure(error.ConchError("Incorrect signature"))

    def _sanityCheckKey(self, credentials):
        """
        Checks whether the provided credentials are a valid SSH key with a
        signature (does not actually verify the signature).

        @param credentials: the credentials offered by the user
        @type credentials: L{ISSHPrivateKey} provider

        @raise ValidPublicKey: the credentials do not include a signature. See
            L{error.ValidPublicKey} for more information.

        @raise BadKeyError: The key included with the credentials is not
            recognized as a key.

        @return: the key in the credentials
        @rtype: L{twisted.conch.ssh.keys.Key}
        """
        if not credentials.signature:
            raise error.ValidPublicKey()

        return keys.Key.fromString(credentials.blob)

    def _checkKey(self, pubKey, credentials):
        """
        Checks the public key against all authorized keys (if any) for the
        user.

        @param pubKey: the key in the credentials (just to prevent it from
            having to be calculated again)
        @type pubKey:

        @param credentials: the credentials offered by the user
        @type credentials: L{ISSHPrivateKey} provider

        @raise UnauthorizedLogin: If the key is not authorized, or if there
            was any error obtaining a list of authorized keys for the user.

        @return: C{pubKey} if the key is authorized
        @rtype: L{twisted.conch.ssh.keys.Key}
        """
        user_keys = self.getAuthorizedKeys(credentials.username)
        if any(
            key == pubKey for key in user_keys
        ):
            return pubKey

        raise UnauthorizedLogin("Key not authorized")

    def getAuthorizedKeys(self, username):
        """Get authorize keys by reading keys from either files or from backend
        """
        auth_pubkey_method = CowrieConfig.get("ssh", "auth_pubkey_method", fallback="file")

        if auth_pubkey_method == "file":
            local_home = CowrieConfig.get("ssh", "local_home")
            authorized_keys = path.join(local_home, username.decode('utf8'), ".ssh", "authorized_keys")
            try:
                return [keys.Key.fromFile(authorized_keys)]
            except FileNotFoundError:
                return []
        elif auth_pubkey_method == "container":
            containerName = CowrieConfig.get("docker", "container_name")
            try:
                container = DockerExistingContainer()
                if container.connect(containerName):
                    authorized_keys = container.getpubkeys(username.decode('utf8'))
                    if authorized_keys:
                        log.msg(f"getting pubkeys from backend for: {username}")
                        return [keys.Key.fromString(key) for key in authorized_keys]
            except docker.errors.APIError:
                return []

        return []

    def _verifyKey(self, pubKey, credentials):
        """
        Checks whether the credentials themselves are valid, now that we know
        if the key matches the user.

        @param pubKey: the key in the credentials (just to prevent it from
            having to be calculated again)
        @type pubKey: L{twisted.conch.ssh.keys.Key}

        @param credentials: the credentials offered by the user
        @type credentials: L{ISSHPrivateKey} provider

        @raise UnauthorizedLogin: If the key signature is invalid or there
            was any error verifying the signature.

        @return: The user's username, if authentication was successful
        @rtype: L{bytes}
        """
        try:
            if pubKey.verify(credentials.signature, credentials.sigData):
                return credentials.username
        except Exception as e:  # Any error should be treated as a failed login
            raise UnauthorizedLogin("Error while verifying key") from e

        raise UnauthorizedLogin("Key signature invalid.")

@implementer(ICredentialsChecker)
class HoneypotNoneChecker:
    """
    Checker that does no authentication check
    """

    credentialInterfaces = (conchcredentials.IUsername,)

    def requestAvatarId(self, credentials):
        return defer.succeed(credentials.username)


@implementer(ICredentialsChecker)
class HoneypotPasswordChecker:
    """
    Checker that accepts "keyboard-interactive" and "password"
    """

    credentialInterfaces = (
        conchcredentials.IUsernamePasswordIP,
        conchcredentials.IPluggableAuthenticationModulesIP,
    )

    def requestAvatarId(self, credentials):
        if hasattr(credentials, "password"):
            if self.checkUserPass(
                credentials.username, credentials.password, credentials.ip
            ):
                return defer.succeed(credentials.username)
            return defer.fail(UnauthorizedLogin())
        if hasattr(credentials, "pamConversion"):
            return self.checkPamUser(
                credentials.username, credentials.pamConversion, credentials.ip
            )
        return defer.fail(UnhandledCredentials())

    def checkPamUser(self, username, pamConversion, ip):
        r = pamConversion((("Password:", 1),))
        return r.addCallback(self.cbCheckPamUser, username, ip)

    def cbCheckPamUser(self, responses, username, ip):
        for response, _ in responses:
            if self.checkUserPass(username, response, ip):
                return defer.succeed(username)
        return defer.fail(UnauthorizedLogin())

    def checkUserPass(self, theusername: bytes, thepassword: bytes, ip: str) -> bool:
        # UserDB is the default auth_class
        authname = auth.UserDB

        # Is the auth_class defined in the config file?
        if CowrieConfig.has_option("honeypot", "auth_class"):
            authclass = CowrieConfig.get("honeypot", "auth_class")
            authmodule = "cowrie.core.auth"

            # Check if authclass exists in this module
            if hasattr(modules[authmodule], authclass):
                authname = getattr(modules[authmodule], authclass)
            else:
                log.msg(f"auth_class: {authclass} not found in {authmodule}")

        theauth = authname()

        if theauth.checklogin(theusername, thepassword, ip):
            log.msg(
                eventid="cowrie.login.success",
                format="login attempt [%(username)s/%(password)s] succeeded",
                username=theusername,
                password=thepassword,
            )
            return True

        log.msg(
            eventid="cowrie.login.failed",
            format="login attempt [%(username)s/%(password)s] failed",
            username=theusername,
            password=thepassword,
        )
        return False
