from zope.interface import implementer
from twisted.conch.ssh.common import NS, getNS
from twisted.internet import error, defer, protocol, reactor
from twisted.python import failure, log

from cowrie.core.config import CowrieConfig
from smartproxy.realssh import channel

from twisted.conch.interfaces import ISFTPServer
from smartproxy.realssh.factory import SSHClientFactory
from container_pool.container import DockerExistingContainer
from twisted.conch.ssh import filetransfer as conchfiletransfer


@implementer(ISFTPServer)
class FTPServer():
    def __init__(self, avatar):
        self.avatar = avatar

    def gotVersion(self, otherVersion, extData):
        """
        Called when the client sends their version info.

        otherVersion is an integer representing the version of the SFTP
        protocol they are claiming.
        extData is a dictionary of extended_name : extended_data items.
        These items are sent by the client to indicate additional features.

        This method should return a dictionary of extended_name : extended_data
        items.  These items are the additional features (if any) supported
        by the server.
        """
        print("gotVersion: ", otherVersion, extData)
        return {}

    def openFile(self, filename, flags, attrs):
        """
        Called when the clients asks to open a file.

        @param filename: a string representing the file to open.

        @param flags: an integer of the flags to open the file with, ORed
        together.  The flags and their values are listed at the bottom of
        L{twisted.conch.ssh.filetransfer} as FXF_*.

        @param attrs: a list of attributes to open the file with.  It is a
        dictionary, consisting of 0 or more keys.  The possible keys are::

            size: the size of the file in bytes
            uid: the user ID of the file as an integer
            gid: the group ID of the file as an integer
            permissions: the permissions of the file with as an integer.
            the bit representation of this field is defined by POSIX.
            atime: the access time of the file as seconds since the epoch.
            mtime: the modification time of the file as seconds since the epoch.
            ext_*: extended attributes.  The server is not required to
            understand this, but it may.

        NOTE: there is no way to indicate text or binary files.  it is up
        to the SFTP client to deal with this.

        This method returns an object that meets the ISFTPFile interface.
        Alternatively, it can return a L{Deferred} that will be called back
        with the object.
        """
        print("openFile: ", filename, flags, attrs)
        return b''

    def removeFile(self, filename):
        """
        Remove the given file.

        This method returns when the remove succeeds, or a Deferred that is
        called back when it succeeds.

        @param filename: the name of the file as a string.
        """
        print("removeFile")

    def renameFile(self, oldpath, newpath):
        """
        Rename the given file.

        This method returns when the rename succeeds, or a L{Deferred} that is
        called back when it succeeds. If the rename fails, C{renameFile} will
        raise an implementation-dependent exception.

        @param oldpath: the current location of the file.
        @param newpath: the new file name.
        """
        print("renameFile")

    def makeDirectory(self, path, attrs):
        """
        Make a directory.

        This method returns when the directory is created, or a Deferred that
        is called back when it is created.

        @param path: the name of the directory to create as a string.
        @param attrs: a dictionary of attributes to create the directory with.
        Its meaning is the same as the attrs in the L{openFile} method.
        """
        print("makeDirectory")

    def removeDirectory(self, path):
        """
        Remove a directory (non-recursively)

        It is an error to remove a directory that has files or directories in
        it.

        This method returns when the directory is removed, or a Deferred that
        is called back when it is removed.

        @param path: the directory to remove.
        """
        print("removeDirectory")

    def openDirectory(self, path):
        """
        Open a directory for scanning.

        This method returns an iterable object that has a close() method,
        or a Deferred that is called back with same.

        The close() method is called when the client is finished reading
        from the directory.  At this point, the iterable will no longer
        be used.

        The iterable should return triples of the form (filename,
        longname, attrs) or Deferreds that return the same.  The
        sequence must support __getitem__, but otherwise may be any
        'sequence-like' object.

        filename is the name of the file relative to the directory.
        logname is an expanded format of the filename.  The recommended format
        is:
        -rwxr-xr-x   1 mjos     staff      348911 Mar 25 14:29 t-filexfer
        1234567890 123 12345678 12345678 12345678 123456789012

        The first line is sample output, the second is the length of the field.
        The fields are: permissions, link count, user owner, group owner,
        size in bytes, modification time.

        attrs is a dictionary in the format of the attrs argument to openFile.

        @param path: the directory to open.
        """
        print("openDirectory: ", path)
        return {}

    def getAttrs(self, path, followLinks):
        """
        Return the attributes for the given path.

        This method returns a dictionary in the same format as the attrs
        argument to openFile or a Deferred that is called back with same.

        @param path: the path to return attributes for as a string.
        @param followLinks: a boolean.  If it is True, follow symbolic links
        and return attributes for the real path at the base.  If it is False,
        return attributes for the specified path.
        """
        print("getAttrs")

    def setAttrs(self, path, attrs):
        """
        Set the attributes for the path.

        This method returns when the attributes are set or a Deferred that is
        called back when they are.

        @param path: the path to set attributes for as a string.
        @param attrs: a dictionary in the same format as the attrs argument to
        L{openFile}.
        """
        print("setAttrs")

    def readLink(self, path):
        """
        Find the root of a set of symbolic links.

        This method returns the target of the link, or a Deferred that
        returns the same.

        @param path: the path of the symlink to read.
        """
        print("readLink")
        return b''

    def makeLink(self, linkPath, targetPath):
        """
        Create a symbolic link.

        This method returns when the link is made, or a Deferred that
        returns the same.

        @param linkPath: the pathname of the symlink as a string.
        @param targetPath: the path of the target of the link as a string.
        """
        print("makeLink")

    def realPath(self, path):
        """
        Convert any path to an absolute path.

        This method returns the absolute path as a string, or a Deferred
        that returns the same.

        @param path: the path to convert as a string.
        """
        print("realPath")
        return b''

    def extendedRequest(self, extendedName, extendedData):
        """
        This is the extension mechanism for SFTP.  The other side can send us
        arbitrary requests.

        If we don't implement the request given by extendedName, raise
        NotImplementedError.

        The return value is a string, or a Deferred that will be called
        back with a string.

        @param extendedName: the name of the request as a string.
        @param extendedData: the data the other side sent with the request,
        as a string.
        """
        print("extendedRequest")

class FileTransferSession(conchfiletransfer.FileTransferServer):
    input = b''
    def __init__(self, data, avatar):
        self.user = avatar
        self.request = b'subsystem'
        self.fileTransferCmd = b'sftp'
        self.isFileTransferCmd = True
        self.backendChannel = None
        self.username = self.user.username
        # ftpserver = conchfiletransfer.FileTransferServer(data, avatar)
        self.ready = False
        super().__init__(data=data, avatar=avatar)


    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need provide how we grab
        the proper transport to access underlying SSH information. Meant to be
        overridden for other protocols.
        """
        return self.transport.session.conn.transport


    def connectionMade(self):
        super().connectionMade()
        pt = self.getProtoTransport()
        self.transportId = pt.transportId
        self.password = pt.transport.password.decode("utf8")
        containerName = CowrieConfig.get("docker", "container_name")
        container = DockerExistingContainer()
        container.connect(containerName)
        accountCreationIsDone = container.createUser(bytes(self.username, "utf8"), bytes(self.password, "utf8"))

        """
        BEGIN SMP:
        Make connection to the target machine
        """
        if accountCreationIsDone:
            username = self.username
            password = self.password
            server = CowrieConfig.get('proxy', 'backend_ssh_host')
            port = CowrieConfig.getint('proxy', 'backend_ssh_port')
            self.d = defer.Deferred()
            self.d.addCallback(self._cbTargetMachineReady)
            self.d.addErrback(self._ebTargetMachineFailed)

            sshClientfactory = SSHClientFactory(username, password, self)
            reactor.connectTCP(server, port, sshClientfactory)
        else:
            pt.transport.loseConnection()
        """
        END SMP
        """

    def _cbTargetMachineReady(self, conn):
        self.backendConn = conn
        self.d = defer.Deferred()
        self.d.addCallback(self._cbChannelReady)
        self.backendConn.openChannel(channel.SFTPChannel(protocol=self, conn=self.backendConn))


    def _ebTargetMachineFailed(self, error):
        pass

    def _cbChannelReady(self, data):
        self.backendChannel.write(self.input)
        # super().dataReceived(self.input)
        self.input = b''
        self.ready = True

    def dataReceived(self, data):
        if self.ready:
            self.backendChannel.write(data)
            # super().dataReceived(data)
        else:
            self.input += data

    def write(self, data):
        self.transport.write(data)


    def extWrite(self, data):
        self.transport.write(data)


    def connectionLost(self, reason):
        if self.backendChannel:
            self.backendChannel.closeConnection()


    def eofReceived(self):
        stat = failure.Failure(error.ProcessDone(status=""))
        self.transport.processEnded(stat)