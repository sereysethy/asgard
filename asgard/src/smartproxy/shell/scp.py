from twisted.python import failure, log
from twisted.internet import error
from cowrie.core.config import CowrieConfig
from smartproxy.shell.protocol2 import HoneyPotBaseProtocol

import os
import shlex
import shutil
import hashlib
import time
import re

class HoneyPotScpProtocol(HoneyPotBaseProtocol):
    # input_data is static buffer for stdin received from remote client
    input_data = b""

    def __init__(self, avatar, execcmd):
        """
        IMPORTANT
        Before this, execcmd is 'bytes'. Here it converts to 'string' and
        commands work with string rather than bytes.
        """
        HoneyPotBaseProtocol.__init__(self, avatar)
        self.execcmd = execcmd.decode('utf8')
        self.request = b'exec-scp'

        self.stack = []
        self.index = -1
        self.filePermission = 0
        self.fileSize = 0
        self.folderSize = 0
        self.fileName = None
        self.folderName = None
        self.fd = 0
        self.dest = self.user.dest
        self.transferredFile = None
        self.isFileSaved = False

        self.download_path = CowrieConfig.get('honeypot', 'download_path')
        
        tmp_folderName = '%s_%s_%s_%s' % \
                    (time.strftime('%Y%m%d%H%M%S'),
                        self.user.transportId,
                        self.user.sessionId,
                        re.sub('[^A-Za-z0-9]', '_', execcmd.decode('ascii')))
        tmp_archiveName = 'archive_%s_%s_%s_%s' % \
                    (time.strftime('%Y%m%d%H%M%S'),
                        self.user.transportId,
                        self.user.sessionId,
                        re.sub('[^A-Za-z0-9]', '_', execcmd.decode('ascii')))

        self.donwloadedFolder = os.path.join(self.download_path, tmp_folderName)
        self.archiveName      = os.path.join(self.donwloadedFolder, tmp_archiveName)

        os.mkdir(self.donwloadedFolder, mode=0o755)

        self.folders = [self.donwloadedFolder]
        
    def connectionMade(self):
        HoneyPotBaseProtocol.connectionMade(self)
        log.msg(eventid='cowrie.command.input', input=self.execcmd, format='CMD: %(input)s')

    def connectionLost(self, reason):
        """
        Overwritten.

        Called when the connection is shut down.
        Clear any circular references here, and any external references to
        this Protocol. The connection has been closed.
        """
        self.setTimeout(None)
        self.terminal = None  # (this should be done by super above)
        self.cmdstack = []
        self.fs = None
        self.pp = None
        self.user = None
        self.environ = None
        if self.backendChannel:
            self.backendChannel.closeConnection()
            self.backendChannel = None
        
    def dataReceived(self, data):
        """
        Data received from attacker.
        """

        if self.stack[self.index] == 'start' and data[0] == 67:
            """
            C0XXX size filename\n
            """
            self.filePermission, self.fileSize, self.fileName = self.statFile(data)
            self.createFile()
            self.stack.append('file')
            self.index += 1
            self.isFile = True
            self.transferredFile = self.fileName

        elif self.stack[self.index] == 'start_folder' and data[0] == 67:
            """
            C0XXX size filename\n
            """
            self.filePermission, self.fileSize, self.fileName = self.statFile(data)
            self.createFile()
            self.stack.append('file')
            self.index += 1
        elif self.stack[self.index] == 'start' and data[0] == 68:
            """
            D0XXX 0 folder_name\n
            """
            self.folderPermission, self.folderSize, self.folderName = self.statFile(data)
            self.createFolder()
            self.folders.append(self.folderName)
            self.stack.append('folder')
            self.index += 1
            self.transferredFile = self.folderName
            self.isFile = False

        elif self.stack[self.index] == 'start_folder' and data[0] == 68:
            """
            D0XXX 0 folder_name\n
            """
            self.folderPermission, self.folderSize, self.folderName = self.statFile(data)
            self.createFolder()
            self.folders.append(self.folderName)
            self.stack.append('folder')
            self.index += 1
        elif self.stack[self.index] == 'start_file':
            """
            receiving file content
            """
            rcv = len(data)
            if rcv > self.fileSize:
                self.writeFile(data[0:self.fileSize])
            else:
                self.writeFile(data)
            self.fileSize = self.fileSize - rcv
        elif data == b'E\n':
            """
            end of a current folder
            """
            self.stack.append('end_folder')
            self.index += 1

        self.backendChannel.write(data)

    def dataReceivedFromBackend(self, data):
        """
        This function will be called when data is received from backend channel.
        """

        if len(self.stack) == 0 and data == b'\x00':
            self.stack.append('start')
            self.index += 1
        elif self.stack[self.index] == 'file' and data == b'\x00':
            self.stack.append('start_file')
            self.index += 1
        elif self.stack[self.index] == 'folder' and data == b'\x00':
            self.stack.append('start_folder')
            self.index += 1
        elif self.stack[self.index] == 'end_folder' and data == b'\x00':
            self.stack.pop()
            self.stack.pop()
            self.stack.pop()
            self.folders.pop()
            self.index = self.index - 3
        elif self.stack[self.index] == 'start_file' and data == b'\x00':
            self.stack.pop()
            self.stack.pop()
            self.index = self.index - 2
            self.closeFile()

        self.terminal.write(data)
        """
        END SMP
        """

    def extWrite(self, data):
        """
        BEGIN SMP: This function will be called when extended data is received
        from back end channel.
        """
        # log.msg(eventid="smp.backend.extended", output=data, sessionno=self.session.sessionno, format='Extended Data: %(output)s')
        self.terminal.write(data)
        """
        END SMP
        """

    def eofReceived(self):
        """
        BEGIN SMP: when front/backend channel tells us to close the connection,
        we check if the terminal is still active before ending the process
        """
        if self.terminal and hasattr(self.terminal, 'transport'):
            stat = failure.Failure(error.ProcessDone(status=""))
            self.terminal.transport.processEnded(stat)

        """
        This is to prevent a case where this function is called twice when we
        receive a disconnect from client or from backend channel. So we will only
        save file once in either case.
        """
        if not self.isFileSaved:
            self.isFileSaved = True
            
            if self.transferredFile is None:
                """
                File was not yet transferred due to error like file does not exist
                or try to transfer a folder as a file
                """
                shutil.rmtree(self.donwloadedFolder, ignore_errors=True)
                log.msg(eventid='cowrie.session.error_file_transfer',
                                format='scp error transfer file/folder to %(outfile)s',
                                outfile=self.dest
                                )
            else:
                self.saveTransferredFile()
            
        """
        END SMP
        """

    def saveTransferredFile(self):
        """
        Save file or folder. If it is a file, do a hash on its content and
        rename it. If file already exists, we remove it. 
        If it is a folder, we do a hash on the name of the temporary
        folder name, it makes no sense, but to have a consistent filename for
        logged purpose. After file is rename, temporary folder will be removed.
        """
        filepath = os.path.join(self.donwloadedFolder, self.transferredFile)

        if self.isFile:
            filetype = "file"
        
            with open(filepath, 'rb') as f:
                shasum = hashlib.sha256(f.read()).hexdigest()
                hashPath = os.path.join(self.download_path, shasum)

                # If we have content already, delete temp file
                if not os.path.exists(hashPath):
                    os.rename(filepath, hashPath)
                    duplicate = False
                else:
                    os.remove(filepath)
                    duplicate = True
        else:
            filetype = "folder"
            duplicate = False
            shasum = hashlib.sha256(self.donwloadedFolder.encode('utf-8')).hexdigest()
            hashPath = os.path.join(self.download_path, shasum)
            os.rename(filepath, hashPath)

        shutil.rmtree(self.donwloadedFolder, ignore_errors=True)
        log.msg(eventid='cowrie.session.file_upload',
                                format='scp uploaded %(filetype)s %(orifile)s to %(outfile)s',
                                orifile=self.transferredFile,
                                filetype=filetype,
                                destfile=self.dest,
                                duplicate=duplicate,
                                shasum=shasum,
                                outfile=hashPath
                                )

    def createFile(self):
        path = ""
        for f in self.folders:
            path = os.path.join(path, f)

        path = os.path.join(path, self.fileName)
        log.msg("creating file: ", path)
        self.fd = os.open(path, os.O_CREAT|os.O_WRONLY, self.filePermission)

    def writeFile(self, buf):
        os.write(self.fd, buf)

    def createFolder(self):
        path = ""
        for f in self.folders:
            path = os.path.join(path, f)

        path = os.path.join(path, self.folderName)
        log.msg("creating folder: ", path)
        os.mkdir(path, mode=self.folderPermission)
    
    def closeFile(self):
        log.msg("closing file")
        os.close(self.fd)

    def statFile(self, name):
        #C0644 6 f4.txt\n
        name = name.decode('utf8')
        tokens = shlex.split(name)
        return int(tokens[0][2:len(tokens[0])], 8), int(tokens[1]), tokens[2][0:len(tokens[2])]