from typing import Tuple
import os
import json
import docker
import requests

from twisted.logger import globalLogPublisher
from twisted.logger import textFileLogObserver
from twisted.python import log

from cowrie.core.config import CowrieConfig
from docker.models.containers import Container
from container_pool import dockerClient

class DockerExistingContainer():
    """
    This class serves as a wrapper or interface to the Docker engine.
    It connects to the Docker engine using a singleton `dockerClient`
    from the container_pool module.

    Attributes:
        imageName: Name of Docker image used to create a new container of an SSH server. 
            Although, this class can be used to run a contaienr on the fly, 
            it is not currently used.
        SSHPort : SSH server port on the new container
        socketPath : UNIX socket to connect to Docker engine
        network : Internal Docker network
        container : The current container of the backend SSH server
        debug: when it is set to ``True``, it uses a different Docker image
            to start the contaienr.
    """

    imageName : str = CowrieConfig.get('docker', 'ssh_image')
    SSHPort : int = CowrieConfig.getint('docker', 'ssh_port')
    socketPath : str = CowrieConfig.get('docker', 'unix_socket_path')
    network : str = CowrieConfig.get('docker', 'network')

    container : Container = None

    debug : bool = CowrieConfig.getboolean('docker', 'debug')

    def connect(self, id: str)->bool:
        """
        Connect to a container identified by its id.

        Args:
            id: id of the container

        Returns:
            ``True`` if the connection is successful, otherwise ``False``.
        """
        try:
            self.container = dockerClient.containers.get(id)
            return True
        except docker.errors.NotFound as error:
            log.err(f"{repr(error)}")
        except docker.errors.APIError as error:
            log.err(f"{repr(error)}")

        return False

    def getNetworkInfo(self):
        network = self.network
        sshPort = self.SSHPort
        ip = ''

        if self.debug:
            ip = self.debug_ssh_host
            port = self.debug_ssh_port
        else:
            ip = self.container.attrs['NetworkSettings']['Networks'][network]['IPAddress']
            port = sshPort

        return ip, port

    def id(self)->str:
        """
        Returns an id of a newly created container.
        """
        return self.container.id

    def commit(self):
        dockerClient.commit(container=self.container_name, tag=self.tag)

    def start(self):
        try:
            if self.debug:
                self.container = dockerClient.containers.run(self.imageName,
                                                        detach=True,
                                                        remove=True,
                                                        ports={'22/tcp':self.debug_ssh_port})
            else:
                self.container = dockerClient.containers.run(self.imageName,
                                                        detach=True,
                                                        remove=True,
                                                        auto_remove=True,
                                                        network=self.network
                                                        )
            self.container.reload()
        except docker.errors.APIError as apierror:
            log.msg(apierror)
            self.defer.errback(apierror)
        except requests.exceptions.ReadTimeout as readTimeoutError:
            log.msg(readTimeoutError)
            self.defer.errback(readTimeoutError)
        except:
            log.msg("maybe client dies and container failed to start")
            self.defer.errback(Exception("container failed to start"))

    def createUser(self, username: bytes, password: bytes)->Tuple[bool, int, int]:
        """
        Create a new user using the attacker's username and password.
        This is called when the username does not exist on the target system.
        
        Args:
            username: Username used by the attacker to connect to the proxy.
            password: Password used by the attacker to connect to the proxy.
        
        Returns:
            A tuple containing a boolean value indicating the status of user creation.
            If the returned value is ``True``, it indicates the user creation was
            successful and the next two values correspond respectively to the ``uid``
            and ``gid`` of the new user.
        """

        if username != b'root':
            # only add user if user is not root
            log.msg("create a new user: ", username, password)
            cmd = 'adduser --force-badname ' + username.decode('utf8')
            exit_code, output = self.container.exec_run(cmd)
            if exit_code > 0:
                log.err(output)

        # user exists/is created, then change the password
        changePasswordCmd = 'sh -c "echo \'' + username.decode('utf8') + ':' + password.decode('utf8') + '\'|chpasswd"'
        exit_code, output = self.container.exec_run(changePasswordCmd)

        if exit_code > 0:
            log.err(output)
            return False, None, None

        # get uid, gid of this user
        idCmd = 'id ' + username.decode('utf8')
        exit_code, output = self.container.exec_run(idCmd)
        # the result should look something like this
        # uid=1001(standard) gid=1001(standard) groups=1001(standard)
        output = output.decode('utf8')
        tokens = output.split()
        for token in tokens:
            toks = token.split('=')
            if toks[0] == 'uid':
                tmp = toks[1].split('(')
                uid = tmp[0]
            elif toks[0] == 'gid':
                tmp = toks[1].split('(')
                gid = tmp[0]

        return True, uid, gid

    def usermod(self, username: bytes, password: bytes)->bool:
        """
        Modify an existing user by changing its password to the that
        supplied by the attacker.
        
        Args:
            username: Username used by the attacker to connect to the proxy.
            password: Password used by the attacker to connect to the proxy.

        Returns:
            ``True`` indicates if the password modification was successful,
            otherwise ``False``.
        """

        if username is None or password is None:
            log.err('username or password is None')
            return False

        if username.strip() == b'' or password.strip() == b'':
            log.err('username or password contains only blank spaces')
            return False

        try:
            new_username = username.decode('utf8')
            new_password = json.dumps(password.decode('utf8'))
        except UnicodeError:
            return False

        if new_username in ["root", "nproc"]:
            # For root user, we only update its password
            cmd = f'sh -c \"echo \'{new_username}:{new_password}\'|chpasswd\"'
            exit_code, output = self.container.exec_run(cmd)
            if exit_code > 0:
                log.err(output)
                return False
        else:
            # 1) change the group name of existing user
            cmd = "groupmod --new-name " +  new_username + " " + self.existingUsername
            exit_code, output = self.container.exec_run(cmd)

            if exit_code > 0:
                log.err(output)
                return False

            # 2) change username, home directory
            cmd = "usermod -l " + new_username + " -d /home/"+ username.decode('utf8') + " " + self.existingUsername
            exit_code, output = self.container.exec_run(cmd)

            if exit_code > 0:
                log.err(output)
                return False

            # 3) modify the name of home directory
            cmd = "mv /home/" + self.existingUsername + " /home/" + new_username
            exit_code, output = self.container.exec_run(cmd)

            if exit_code > 0:
                log.err(output)
                return False

            # 4) change password
            cmd = f'sh -c \"echo \'{new_username}:{new_password}\'|chpasswd\"'
            exit_code, output = self.container.exec_run(cmd)

            if exit_code > 0:
                log.err(output)
                return False

        return True

    def fileExists(self, fileName, fileNames):
        found = False
        for name in fileNames:
            if fileName.startswith(name):
                found = True

        if not found:
            fileNames.append(fileName)

        return found

    def save(self, transportId):
        containerId = self.container.short_id
        fileDirPath = self.filePath
        sessionDirPath = self.sessionPath

        fileNames = []
        content = {}

        dirPath = '%s/%s' % \
                            (fileDirPath, transportId)

        os.mkdir(dirPath)

        sessionFilePath = '%s/%s.json' % \
                            (sessionDirPath, transportId)


        log.msg("Saving container information to path %s" % (sessionFilePath))

        # getting list of file system changes
        fileNameChanges = self.container.diff()

        content['session'] = transportId
        content['files'] = fileNameChanges
        content['top'] = self.container.top()

        with open(sessionFilePath, 'w') as output:
            json.dump(content, output, ensure_ascii=False, separators=(',', ':'))

        for fileName in fileNameChanges:
            # only top folder will be archived, e.g. /tmp but not /tmp/xxx
            if not self.fileExists(fileName['Path'], fileNames):
                path = '%s/%s.tar' % (dirPath, os.path.basename(fileName['Path']))
                archiveFile = open(path, 'wb')
                bits, stat = self.container.get_archive(fileName['Path'])
                for chunk in bits:
                    archiveFile.write(chunk)
                archiveFile.close()

        self.stop()

    def stop(self):
        if self.container:
            self.container.stop()
            self.container = None

    def logs(self):
        if self.container:
            return self.container.logs()
        else:
            return ""

    def getpubkeys(self, username: str) -> bytes:
        """Read public keys from authorized_keys using a command "cat"

        Args:
            username: username whose home directory file will be read from

        Returns:
            public keys if the file 'authorized_keys' exists, otherwise None
        """

        if username == "root":
            cmd = f"cat /{username}/.ssh/authorized_keys"
        else:
            cmd = f"cat /home/{username}/.ssh/authorized_keys"

        exit_code, output = self.container.exec_run(cmd)
        # remove an excess newline in the keys
        output = output.strip(b'\n')
        # break it down to get keys
        output = output.split(b'\n')
        if exit_code == 0:
            return output
        else:
            return None

class DockerContainer():
    filePath : str = CowrieConfig.get('docker', 'file_path')
    sessionPath : str = CowrieConfig.get('docker', 'session_path')
    debug : bool = CowrieConfig.getboolean('docker', 'debug', fallback=False)

    debug_ssh_host : str = CowrieConfig.get('docker', 'debug_ssh_host', fallback='localhost')
    debug_ssh_port : str = CowrieConfig.getint('docker', 'debug_ssh_port', fallback=2226)

    container : Container = None

    existingUsername : str = CowrieConfig.get('proxy', 'backend_user')
    existingPassword : str = CowrieConfig.get('proxy', 'backend_pass')

    imageName = CowrieConfig.get('docker', 'ssh_image')
    SSHPort = CowrieConfig.getint('docker', 'ssh_port')
    network = CowrieConfig.get('docker', 'network')

    def connect(self):
        # self.client = docker.DockerClient(base_url=self.socketPath)
        # self.client = dockerClient
        pass

    def getNetworkInfo(self):
        network = self.network
        sshPort = self.SSHPort
        ip = ''

        if self.debug:
            ip = self.debug_ssh_host
            port = self.debug_ssh_port
        else:
            ip = self.container.attrs['NetworkSettings']['Networks'][network]['IPAddress']
            port = sshPort

        return ip, port

    def getContainer(self, name: str):
        self.container = dockerClient.containers.get(name)
        return self.container

    def createUser(self, username: bytes, password: bytes):
        """create a new user using attacker's username and password."""

        if username != b'root':
            # only add user if user is not root
            log.msg("create a new user: ", username, password)
            cmd : str = 'adduser ' + username.decode('utf8')
            exit_code, output = self.container.exec_run(cmd)
            if exit_code > 0:
                log.err(output)
                return False

        # add/change user password
        changePasswordCmd = 'sh -c "echo \'' + username.decode('utf8') + ':' + password.decode('utf8') + '\'|chpasswd"'
        exit_code, output = self.container.exec_run(changePasswordCmd)

        if exit_code > 0:
            log.err(output)
            return False

        return True

    def usermod(self, username, password):
        """Modify existing user"""

        if username is None or password is None:
            log.err('username or password is None')
            return False

        if username.strip() == b'' or password.strip() == b'':
            log.err('username or password contains only blank spaces')
            return False

        try:
            new_username = username.decode('utf8')
            new_password = json.dumps(password.decode('utf8'))
        except UnicodeError:
            return False

        if new_username in ["root", "nproc"]:
            # For root user, we only update its password
            cmd = f'sh -c \"echo \'{new_username}:{new_password}\'|chpasswd\"'
            exit_code, output = self.container.exec_run(cmd)
            if exit_code > 0:
                log.err(output)
                return False
        else:
            # 1) change the group name of existing user
            cmd = "groupmod --new-name " +  new_username + " " + self.existingUsername
            exit_code, output = self.container.exec_run(cmd)

            if exit_code > 0:
                log.err(output)
                return False

            # 2) change username, home directory
            cmd = "usermod -l " + new_username + " -d /home/"+ username.decode('utf8') + " " + self.existingUsername
            exit_code, output = self.container.exec_run(cmd)

            if exit_code > 0:
                log.err(output)
                return False

            # 3) modify the name of home directory
            cmd = "mv /home/" + self.existingUsername + " /home/" + new_username
            exit_code, output = self.container.exec_run(cmd)

            if exit_code > 0:
                log.err(output)
                return False

            # 4) change password
            cmd = f'sh -c \"echo \'{new_username}:{new_password}\'|chpasswd\"'
            exit_code, output = self.container.exec_run(cmd)

            if exit_code > 0:
                log.err(output)
                return False

        return True

    def fileExists(self, fileName, fileNames):
        found = False
        for name in fileNames:
            if fileName.startswith(name):
                found = True

        if not found:
            fileNames.append(fileName)

        return found

    def save(self, transportId):
        containerId = self.container.short_id
        fileDirPath = self.filePath
        sessionDirPath = self.sessionPath

        fileNames = []
        content = {}

        dirPath = '%s/%s' % \
                            (fileDirPath, transportId)

        os.mkdir(dirPath)

        sessionFilePath = '%s/%s.json' % \
                            (sessionDirPath, transportId)


        log.msg("Saving container information to path %s" % (sessionFilePath))

        # getting list of file system changes
        fileNameChanges = self.container.diff()

        content['session'] = transportId
        content['files'] = fileNameChanges
        content['top'] = self.container.top()

        with open(sessionFilePath, 'w') as output:
            json.dump(content, output, ensure_ascii=False, separators=(',', ':'))

        for fileName in fileNameChanges:
            # only top folder will be archived, e.g. /tmp but not /tmp/xxx
            if not self.fileExists(fileName['Path'], fileNames):
                path = '%s/%s.tar' % (dirPath, os.path.basename(fileName['Path']))
                archiveFile = open(path, 'wb')
                bits, stat = self.container.get_archive(fileName['Path'])
                for chunk in bits:
                    archiveFile.write(chunk)
                archiveFile.close()

        self.stop()

    def stop(self):
        if self.container:
            self.container.stop()
            self.container = None

    def logs(self):
        if self.container:
            return self.container.logs()
        else:
            return ""