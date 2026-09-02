"""
The container pool module creates a Docker client using
`Docker SDK for Python <https://docker-py.readthedocs.io/en/stable/index.html>`_
to connect to Docker engine. The client `dockerClient` is created using a UNIX socket.
"""
import os
import pwd
import grp
from twisted.python import log

from docker.errors import DockerException
from docker import DockerClient

from cowrie.core.config import CowrieConfig
from docker.client import DockerClient

# singleton Docker client to be used by all modules in Asgard
dockerClient : DockerClient = None

socketPath : str = CowrieConfig.get('docker', 'unix_socket_path')
debug : bool = CowrieConfig.getboolean('docker', 'debug', fallback=False)

if debug:
    log.msg(f"Debug mode is enabled. Docker client will be created using socket path: {socketPath}")
    uid = os.getuid()
    gid = os.getgid()
    euid = os.geteuid()
    egid = os.getegid()
    groups = os.getgroups()

    try:
        user_name = pwd.getpwuid(uid).pw_name
    except KeyError:
        user_name = "(unknown)"

    try:
        group_name = grp.getgrgid(gid).gr_name
    except KeyError:
        group_name = "(unknown)"

    log.msg(f"UID:  {uid} ({user_name})")
    log.msg(f"GID:  {gid} ({group_name})")
    log.msg(f"EUID: {euid}")
    log.msg(f"EGID: {egid}")
    log.msg(f"Supplementary groups: {groups}")

try:
    dockerClient : DockerClient = DockerClient(base_url=socketPath)
except DockerException as e:
    # To bypass exceptions raised of "file does not exist" when generating sphinx-doc
    log.err(f"Failed to create Docker client using socket path: {socketPath}. Error: {e}")
