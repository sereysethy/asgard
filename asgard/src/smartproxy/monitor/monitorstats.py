# module import
from abc import ABC, abstractmethod
import redis
import json
import numpy as np

# from Cowrie
from cowrie.core.config import CowrieConfig
from smartproxy import log

class Monitor(ABC):
    """A base class to communicate with the monitor component.

    It serves as a base class serves whose methods should be implemented
    to get data from the monitor component.

    It has one attribute client that talks with the component.
    For instance, it can be a web client or a redis client, depending on
    how it acquires data from the monitor component.

    Attributes:
        debug: Running in a debug mode
        client: a client to communicate with the monitor component.
    """

    debug: bool = False
    client = None

class MonitorStats(Monitor):
    """A monitor class that gets the data from a redis server.

    It gets observational data from the monitor component via
    a redis server. It uses a Redis client to communicate with a redis server.

    Attributes:
        redisHost: Redis host server
        redisPort: Redis port server
        debug: Running in a debug mode
    """

    debug: bool = False
    redisHost: str
    redisPort: str

    def __init__(self):
        """
        Initialize the monitor class by creating a redis client.
        """
        self.debug = CowrieConfig.getboolean("monitor", "debug", fallback=False)
        self.redisHost = CowrieConfig.get("redis", "host")
        self.redisPort = CowrieConfig.get("redis", "port")

        try:
            self.client = redis.Redis(host=self.redisHost, port=self.redisPort)
        except redis.exceptions.ConnectionError as e:
            log.error('cant connecto to redis server {host} on port {port}',
                            host=self.redisHost, port=self.redisPort)
            log.error('error: {e}', e=e)

    def getCPUUsagePercentage(self)->float:
        """
        Returns the CPU usage as a percentage (0–100).

        Returns:
            The CPU usage as a percentage (0–100).
        """
        # get it from redis
        if self.debug:
            cpuUsagePer = np.random.random() * 100.0
        else:
            cpuUsagePer = self._get("cpu_usage_per")
            if cpuUsagePer is None:
                return 0.0

        # check if it is not null
        if cpuUsagePer:
            # convert it to float
            cpuUsagePer = float(cpuUsagePer)
            # it is possible that the usage is greater than 100%
            # because the usage is multiplied by the number of CPU cores.
            if cpuUsagePer > 100.0:
                cpuUsagePer = 100.0
        else:
            cpuUsagePer = 0.0

        return cpuUsagePer

    def getAvgCPUUsagePercentage(self):
        """
        Returns the average CPU usage as a percentage (0–100).

        Returns:
            The average CPU usage as a percentage (0–100).
        """
        # get it from redis
        if self.debug:
            avgCpuUsagePer = np.random.random() * 100.0
        else:
            avgCpuUsagePer = self._get("avg_cpu_usage_per")
            if avgCpuUsagePer is None:
                return 0.0

        # check if it is not null
        if avgCpuUsagePer:
            # convert it to float
            avgCpuUsagePer = float(avgCpuUsagePer)
            # it is possible that the usage is greater than 100%
            # because the usage is multiplied by the number of CPU cores.
            if avgCpuUsagePer > 100.0:
                avgCpuUsagePer = 100.0
        else:
            avgCpuUsagePer = 0.0

        return avgCpuUsagePer

    def getMemoryUsagePercentage(self)->float:
        """
        Returns the Memory usage as a percentage (0–100).

        Returns:
            The Memory usage as a percentage (0–100).
        """
        # get it from redis
        if self.debug:
            memUsagePer = np.random.random() * 100.0
        else:
            memUsagePer = self._get("mem_usage_per")
            if memUsagePer is None:
                return 0.0

        # check if it is not null
        if memUsagePer:
            # convert it to float
            memUsagePer = float(memUsagePer)
        else:
            memUsagePer = 0.0
        return memUsagePer

    def getAvgMemoryUsagePercentage(self):
        """
        Returns the average Memory usage as a percentage (0–100).

        Returns:
            The average Memory usage as a percentage (0–100).
        """
        # get it from redis
        if self.debug:
            avgMemUsagePer = np.random.random() * 100.0
        else:
            avgMemUsagePer = self._get("avg_mem_usage_per")
            if avgMemUsagePer is None:
                return 0.0

        # check if it is not null
        if avgMemUsagePer:
            # convert it to float
            avgMemUsagePer = float(avgMemUsagePer)
        else:
            avgMemUsagePer = 0.0
        return avgMemUsagePer

    def getNetworkInboundUsage(self):
        """
        Get inbound network trafic data

        Returns:
            Return the amount of inbound network trafic data
        """

        # get it from redis
        netInUsageBytes = self._get("net_in_byte")

        if netInUsageBytes is None:
            return 0.0

        # check if it is not empty
        if netInUsageBytes:
            # convert it to float
            netInUsageBytes = float(netInUsageBytes)
        else:
            netInUsageBytes = 0.0

        return netInUsageBytes

    def getNetworkOutboundUsage(self):
        """
        Get outbound network trafic data

        Returns:
            the amount of outbound network trafic data
        """

        # get it from redis
        netOutUsageBytes = self._get("net_out_byte")
        if netOutUsageBytes is None:
            return 0.0

        # check if it is not empty
        if netOutUsageBytes:
            # convert it to float
            netOutUsageBytes = float(netOutUsageBytes)
        else:
            netOutUsageBytes = 0.0
        return netOutUsageBytes

    def getBlkReadUsage(self):
        """
        Get block read data in byte from redis server.

        Returns:
            the amount of block data read from disk
        """

        # get it from redis
        blkReadByte = self._get("blk_read_byte")

        if blkReadByte is None:
            return 0.0

        # check if it is not empty
        if blkReadByte:
            # convert it to float
            blkReadByte = float(blkReadByte)
        else:
            blkReadByte = 0.0

        return blkReadByte

    def getBlkWriteUsage(self)->float:
        """
        Get block write data in byte from redis server.

        Returns:
            Return the amount of block data written to disk
        """

        # get it from redis
        blkWriteByte = self._get("blk_write_byte")
        if blkWriteByte is None:
            return 0.0

        # check if it is not empty
        if blkWriteByte:
            blkWriteByte = float(blkWriteByte)
        else:
            blkWriteByte = 0.0

        return blkWriteByte

    def _get(self, key: str):
        """
        Get the value from redis server.

        Args:
            key: The key to get the value from redis server.
        Returns:
            The value from redis server, or None if there is a connection error.
        """
        try:
            return self.client.get(key)
        except redis.exceptions.ConnectionError as e:
            log.error('error redis get: {e}', e=e)
            return None

class MonitorProcess(Monitor):
    """A monitor class that retrieves information about running processes.

    This class serves two purposes:

    1) It retrieves information about running processes from the monitor component via
    a Redis server. It uses a Redis client to subscribe to the channel specified by
    the key `channel_process_name`, and continuously receives messages from that channel.

    2) It writes to another channel, specified by the key `channel_process_kill`,
    in order to terminate a process.

    The names of these channels (`channel_process_name` and `channel_process_kill`)
    are defined in the configuration file under the `redis` section.

    Attributes:

        redisHost: Redis server host
        redisPort: Redis server port
        ready: Set to `True` when the monitor setup is complete

    """
    ready: bool = False

    def __init__(self):
        self.redisHost = CowrieConfig.get("redis", "host")
        self.redisPort = CowrieConfig.get("redis", "port")

        try:
            self.client = redis.Redis(
                                host=self.redisHost,
                                port=self.redisPort)
            self.setup()
        except redis.exceptions.ConnectionError as e:
            log.error('cant connecto to redis server {host} on port {port}',
                            host=self.redisHost, port=self.redisPort)
            log.error('error: {e}', e=e)

    def setup(self):
        """
        Run the setup by subscribing to the redis channel to get the information
        of the process object.

        Setup the list of the ignored commands.
        """
        self.channelProcessName = CowrieConfig.get("redis", "channel_process_name")
        self.channelProcessKill = CowrieConfig.get("redis", "channel_process_kill")

        log.info("subscribe to the Redis channel: {channel}",
                channel=self.channelProcessName)
        self.channel = self.client.pubsub()
        self.channel.subscribe(self.channelProcessName)

        ignoredCommands = CowrieConfig.get("monitor", "ignored_commands")
        self.ignoredCommands = ignoredCommands.split(',')

        log.info("ignore these commands: {cmds}", cmds=self.ignoredCommands)

        # now the set up is ready!
        self.ready = True

    def getProcess(self):
        """
        When this function is called, it will check with redis subscriber
        to see if there is any messages (running process) in the queue.

        It will also check the process name against the list of ignored commands.
        If it is in the list, it will not be reported.

        The message object contain the information which is derived from the
        following message returned from the command `docker top` that return the
        information of process from the host perspective.

        ..  code-block::

            UID     PID     PPID    C   STIME TTY TIME      CMD
            root    37209   37160   0   14:46 ?   00:00:00  /usr/sbin/sshd -D -e -o LogLevel=DEBUG3

        Returns:
            An object containing the information of a running process
        """

        # just in case, it got called before everything is setup
        if not self.ready:
            return None

        processList = []

        while True:
            message = self.channel.get_message()
            if message and message['type'] == 'message':
                try:
                    # get a dict of a process: uid, pid, ppid, c, stime, tty, time, cmd
                    process = json.loads(message['data'].decode('utf8'))

                    cmdName = process['cmd']
                    # command can contain spaces, so here we simply split them and
                    # take the first one, assume that it is the command name.

                    # TODO: the check should be more elaborated, we can for example
                    # use the PID and check the on the host "/proc/${PID}/exe" to
                    # the name and the path to the executable.
                    cmdNameList = cmdName.split()
                    cmdName = cmdNameList[0]
                    if cmdName not in self.ignoredCommands:
                        processList.append(process)
                except json.decoder.JSONDecodeError as e:
                    log.error("{e}", e=e)
                    break
            else:
                break

        return processList

    def killProcess(self, pid: int):
        """
        This function will publish the `pid` that needs to be killed to the
        Redis pub/sub channel.

        Depending on how the termination of a process is implemented on the monitor component,
        there should be a program that is subscribed to this channel and will
        kill that process.
        For instance, a program that runs on the host that runs the target system and is subscribed
        to this channel will receive the `pid` and will kill that process on the host using
        the command ``kill -9 ${pid}``. This program should be running with root privileges
        to be able to kill any process on the host.

        Args:
            pid: Host process id

        Returns:
            A status number ``0`` indicating if the publish is ok,
                otherwise ``1`` indicating that there is an error.
        """

        try:
            return self.client.publish(self.channelProcessKill, pid)
        except:
            return 1
