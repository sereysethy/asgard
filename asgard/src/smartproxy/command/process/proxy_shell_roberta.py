"""
version: 3

"""

from twisted.internet import task
from twisted.internet import defer

# Cowrie
from cowrie.core.config import CowrieConfig

# Smart proxy
from smartproxy import log, processlog
from smartproxy.command.shell_roberta import ShellRoberta
import smartproxy.utils.utils as utils
from smartproxy.monitor.monitorstats import MonitorProcess

class ProxyShellRoberta(ShellRoberta):
    """
    This shell inherits the Roberta shell.

    State observation
    -----------------
        In use case #3, the state observation returned from the environment consists
        of:
        - risk level associated to the command
        - command embedding representing the command
        - state of the command execution: start (C) or running (R)
        - normalised cpu percentage usage
        - normalised memory percentage usage

    Actions
    -------
        - allow:
        - block:
        - substitute:
        - terminate: only applied for a running process
        - nop: only applied for a running process
    """

    def __init__(self, username: str = None, simulated: bool = False, exploration: bool = True)->None:
        super().__init__(username, simulated, exploration)

        self.monitorProcess = MonitorProcess()

        self.THREAD_LOOPING_TIME = CowrieConfig.getint('proxy_shell',
                                        'running_thread_looping_time',
                                        fallback=5)

        self.running = False

    def start(self)->defer.Deferred:
        """
        Start the scheduled call to get the running process and submit it to
        the agent to decide on which action to take.

        Params
        ------
            None

        Returns
        -------
            defer.Deferred: a defer that will be called back later to process
                the process informations.
        """

        log.info("starting the looping thread to check the running process \
for every {duration} seconds", duration=self.THREAD_LOOPING_TIME)
        self.processesLoop = task.LoopingCall(self.getContainerProcesses)
        d = self.processesLoop.start(
                interval=self.THREAD_LOOPING_TIME,
                now=False)
        d.addCallback(self._cbLoopContainerProcessesDone)
        d.addErrback(self._cbLoopContainerProcessesFailed)

        self.running = True

        return d

    def _cbLoopContainerProcessesDone(self, result)->None:
        """
        A callback function is called when the getContainerProcess is finished.
        """
        if not self.running:
            log.info('_cbLoopContainerProcessesDone is done')

    def _cbLoopContainerProcessesFailed(self, failure)->None:
        """
        An errback function is called when the getContainerProcess has an error.
        """

        log.info('_cbLoopContainerProcessesFailed failed: {failure}', failure=failure)

    def stop(self)->None:
        """
        Stop the scheduled call and release all resources
        """

        if self.processesLoop.running:
            self.running = False
            self.processesLoop.stop()

        self.monitorProcess = None
        self.agent = None
        self.env = None

    def exec(self, parsedcmd):
        """
        @overide
        """

        log.info('monitor: start executing command: {name}', name=parsedcmd["cmd"])

        # create an observation
        rawCmd = parsedcmd['cmd_str']
        basename = utils.get_basename(parsedcmd['cmd'])
        parsedcmd['basename']  = basename
        execcmd = parsedcmd['cmd']

        cmdStateExec = parsedcmd['state']

        # create an observation based on obtained basename
        obs, cmdIndex = self._makeObs(rawCmd, basename, execcmd, cmdStateExec)
        # query action from current policy
        self.action = self._getAction(obs, parsedcmd)

        env = self._takeAction(parsedcmd, obs, cmdIndex, self.action)

        if self.action == self.env.ACTION_TERMINATE:
            self._execActionTerminate(parsedcmd)
        elif self.action == self.env.ACTION_NOP:
            self._execActionNop()

    def _execActionTerminate(self, parsedcmd):
        """
        Terminate the running command.

        We will execute a command "kill" that will terminate the running program.

        docker exec -it redis sh -c 'kill 1'
        """
        # get the pid
        pid = parsedcmd['pid']
        self.monitorProcess.killProcess(pid)
        return

    def _execActionNop(self):
        """
        Do nothing on the running command
        """

        return

    def getContainerProcesses(self)->None:
        """
        This function is called by a scheduled task to get the informations on
        the running processes.

        Returns
        -------
            None
        """

        cmd = {
            'type': 'command',
            'redirect': False,
            'output': 'stdout',
            'cmd_str': '',
            'cmd': '',
            'arg': [],
            'pipe': False,
            'sub': False,
            'input': None,
            'last': False,
            'redirects': [],
            'append': False,
            'params': []
        }

        # temporarily stopping the looping call
        self.processesLoop.stop()

        # get the process list
        processList = self.monitorProcess.getProcess()

        # The monitor returns a process
        for process in processList:
            # TODO: maybe we will use it to construct the
            # state observation.
            cmdName = process['cmd']
            cmdNameList = cmdName.split()
            cmd['pid'] = process['pid']
            cmd['cmd'] = cmdNameList[0]
            cmd['cmd_str'] = cmdName
            cmd['state'] = process['status']
            uid = process['uid']

            if uid == 'root':
                uid = '0'

            self.exec(cmd)

        # restart the looping call
        self.processesLoop = task.LoopingCall(self.getContainerProcesses)
        d = self.processesLoop.start(
                interval=self.THREAD_LOOPING_TIME,
                now=False)
        d.addCallback(self._cbLoopContainerProcessesDone)
        d.addErrback(self._cbLoopContainerProcessesFailed)
