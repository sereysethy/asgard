import os
import json

from twisted.internet import reactor, defer
from twisted.python.logfile import DailyLogFile
from twisted.logger import Logger
from twisted.logger import textFileLogObserver
from twisted.logger import globalLogPublisher
from twisted.python import log

from cowrie.core.config import CowrieConfig

from smartproxy.ssh.factory import SSHClientFactory
from smartproxy.command.shell import Shell

from ray.rllib.env.policy_client import PolicyClient

from container_pool.container import DockerContainer

logfile = DailyLogFile("octopus.log", "var/log/cowrie")
globalLogPublisher.addObserver(textFileLogObserver(logfile))

username = CowrieConfig().get('proxy', 'backend_user')
password = CowrieConfig().get('proxy', 'backend_pass')
server = CowrieConfig().get('proxy', 'backend_ssh_host')
port = CowrieConfig().getint('proxy', 'backend_ssh_port')

policyServerUrl = CowrieConfig().get('policy_server', 'url')

honeypot_sessions = []

def load():
    global honeypot_sessions
    filename = "ubuntu-shell.txt"
    path_data = "data"
    # for line in open(os.path.join(path_data, filename)):
    #     self.STATE_COMMAND.append(line.rstrip())

    honeypot_sessions += [json.loads(line)['cowrie_command_input'] for line in open(os.path.join(path_data, "mongo", "out", "episodes_infosec_buffy.json"), 'r')]
    honeypot_sessions += [json.loads(line)['cowrie_command_input'] for line in open(os.path.join(path_data, "mongo", "out", "episodes_infosec_daisy.json"), 'r')]
    honeypot_sessions += [json.loads(line)['cowrie_command_input'] for line in open(os.path.join(path_data, "mongo", "out", "episodes_infosec_gabble.json"), 'r')]
    honeypot_sessions += [json.loads(line)['cowrie_command_input'] for line in open(os.path.join(path_data, "mongo", "out", "episodes_infosec_rosy.json"), 'r')]

policyClient = PolicyClient(policyServerUrl)
# load()
honeypot_sessions = [["ls $(which ls)"]]
# honeypot_sessions = [["ls $(which ls)", 'exit'], ["pwd\ndate","exit"], ['pwd', 'df']]
# honeypot_sessions = [['monvar=\"xxxx\"']]
# honeypot_sessions = [['unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG WATCH ; history -n ; export HISTFILE=/dev/null ; export HISTSIZE=0; export HISTFILESIZE=0 ; rm -rf /var/log/wtmp ; rm -rf /var/log/lastlog ; rm -rf /var/log/secure ; rm -rf /var/log/xferlog ; rm -rf /var/log/messages ; rm -rf /var/run/utmp ; touch /var/run/utmp ; touch /var/log/messages ; touch /var/log/wtmp ; touch /var/log/messages ; touch /var/log/xferlog ; touch /var/log/secure ;  touch /var/log/lastlog ; rm -rf /var/log/maillog ; touch /var/log/maillog ; rm -rf /root/.bash_history ; touch /root/.bash_history ; history -r ', 'uname', 'free -m', 'ps -x', 'cat /proc/cpuinfo']]
# honeypot_sessions = [['ls','pwd', 'date', 'df', 'exit']]
# honeypot_sessions = [['ls','exit', 'date']]
# honeypot_sessions = [['uname -a & lscpu'], ['ls', './infinite', 'exit', 'date']]
# honeypot_sessions = [["ls -ialgG /","ls /etc","cd etc","cd /etc","ls","cd init.d","ls","less README","cat README","ls -l","bash","exit"]]
n = len(honeypot_sessions)
i = 0
sh = None
current_session = []
current_container = None

def _cbContainerStartedSuccess(container):
    global current_container

    log.msg("Container started successfully")
    ip, port = container.getNetworkInfo()
    print(ip, port, container.id())
    current_container = container
    connect_to_backend(ip, port, container)

def _cbContainerStartedError(reason):
    log.msg("Container failed to start, disconnect everything")
    log.msg('reason: ', reason)
    if current_container:
        current_container.stop()
        current_container = None
    reactor.stop()

def connect_to_backend(ip, port, container):
    global current_session
    global current_container
    global policyClient

    log.msg('current session: ', current_session)
    deferred = defer.Deferred()
    deferred.addCallback(next)
    sh = Shell(session=current_session,
               policyClient=policyClient,
               deferred=deferred,
               container_name=container.id(),
               simulated=False)
    sshClientfactory = SSHClientFactory(shell=sh, username=username, password=password, container=container)
    reactor.connectTCP(ip, port, sshClientfactory)
    return deferred

def train():
    global honeypot_sessions
    global i, n
    global current_session

    if i < n:
        current_session = honeypot_sessions[i]
        i += 1

        deferred = defer.Deferred()
        deferred.addCallback(_cbContainerStartedSuccess)
        deferred.addErrback(_cbContainerStartedError)
        c = DockerContainer(deferred)
        c.start()

def next(result):
    global sh, current_container
    global i, n
    sh = None

    if current_container:
        current_container.stop()
        current_container = None

    if i < n:
        train()
    else:
        reactor.stop()

reactor.callWhenRunning(train)
reactor.run()
