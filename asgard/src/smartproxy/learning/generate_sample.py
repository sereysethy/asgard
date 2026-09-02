import os
import json
from datetime import datetime
import argparse

from twisted.internet import reactor, defer
from twisted.python import log

import numpy as np
import gym
import itertools

import sklearn

from cowrie.core.config import CowrieConfig

from smartproxy.ssh.factory import SSHClientFactory
from smartproxy.command.shell_linear import ShellLinear as Shell
from container_pool.container import DockerContainer
from smartproxy.learning.attacker import AttackerEmulator
from smartproxy.learning.env import AttackerEnv
from smartproxy.learning.model import Q_LinFA
from smartproxy import log_training

sample_path = os.path.join("data", "sample")
now = datetime.today().strftime("%Y-%m-%d_%H%M%S")
dir_path = os.path.join(sample_path, now)
os.mkdir(dir_path, 0o755)

username = CowrieConfig().get('proxy', 'backend_user')
password = CowrieConfig().get('proxy', 'backend_pass')
server = CowrieConfig().get('proxy', 'backend_ssh_host')
port = CowrieConfig().getint('proxy', 'backend_ssh_port')

parser = argparse.ArgumentParser()
parser.add_argument("--episode", type=int, required=False)

# create attacker enumator that will make connection and input command
attacker = AttackerEmulator()
attacker.loadTestAttackEpisodes()
#attacker.loadAttackEpisodes()

container = None
number_features = 5
number_actions = 5

agent = Q_LinFA(number_features, number_actions)

shell = None
samples = []
i_episode = 0
checkpoint = 1000

def _cbContainerStartedSuccess(c):
    global container

    log.msg("Container started successfully")
    ip, port = container.getNetworkInfo()
    print(ip, port, container.id())
    connect_to_backend(ip, port, container)

def _cbContainerStartedError(reason):
    global container

    log.msg("Container failed to start, disconnect everything")
    log.msg('reason: ', reason)
    if container:
        container.stop()
        container = None
    reactor.stop()

def connect_to_backend(ip, port, container):
    global shell

    deferred = defer.Deferred()
    deferred.addCallback(cbnext)
    deferred.addErrback(errback)
    shell = Shell(deferred=deferred,
               container_name=container.id(),
               simulated=False)
    shell.setAgent(agent)
    shell.setAttacker(attacker)
    sshClientfactory = SSHClientFactory(shell=shell, username=username, password=password, container=container)
    reactor.connectTCP(ip, port, sshClientfactory)

def save_samples(episode):
    global samples
    global sample_path
    
    pathname = os.path.join(dir_path, str(episode) + ".json")

    log_training.info(f"dumping sample to file {pathname}")
    
    with open(pathname, 'w') as outfile:
        for s in samples:
            outfile.write(json.dumps(s) + '\n')

def generate():
    global samples
    global i_episode
    global container

    # start a new episode of attack
    done, i_episode, episode = attacker.reset()
    if not done:
        log.msg(f"Episode #{i_episode}, filename: {episode['filename']}, session: {episode['session']}")
        log_training.info(f"Episode #{i_episode}, filename: {episode['filename']}, session: {episode['session']}")
        deferred = defer.Deferred()
        deferred.addCallback(_cbContainerStartedSuccess)
        deferred.addErrback(_cbContainerStartedError)
        container = DockerContainer(deferred)

        container.start()
    else:
        reactor.stop()

def errback(failure):
    global i_episode
    global container
    
    log.msg(failure)
    
    if container:
        container.stop()
        container = None
    reactor.stop()

def cbnext(result):
    global container
    global shell
    global samples
    global i_episode

    if container:
        container.stop()
        container = None

    sample = shell.getSample()
    if sample:
        samples.append(sample)

    if i_episode % checkpoint == 0:
        save_samples(i_episode)
        samples = []

    shell = None
    generate()


if __name__ == '__main__':
    args = parser.parse_args()

    if args.episode:
        attacker.setEpisodeIndex(args.episode)

    reactor.callWhenRunning(generate)
    reactor.run()

    save_samples("episode_after_error")