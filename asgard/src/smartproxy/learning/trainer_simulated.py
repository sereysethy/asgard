import os
import itertools
from os.path import isfile, join
import json
import argparse
from datetime import datetime

from twisted.internet import reactor, defer
from twisted.python import log

from cowrie.core.config import CowrieConfig

from smartproxy.command.shell_simulated import ShellSimulated as ShellSimulated
from smartproxy.learning.attacker import AttackerEmulator

parser = argparse.ArgumentParser()

parser.add_argument("--episode-file", type=str, help="file to load attacker command episodes", required=False)

i_episode = 0
current_episode = None
attacker = None

def train(filename):
    global i_episode
    global current_episode

    done = False
    
    with open(filename, "w") as out_file:
        while not done:
            # start a new episode of attack
            done, i, current_episode = attacker.reset()
            if not done:
                i_episode += 1
                log.msg(f"Training for episode #{i_episode}, filename: {current_episode['filename']}, session: {current_episode['session']}")
                shell = ShellSimulated(simulated=True)
                shell.setAttacker(attacker)
                shell.start()
                sample = shell.getSample()
                print(sample)
                current_episode["command_list"] = sample
                current_episode["number_command"] = len(sample)
                json_string = json.dumps(current_episode)
                out_file.write(json_string)
                out_file.write('\n')

if __name__ == "__main__":
    args = parser.parse_args()

    # create attacker emulator that will make connection and input command
    attacker = AttackerEmulator()
    attacker.loadAttackEpisodesByFilename(args.episode_file)

    filename = os.path.join(args.episode_file + "_added")
    train(filename)