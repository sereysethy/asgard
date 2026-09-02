import os
import json
import re

PATH_DATA = 'data'
VAR_DATA = "var/data"

def generate_attacker_commands():
    honeypot_sessions = []
    filename = "ubuntu-shell.txt"

    path = os.path.join(VAR_DATA, "mongo", "out")
    file_names = os.listdir(path)

    command_set = set()
    
    for file in file_names:
        with open(os.path.join(path, file)) as f:
            for line in f:
                session = json.loads(line)['cowrie_command_input']
                for cmd in session:
                    tmp = cmd.replace('|', '\n').replace('&&', '\n').replace(';', '\n').rstrip().splitlines()
                    for c in tmp:
                        # c = re.sub(r'^ ', '', c)
                        l = c.split()
                        if len(l) > 0:
                            if re.search(r"[./()=${}&\\<>0-9\"#':]", l[0]) is None:
                                command_set.add(l[0])


    file_output = open(os.path.join(PATH_DATA, 'attacker_commands.txt'), 'w')
    for c in command_set:
        file_output.write(c)
        file_output.write('\n')

    file_output.close()
    print('Number of commands: ', len(command_set))

    return command_set.copy()


def load_attacker_commands():
    path = os.path.join(PATH_DATA, 'commands', 'attacker_commands.txt')

    command_list = []
    with open(os.path.join(path)) as f:
        for line in f:
            command_list.append(line.rstrip())

    return command_list.copy()

def load_linux_commands(except_cmd):
    """Read file ubuntu_commands.txt containing linux cmd except exit."""

    path = os.path.join(PATH_DATA, 'commands', 'ubuntu_commands.txt')

    command_list = []
    with open(os.path.join(path)) as f:
        for line in f:
            cmd = line.rstrip()
            if cmd not in except_cmd:
                command_list.append(cmd)

    return command_list.copy()

def load_linux_root_commands(except_cmd):
    """Read file ubuntu_root_commands.txt containing linux cmd except exit."""

    path = os.path.join(PATH_DATA, 'commands', 'ubuntu_root_commands.txt')

    command_list = []
    with open(os.path.join(path)) as f:
        for line in f:
            cmd = line.rstrip()
            if cmd not in except_cmd:
                if cmd not in command_list:
                    command_list.append(cmd)
                else:
                    print(f"duplicate command: {cmd}")

    return command_list.copy()

def load_commands_all_distro():
    """
    This function is used to combine all commands from different files
    and produce a sorted commands to a single file "commands_all_dist.txt"
    """

    names = [
        "debian_buster_commands.txt",
        "debian_stretch_commands.txt",
        "centos7_commands.txt",
        "centos8_commands.txt",
        "ubuntu_root_commands.txt",
        "raspbian_buster_commands.txt",
        "debian_arm_buster_commands.txt",
        "commands_risk_model_v2.txt"
        ]
    command_list = []
    for name in names:
        path = os.path.join(PATH_DATA, 'commands', name)
        with open(path, "r") as fin:
            for line in fin:
                cmd = line.rstrip()
                if cmd not in command_list:
                    command_list.append(cmd)
                else:
                    print(f"duplicate command: {cmd}")

    command_list.sort()
    path = os.path.join(PATH_DATA, 'commands', "commands_all_dist.txt")
    with open(path, "w") as fout:
        for c in command_list:
            fout.write(c)
            fout.write("\n")

    return command_list

def load_all_commands(except_cmd):
    path = os.path.join(PATH_DATA, 'commands', "commands_all_dist.txt")
    command_list = []

    with open(path, "r") as fin:
        for line in fin:
            cmd = line.rstrip()
            if cmd not in except_cmd:
                if cmd not in command_list:
                    command_list.append(cmd)
                else:
                    print(f"duplicate command: {cmd}")
    return command_list

def load_user_commands(except_cmd):
    return load_linux_commands(except_cmd)

def load_root_commands():
    user_commands = load_user_commands()
    all_commands = load_linux_root_commands()
    root_commands = []
    for cmd in all_commands:
        if cmd not in user_commands:
            root_commands.append(cmd)

    return root_commands

def check_commands():
    existing_commands = load_linux_root_commands([])
    attacker_commands = load_attacker_commands()

    for acmd in attacker_commands:
        if acmd not in existing_commands:
            print(acmd)

if __name__ == "__main__":
    check_commands()

# generate_attacker_commands()
# command_list = load_attacker_commands()
# print(command_list)
# command_to_ix = {word: i for i, word in enumerate(command_list)}
# print(command_to_ix)