import re
import os
import matplotlib.pyplot as plt
import json

def loadJsonFromFile(filename):
    try:
        with open(filename, "r") as infile:
            o = json.load(infile)
            return o
    except json.JSONDecodeError as e:
        print(e)
    except OSError as e:
        print(e)

    return None

def preprocessCmd(lines):
    """
    Command can span multiple lines, so before command is parsed, command
    should be pre-processed to produce an array of lines.
    """
    cmds = []
    tokens = lines.split('\n')

    """ regex to check if there are two consecutive ;; at the end """
    reFindSemi = re.compile('.*; *;')

    for token in tokens:
        if token != '' and token[0] != '#':
            result = reFindSemi.match(token)
            """
            two ;; leave it as it is maybe attacker use it to fingerprint
            a honeypot.
            """
            if result:
                cmds.append(token)
            else:
                cmds.append(token.rstrip(' ;'))

    return cmds

def get_basename(path):
    """
    Get the name of command using path of os, ./path/to/command
    or ./command => basename = 'command'

    But if the path start with special characters like #, we return the line
    back.
    """

    if path.startswith('#'):
        return path
    elif path.find('#') > 0:
        return path

    return os.path.basename(path)
