import os
import json
import re
import numpy as np

from twisted.python import failure, log
from bashlex import parser, ast
from cowrie.smartproxy.models.parser import nodevisitor
from cowrie.smartproxy.utils import preprocessCmd
import datetime
import matplotlib.pyplot as plt

class RL():
    """
    States are used to represent the environment
        - command represents known command
        - custom represents unknown command
    """
    
    
    STATE_COMMAND = ['sshd']
    STATE_CUSTOM = ['custom']
    STATE_TERMINAL = ['exit']

    ACTIONS = ['allow', 'block']
    
    def __init__(self):
        self.Qs = {}
        self.numberActions = len(self.ACTIONS)
        self.alpha = 0.05
        self.gamma = 1
        self.epsilon = 0.1
        self.honeypot_sessions = []
        self.load()
        self.xs = {}
        self.ys = {}
        # self.preprocess()
    
    def load(self):
        filename = "ubuntu-shell.txt"
        path_data = "data"
        for line in open(os.path.join(path_data, filename)):
            self.STATE_COMMAND.append(line.rstrip())

        self.honeypot_sessions += [json.loads(line)['cowrie_command_input'] for line in open(os.path.join(path_data, "mongo", "out", "episodes_infosec_buffy.json"), 'r')]
        self.honeypot_sessions += [json.loads(line)['cowrie_command_input'] for line in open(os.path.join(path_data, "mongo", "out", "episodes_infosec_daisy.json"), 'r')]
        self.honeypot_sessions += [json.loads(line)['cowrie_command_input'] for line in open(os.path.join(path_data, "mongo", "out", "episodes_infosec_gabble.json"), 'r')]
        self.honeypot_sessions += [json.loads(line)['cowrie_command_input'] for line in open(os.path.join(path_data, "mongo", "out", "episodes_infosec_rosy.json"), 'r')]

    def preprocess(self):
        count = 0
        print("before: ", len(self.STATE_COMMAND))
        for s in self.honeypot_sessions:
            for c in s:
                if c not in self.STATE_COMMAND and len(c) > 1 and c[0] != '.' and c[1] != '/':
                    if c[0:4] != "echo":
                        count += 1
                        #print(c)
                        self.STATE_COMMAND.append(c)

        print("count: ", count)
        print("after: ", len(self.STATE_COMMAND))

    def buildTransitions(self, episodes = None):
        print("before: ", len(self.STATE_COMMAND))
        shell = Shell(self)
        transitions = {}
        total = 0
        
        for s in self.honeypot_sessions:
            lengthSession = len(s)
            # we artificially add sshd as start state exit as end state
            if lengthSession > 0:
                s = ['sshd'] + s + ['exit']
            lengthSession = len(s)
            for i in range(lengthSession):
                cmd = s[i]

                if cmd == "":
                    continue

                oldCmdList = shell.cmdList
                shell.cmdList = []

                if cmd.find('\n') >= 0:
                    arrCmds = preprocessCmd(cmd)
                    for c in arrCmds:
                        shell.cmdpending = self.parsing(c)
                        shell.start()
                else:
                    shell.cmdpending = self.parsing(cmd)
                    shell.start()

                try:
                    if i == 0:
                        lastCmd = None
                    else:
                        lastCmd = oldCmdList[len(oldCmdList) - 1] # last command of this list
                        lastCmd = self.state(lastCmd, [], s, [])
                except:
                    print(s)
                    print(cmd)
                    print(oldCmdList)
                    continue
                
                lengthSubSession = len(shell.cmdList)
                for j in range(lengthSubSession):
                    subCurCmd = self.state(shell.cmdList[j], [], [], [])
                    if lastCmd is None:
                        if subCurCmd not in transitions:
                            transitions[subCurCmd] = {}
                    else:
                        total += 1
                        subPreCmd = lastCmd

                        if subPreCmd not in transitions:
                            transitions[subPreCmd] = {}
                    
                        if subCurCmd not in transitions[subPreCmd]:
                            transitions[subPreCmd][subCurCmd] = 1
                        else:
                            transitions[subPreCmd][subCurCmd] += 1
                        lastCmd = subCurCmd
                        
        print(transitions)
        print(total)

    def draw(self):
        fig = plt.figure(figsize=(20,30))
        i = 1
        max = 40
        for key, value in self.xs.items():
            if i > max:
                break
            ax = fig.add_subplot(8, 5, i)
            ax.plot(self.xs[key]['allow'], self.ys[key]['allow'], label='allow', linestyle='-')
            ax.plot(self.xs[key]['block'], self.ys[key]['block'], label='block', linestyle=':')
            # plt.xlabel('Steps')
            # plt.ylabel('Average reward')
            # plt.legend()
            plt.title(key)
            i += 1
        plt.savefig("result/learn" + datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S') + ".pdf")

        plt.clf()
        plt.close(fig)
        plt.plot(self.xs['wget']['allow'], self.ys['wget']['allow'], label='allow')
        plt.plot(self.xs['wget']['block'], self.ys['wget']['block'], label='block')
        plt.xlabel('Steps')
        plt.ylabel('Average reward')
        plt.legend()
        plt.title('wget')
        plt.savefig("result/wget" + datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S') + ".png")

        plt.clf()
        plt.plot(self.xs['curl']['allow'], self.ys['curl']['allow'], label='allow')
        plt.plot(self.xs['curl']['block'], self.ys['curl']['block'], label='block')
        plt.xlabel('Steps')
        plt.ylabel('Average reward')
        plt.legend()
        plt.title('curl')
        plt.savefig("result/curl" + datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S') + ".png")

            # plt.plot(self.xs[key]['allow'], self.ys[key]['allow'], label='allow')
            # plt.plot(self.xs[key]['block'], self.ys[key]['block'], label='block')
            # plt.xlabel('Steps')
            # plt.ylabel('Average reward')
            # plt.title(key)
            # plt.savefig("result/" + key + ".png")
            # plt.clf()
            

        # plt.plot(self.xs['custom']['allow'], self.ys['custom']['allow'], label='custom_allow')
        # plt.plot(self.xs['custom']['block'], self.ys['custom']['block'], label='custom_block')

        # plt.plot(xs[1], ys[1], label='epsilon = 0.01')
        # plt.plot(xs[2], ys[2], label='epsilon = 0.1')
        
    def reward(self, state, action):
        if state in self.STATE_TERMINAL:
            return 0
        elif state in self.STATE_COMMAND:
            return 0
        elif state in self.STATE_CUSTOM:
            return 1
            # if action == 'allow':
            #     return 1
            # else:
            #     return 0
        else:
            return 0

    def action(self, state, steps):
        """
        This function will choose action based on a current state.
        It will balance between exploitation and exploration based on a 
        probability epsilon.
        """

        if steps % 1000 == 0:
            self.epsilon = self.epsilon - 0.0015

        epsilon = self.epsilon
        # init
        if state not in self.Qs:
            self.Qs[state] = {}

            self.xs[state] = {}
            self.ys[state] = {}

            self.xs[state]['allow'] = []
            self.xs[state]['block'] = []

            self.ys[state]['allow'] = []
            self.ys[state]['block'] = []

        s = np.random.random(1)
    
        # exploration
        if s[0] <= epsilon:
            i = np.random.randint(0, self.numberActions)
            maxA = self.ACTIONS[i]

            # if the randomly chosen action has not been select before
            # we initialise its Qs value.
            if maxA not in self.Qs[state]:
                if state in self.STATE_TERMINAL:
                    # if state is a terminal state (an absorbing state)
                    # its value is 0.
                    self.Qs[state][maxA] = 0.0
                else:
                    # otherwise, we randomly initialise a value
                    self.Qs[state][maxA] = np.random.random(1)[0]

        # exploitation by greedy
        else:
            # check number of actions available
            if len(self.Qs[state]) > 0:
                maxQ = None
                maxA = None
                for action in self.Qs[state]:
                    if maxQ is None:
                        maxQ = self.Qs[state][action]
                        maxA = action
                    elif maxQ < self.Qs[state][action]:
                        maxQ = self.Qs[state][action]
                        maxA = action
            else:
                # no action, so it is the same as exploration
                i = np.random.randint(0, self.numberActions)
                maxA = self.ACTIONS[i]
                if state in self.STATE_TERMINAL:
                    self.Qs[state][maxA] = 0.0
                else:
                    self.Qs[state][maxA] = np.random.random(1)[0]
        
        return maxA

    def maxAction(self, state, steps):
        if state not in self.Qs:
            return self.action(state, steps)

        if len(self.Qs[state]) > 0:
            maxQ = None
            maxA = None
            for action in self.Qs[state]:
                if maxQ is None:
                    maxQ = self.Qs[state][action]
                    maxA = action
                elif maxQ < self.Qs[state][action]:
                    maxQ = self.Qs[state][action]
                    maxA = action
        else:
            i = np.random.randint(0, self.numberActions)
            maxA = self.ACTIONS[i]
            if state in self.STATE_TERMINAL:
                self.Qs[state][maxA] = 0
            else:
                self.Qs[state][maxA] = np.random.random(1)[0]

        return maxA
        
    def Q(self, state, action):
        if state in self.STATE_TERMINAL:
            return 0
        elif action in self.Qs[state]:
            return self.Qs[state][action]
        else:
            self.Qs[state][action] = 0
            return self.Qs[state][action]

    def state(self, i, cmdList, cmds, parsedCmds):
        if i in self.STATE_COMMAND:
            return i
        elif i != "Enter": #len(i) > 1 and i[0] == '.' and i[1] == '/':
            return 'custom'
        else:
            print("UNKNOWN_STATE: ", i)
            print("cmd list: ", cmdList)
            print("cmds: ", cmds)
            print("parsed cmds: ", parsedCmds)
            return "UNKNOWN_STATE"

    def parsing(self, line):
        """ ignore line start with #, consider them all as comment """
        if line[0] == '#':
            return []

        try:
            trees = parser.parse(line)
            
            for tree in trees:
                visitor = nodevisitor(self, line)
                visitor.visit(tree)

            return visitor.cmdpending
        except:
            print("==> line:", line)
            return []

    def learn(self, episode, steps):
        shell = Shell(self)
        for t in range(len(episode)):
            cmd = episode[t]

            if cmd == "":
                continue

            if cmd.find('\n') >= 0:
                arrCmds = preprocessCmd(cmd)
                for c in arrCmds:
                    shell.cmdpending = self.parsing(c)
                    shell.start()        
            else:
                shell.cmdpending = self.parsing(cmd)
                shell.start()

        length = len(shell.cmdList)
        if length > 0:
            st = self.state(shell.cmdList[0], shell.cmdList, episode, shell.cmdpending)
            at = self.action(st, steps)
        else:
            print("length = 0, episode: ", episode)

        for i in range(length):
            # st = self.state(shell.cmdList[i], shell.cmdList, episode, shell.cmdpending)
            # at = self.action(st, steps)
            rt1 = self.reward(st, at)
            
            if at == 'block':
                self.Qs[st][at] = self.Qs[st][at] + self.alpha*(rt1 - self.Qs[st][at])
                self.ys[st][at].append(self.Qs[st][at])
                self.xs[st][at].append(len(self.xs[st][at]) + 1)
                break
            elif at == 'allow':
                if i + 1 < length:
                    # choose A' from S'
                    st1 = self.state(shell.cmdList[i + 1], shell.cmdList, episode, shell.cmdpending)
                    at1 = self.action(st1, steps)
                    # at1 = self.maxAction(st1, steps)
                    self.Qs[st][at] = self.Qs[st][at] + self.alpha*(rt1 + self.gamma * self.Q(st1, at1) - self.Qs[st][at])
                    at = at1
                    st = st1
                else:
                    self.Qs[st][at] = self.Qs[st][at] + self.alpha*(rt1 - self.Qs[st][at])
                    at1 = ''
                    st1 = ''
            
                self.ys[st][at].append(self.Qs[st][at])
                self.xs[st][at].append(len(self.xs[st][at]) + 1)

            # if at == 'block':
            #     break
            # else:
            #     at = at1
            #     st = st1

    def train(self):
        i = 0
        for s in self.honeypot_sessions:
            i += 1
            # print("honepot session: ", s)
            self.learn(s, i)
            if i % 1000 == 0:
                print("epoch: ", i)
    
        self.draw()
        # np.save(os.path.join(path, "mongo", "model"), self.Qs)

class Shell:

    def __init__(self, proto):
        self.cmdpending = []
        self.stack = []
        self.index = -1
        self.request = b'exec'
        self.cmd = None
        self.conn = None
        self.index = 0
        self.input = b''
        self.data = b''
        self.extdata = b''
        self.execcmd = b''
        self.var = {}
        self.exitStatus = True
        self.cwd = '/home/nproc'
        self.pipe = False
        self.line = ''
        self.state = None
        self.tbuf = []
        self.buffer = b''
        self.executingCompoundCmd = False

        self.cmdStack = []
        self.cmdStackIndex = -1

        self.context = []
        self.state = None
        self.response = None
        self.inputData = b''
        self.elseIfIndex = 0
        
        self.cmdList = []
    def _pushCmdStack(self, c):
        slef.cmdStackIndex += 1
        self.cmdStack.append(c)


    def _popCmdStack(self):
        slef.cmdStackIndex -= 1
        return self.cmdStack.pop()


    def _value(self, var):
        print("look up 1: ", var)
        key = var
        l = len(var)
        if key in self.var:
            return self.var[key]
        elif var[1] == '{':
            # strip '{' and '}'
            key = '$' + var[2:l-1]
            print("look up 2: ", key)
            if key in self.var:
                return self.var[key]
        elif var[1] != '{':
            key = '$' + '{' + var[1:l-1] + '}'
            print("look up 3: ", key)
            if key in self.var:
                return self.var[key]
        else:
            return None
    
    def _setValue(self, var, value):
        self.var[var] = value

    def writeTerminal(self, data):
        # print("writeTerminal: ", data)
        # self.protocol.terminal.write(data)
        pass

    def execDataReceived(self, data):
        """
        This function will be called after a command execution. We buffer all
        received data.
        """
        self.buffer += data

    def interactiveDataReceived(self, data):
        """
        This function will be called when data is received for all interactive
        data with backend, it controls display and how to manage lineBuffer based
        on the user input and backend response.
        """
        buf = []

        print('==> before response: ', self.response)

        if self.response == b'show-prompt':
            data = data.replace(b'\x08', b'')
            self.writeTerminal(data)
            self.response = None
            return
        
        self.writeTerminal(data)
        
        buf = self.findState(data)
        print('==> after response: ', self.response)
        
        if self.input == b'tab':
            if self.response is None \
                or self.response == b'erase-insert-at' \
                or self.response == b'bell':
                # this can be translated as a bash completion
                print('Bash completion1')
                for ch in buf:
                    self.characterReceived(ch, False)
                self.input = None
        
        if self.input is None:
            # maybe it should be specific, if it is a BACKSPACE
            if self.response == b'bell':
                self.response = None

        if self.response is None:
            if self.input == b'input':
                print('Manual input')
                self.characterReceived(self.inputData, False)
                self.input = None
            elif self.input == b'left':
                self.handle_LEFT()
            elif self.input == b'right':
                self.handle_RIGHT()
            elif self.input == b'backspace':
                # backspace when bufferIndex is at the end of buffer
                self.handle_BACKSPACE()

        if self.response == b'erase-left' and self.input == b'backspace':
            # backspace when bufferIndex is not at the end of buffer
            self.handle_BACKSPACE()

        if self.response == b'erase-right' and self.input == b'right':
            self.handle_RIGHT()

        if self.response == b'erase-insert-at':
            if self.input == b'input':
                for ch in buf:
                    self.characterReceived(ch, False)
                self.input = None

        print(self.protocol.lineBuffer)

    def characterReceived(self, ch, moreCharactersComing):
        p = self.protocol
        if p.mode == 'insert':
            p.lineBuffer.insert(p.lineBufferIndex, ch)
        else:
            p.lineBuffer[p.lineBufferIndex:p.lineBufferIndex + 1] = [ch]
        p.lineBufferIndex += 1
            
    def findState(self, data):
        buf = []
        i = 0
        for b in data:
            keyID = bytes([b])

            if self.response is None:
                if keyID == b'\a':
                    self.response = b'bell'
                elif keyID == b'\x1b':
                    # b'\x1b' or b'\a' is ESC
                    self.response = b'escaped'
                elif keyID == b'\r':
                    self.response = b'return'
                elif keyID in self.protocol._printableChars:
                    buf.append(keyID)
            elif self.response == b'return':
                if keyID == b'\n':
                    self.response = b'newline'
                    buf = []
                elif keyID == b':':
                    self.response = b'prompt_semi'
                else:
                    self.response = None
            elif self.response == b'newline':
                if keyID == b':':
                    self.response = b'prompt_semi'
            elif self.response == b'prompt_semi':
                if keyID == b'~':
                    self.response = b'prompt_tilde'
                else:
                    self.response = None
            elif self.response == b'prompt_tilde':
                if keyID == b'$':
                    self.response = b'prompt'
            elif self.response == b'prompt':
                # catch all
                buf = []
            elif self.response == b'escaped':
                if keyID == b'[':
                    self.response = b'bracket-escaped'
                    # self.escBuf = []
                elif keyID == b'O':
                    self.response = b'low-function-escaped'
                else:
                    self.response = None
                    # self._handleShortControlSequence(ch)
            elif self.response == b'bracket-escaped':
                if keyID == b'O':
                    self.response = b'low-function-escaped'
                elif keyID == b'1':
                    # \x1b[1
                    self.response = b'erase'
                elif keyID.isalpha() or keyID == b'~':
                    # self._handleControlSequence(b''.join(self.escBuf) + ch)
                    # del self.escBuf
                    self.response = None
                else:
                    # self.escBuf.append(ch)
                    pass
            elif self.response == b'low-function-escaped':
                # self._handleLowFunctionControlSequence(ch)
                self.response = None
            elif self.response == b'erase':
                if keyID == b'@':
                    # \x1b[1 then @?
                    self.response = b'erase-at'
                elif keyID == b'P':
                    # \x1b[1 then P?
                    self.response = b'erase-left'
                elif keyID == b'K':
                    # \x1b[ then K?
                    self.response = b'erase-to-line-end'
                else:
                    self.response = None
            elif self.response == b'erase-at':
                if keyID.isalnum():
                    # \x1b[1@ then alpha?
                    buf.append(keyID)
                    self.response = b'erase-insert-at'
                else:
                    self.response = None    
            else:
                # raise ValueError("Illegal state")
                print('Illegal state: ', keyID)

        return buf

    def handle_LEFT(self):
        p = self.protocol
        if p.lineBufferIndex > 0:
            p.lineBufferIndex -= 1
            # self.terminal.cursorBackward()
        print('handle_LEFT lineBufferIndex: ', p.lineBufferIndex)

    def handle_RIGHT(self):
        p = self.protocol
        if p.lineBufferIndex < len(p.lineBuffer):
            p.lineBufferIndex += 1
            # self.terminal.cursorForward()
        print('handle_RIGHT lineBufferIndex: ', p.lineBufferIndex)

    def handle_BACKSPACE(self):
        p = self.protocol
        print('handle_BACKSPACE lineBufferIndex: ', p.lineBufferIndex)
        print('handle_BACKSPACE lineBuffer: ', p.lineBuffer)
        if p.lineBufferIndex > 0:
            p.lineBufferIndex -= 1
            del p.lineBuffer[p.lineBufferIndex]
            # self.terminal.cursorBackward()
            # self.terminal.deleteCharacter()
        print('handle_BACKSPACE lineBuffer: ', p.lineBuffer)
        print('handle_BACKSPACE lineBufferIndex: ', p.lineBufferIndex)

    def handle_RETURN(self):
        p = self.protocol
        if self.response == b'newline':
            self.backendChannel.write(b'\r')
        else:
            self.lineReceived()

    def extReceived(self, dataType, data):
        """
        Extended data received from backend channel. It is stderr data.
        """

        """
        If we received stderr, it means the command exec failed
        """
        self.exitStatus = False
        
        """
        output intermediate result from backend
        """
        # TO FIX
        # self.extdata += data
        self.data += data
        # self.protocol.terminal.write(data)

    def write(self, ch):
        if self.input == b'return':
            self.handle_RETURN()
        else:
            self.backendChannel.write(ch)

    def processExitStatus(self):
        """
        This method will analyse the received buffer and get the exit status of
        the executed command and also the current working directory
        """
        data = self.buffer
        length = len(data)
        found = data.find(b'#####')
        if found >= 0:
            status = json.loads(s=data[found + 5:], encoding='bytes')
            self.exitStatus = status['exit']
            self.cwd = status['cwd']
        self.buffer = data[0:found]
        # print("exit status: ", self.exitStatus)
        # print("cwd status: ", self.cwd)


    def _saveContext(self):
        """
        Save a current context of a command execution
        """
        context = {}
        context['cmd'] = self.cmd
        context['cmdpending'] = self.cmdpending
        context['index'] = self.index
        context['state'] = self.state
        context['elseIfIndex'] = self.elseIfIndex
        context['input'] = self.input
        context['data'] = self.data
        context['extdata'] = self.extdata
        
        # print('saving context')
        # print('context index:', self.index)

        self.index = 0
        self.state = None
        self.elseIfIndex = 0
        self.input = b''
        self.data = b''
        self.extdata = b''

        self.context.append(context)

    def _restoreContext(self):
        """
        Restore to a previous context
        """
        context = self.context.pop()
        self.cmd = context['cmd']
        self.cmdpending = context['cmdpending']
        self.state = context['state']
        self.index = context['index']
        self.elseIfIndex = context['elseIfIndex']
        self.input = context['input'] + self.input
        self.data = context['data'] + self.data
        self.extdata = context['extdata'] + self.extdata

        # print('restoring context, index: ', self.index, '; elseIfIndex: ', self.elseIfIndex)
        # print('restoring cmdpending: ', self.cmdpending)

    def processDataRecieved(self):
        """
        After data is received (in buffer), we start process data in according
        to the command specification:
        - stdout
        - store in a variable
        - redirection, store in input variable
        - etc.
        """
        data = self.buffer
        output = self.cmd['output']

        # print('dataReceived: ', data)
        # print('output: ', output)

        if output == 'stdout':
            if self.context:
                log.msg('output to data')
                # l = len(data)
                # if self.cmd['last'] and l > 0:
                #     data = data[0:l-1]
                self.data += data
            else:
                log.msg('output to stdout')
                self.data = data
                # self.protocol.terminal.write(data)
        elif output == 'input':
            """
            this to remove '\n' at the end of data received sent in excess
            """
            l = len(data)
            if l > 0:
                data = data[0:l-1]

            self.input += data
            self.pipe = True
        elif output == 'var':
            # get the name of variable
            var = self.cmd['var']
            if self.cmd['append']:
                if self.cmd['last']:
                    """
                    this to remove '\n' at the end of data received sent in 
                    excess for displaying on screen
                    """
                    l = len(data)
                    if l > 0:
                        data = data[0:l-1]
                    # print('after removing \n:', data)
                if var in self.var:
                    # append
                    self.var[var] += data
                else:
                    # assign new value
                    self.var[var] = data
            else:
                # it is an assignment
                self.var[var] = data
            # print(self.var)

    def start(self):
        """
        This is where shell starts, but it returns a defer as we can only really
        start the shell execution when the backend is ready to receive command.
        """
        self._exec()

    def next(self):
        """
        process data received, at this point we are sure no more data
        will be recieved.
        """
        self.processExitStatus()
        self.processDataRecieved()

        """ re init buffer """
        self.buffer = b''

        """ execute next pending command """
        self._exec()

    def _showMotd(self):
        self.conn.openChannel(channel.SSHChannelPtyShell(shell=self, conn=self.conn))

    def parsing(self, line):
        """
        Parsing command line to build AST
        """
        trees = parser.parse(line)
        
        for tree in trees:
            visitor = nodevisitor(self, line)
            visitor.visit(tree)
        
        return visitor.cmdpending

    def closeConnection(self):
        """
        Close connection
        """
        # if self.conn:
        #     self.conn.transport.loseConnection()

        # if self.protocol:
        #     self.protocol.eofReceived()
        #     self.protocol = None
    
    
    def _exec(self):
        """
        Methods to execute commands in a command pending
        """
        if self.index < len(self.cmdpending):
            self.cmd = self.cmdpending[self.index]
            self.index += 1
            log.msg('executing command index: {}'.format(self.cmd))
            self._execcmd()
        elif self.context:
            self._restoreContext()
            if self.state is None and self.index < len(self.cmdpending):
                self.cmd = self.cmdpending[self.index]
                self.index += 1
            log.msg('executing command context: {}'.format(self.cmd))
            self._execcmd()
        elif self.request == b'shell-pty':
            log.msg('result of command execution in shell-pty')
            self.writeTerminal(b'\r\n')
            l = len(self.data)
            if l > 0:
                self.data = self.data[0:l-1]
            self.writeTerminal(self.data)
            self.writeTerminal(self.extdata)
            self.showPrompt()
            self.cmdpending = []
            self.index = 0
            self.data = b''
            self.extdata = b''
            self.state = None
            # self.response = None
            print('XXXXXX')
        else:
            self.index = 0
            self.data = b''
            self.extdata = b''
            self.state = None
            log.msg('no more command to execute')
            self.writeTerminal(self.data)
            self.writeTerminal(self.extdata)
            self.closeConnection()

    def _execcmd(self):
        """
        A wrapper that calls subsequent method according to command type:
        _execType()
        """
        t = self.cmd['type']
        log.msg('executing command type: ', t)
        return getattr(self, '_exec%s' % t)()

    def _execoperator(self):
        """
        Execute command based on current operator
        """
        operator = self.cmd['operator']
        if operator == '&&':
            if self.exitStatus == 0:
                return self._exec()
            else:
                return self.closeConnection()
        elif operator == '||':
            if self.exitStatus == 0:
                return self.closeConnection()
            else:
                return self._exec()
        elif operator == ';':
            return self._exec()


    def _execassignment(self):
        """
        Execute assignment command
        """
        c = self.cmd
        # self.cmdList.append(os.path.basename(c['cmd']))
        params = self._listParams()
        
        # self.execcmd = params + bytes(c['var'], 'utf8') + \
        #                bytes(c['sign'], 'utf8') + bytes(c['value'], 'utf8') + \
        #                b'; __exitStatus__=$?; if [ $__exitStatus__ -eq 0 ]; then printf \'%s\' "$' + \
        #                bytes(c['var'], 'utf8') + b'"; fi; printf \'exit: %03d\' $__exitStatus__'
        self.execcmd = params + bytes(c['cmd'], 'utf8') + \
                       b';__exitStatus__=$?; if [ $__exitStatus__ -eq 0 ]; then printf \'%s\' "$' + \
                       bytes(c['var'], 'utf8') + b'"; fi; printf \'#####{"exit": %d, "cwd": "%s"}\' $__exitStatus__ $(pwd)'
        
        self._backendExec()


    def _execcommand(self):
        """
        Execute commands: it can be pipe command or simple command
        """
        if self.pipe:
            self._execpipe()
        else:
            self._execsimple()


    def _execpipe(self):
        """
        Execute pipe command, the input will be simulated by an echo of internal
        `input` variable.
        
        $ echo input | next_command (in the pipeline)
        """

        c = self.cmd
        self.cmdList.append(os.path.basename(c['cmd']))
        params = self._listParams()
        self.execcmd = params

        """ need input """
        self.execcmd += b'echo "' + self.input + b'" | ' + bytes(c['cmd'], 'utf8')
        
        for arg in c['arg']:
            self.execcmd += b' ' + bytes(arg, 'utf8')

        self.execcmd += b'; printf \'#####{"exit": %d, "cwd": "%s"}\' $? $(pwd)'
        
        """
        reinit
        """
        self.pipe = False
        self.input = b''

        self._backendExec()

    def _execsimple(self):
        """
        Execute simple command, check if we have sub variables and fetch their
        values accordingly.
        """
        c = self.cmd
        self.cmdList.append(os.path.basename(c['cmd']))
        params = self._listParams()
            
        self.execcmd = params + bytes(c['cmd'], 'utf8')
        
        for arg in c['arg']:
            self.execcmd += b' ' + bytes(arg, 'utf8')

        self.execcmd += b'; printf \'#####{"exit": %d, "cwd": "%s"}\' $? $(pwd)'
        
        self._backendExec()

    def _execlist(self):
        """
        Execute a list command
        """
        if self.state is None:
            self.state = 'next'
            self._saveContext()
            self.cmdpending = self.cmd['cmd']
            self._exec()
        else:
            self.state = None
            self.input = b''
            self._exec()


    def _execpipeline(self):
        """
        Execute a pipeline
        """
        #FIXME fix state, use different var or manage step
        ####
        ####
        if self.state is None:
            self.state = 'next'
            self._saveContext()
            self.cmdpending = self.cmd['cmd']
            self._exec()
        else:
            self.elseIfIndex = 0
            self.state = None
            self.input = b''
            self._exec()

        
    def _execcompound(self):
        """
        Execute a compound
        """
        if self.state is None:
            self.state = 'next'
            self._saveContext()
            self.cmdpending = self.cmd['cmd']
            self._exec()
        else:
            self.state = None
            self.pipe = self.cmd['pipe']
            if self.cmd['output'] == 'input':
                l = len(self.data)
                if l > 0:
                    self.data = self.data[0:l-1]
                self.input = self.data
                self.data = b''
            else:
                self.input = b''
            self._exec()


    def _execif(self):
        """
        Compound if command has several parts, at least condition and then.
        else is optional as well as elif.

        The execution can be broken down by several sequences; the first command
        condition has to be evaluated first before the first 'then' command will
        be executed. How can we chain that?
        """

        if self.state is None:
            """ evaluate conditions """
            self.cmdpending = self.cmd['condition']
            self.state = 'condition'
            self.index = 0
            # save context
            self._saveContext()
            self._exec()
        elif self.state == 'condition' and self.exitStatus == 0:
            """ evaluate then, if condition passed """
            self.cmdpending = self.cmd['then']
            self.state = 'then'
            self.index = 0
            # save context
            self._saveContext()
            self._exec()
        elif (self.state == 'condition') and \
                (self.exitStatus > 0) and \
                ('elif' in self.cmd) and \
                (self.elseIfIndex < len(self.cmd['elif'])):
            # evaluate first elif condition
            self.cmdpending = [self.cmd['elif'][self.elseIfIndex]]
            if self.elseIfIndex < len(self.cmd['elif']):
                self.elseIfIndex += 1
            self.state = 'elif'
            self._saveContext()
            self._exec()
        elif self.state == 'elif' and self.exitStatus == 0:
            # evaluate elif then
            self.cmdpending = [self.cmd['elif_then'][self.elseIfIndex - 1]]
            self.index = 0
            self.elseIfIndex = 0
            self.state = None
            self._exec()
        elif self.state == 'elif' and \
             self.exitStatus > 0 and \
             self.elseIfIndex < len(self.cmd['elif']):
            # evaluate next elif condition if any
            self.cmdpending = [self.cmd['elif'][self.elseIfIndex]]
            if self.elseIfIndex < len(self.cmd['elif']):
                self.elseIfIndex += 1
            self.state = 'elif'
            self._saveContext()
            self._exec()
        elif (self.state == 'elif' or self.state == 'condition') and 'else' in self.cmd and self.exitStatus > 0:
            # evaluate else clause if if condition failed or nother elif condtions
            self.cmdpending = [self.cmd['else']]
            self.index = 0
            self.elseIfIndex = 0
            self.state = None
            self._exec()
        else:
            self.cmdpending = []
            self.index = 0
            self.elseIfIndex = 0
            self.state = None
            self._exec()

    def _execcommandsubstitution(self):
        """
        Execute a command substitution
        """
        if self.state is None:
            self.state = 'next'
            self._saveContext()
            self.cmdpending = self.cmd['cmd']
            self._exec()
        else:
            self.state = None
            var = self.cmd['var']
            l = len(self.data)
            if l > 0:
                self.data = self.data[0:l-1]
            self.var[var] = self.data
            self.data = b'' 
            self._exec()

    def _execprocesssubstitution(self):
        """
        Execute a process substitution
        """
        if self.state is None:
            self.state = 'next'
            self._saveContext()
            self.cmdpending = self.cmd['cmd']
            self._exec()
        else:
            self.state = None
            var = self.cmd['var']
            l = len(self.data)
            if l > 0:
                self.data = self.data[0:l-1]
            self.var[var] = self.data
            self.data = b'' 
            self._exec()


    def _listParams(self):
        params = b''
        if self.cwd:
            params += b'cd ' + bytes(self.cwd, 'utf8') + b';'

        for p in self.var:
            params += bytes(p, 'utf8') + b'=\"' + self.var[p] + b'\";'
        
        return params

    def _backendExec(self):
        # print("_backendExec: ", self.execcmd)
        data = b'#####{"exit": 0, "cwd": "/home/nproc"}'
        self.execDataReceived(data)
        self.next()
        # if self.protocol.request == b'shell-pty':
        #     self.conn.openChannel(channel.SimpleChannel(shell=self, conn=self.conn))
        # else:
        #     self.conn.openChannel(channel.SimpleChannel(shell=self, conn=self.conn))
    
    def lineReceived(self):
        self.response = 'return'
        line = b''.join(self.protocol.lineBuffer)
        line = line.decode('utf8')
        self.protocol.lineBuffer = []
        self.protocol.lineBufferIndex = 0
        if len(line) > 0:
            print('command to execute: ', line)
            self.cmdpending = self.parsing(line)
            self._exec()

    def handle_CTRL_C(self):
        pass

    def handle_CTRL_D(self):
        pass

    def handle_TAB(self):
        print('handle_TAB, state: ', self.state)
        if self.state is None:
            self.state = 'TAB'
            self.backendChannel.write(b''.join(self.protocol.lineBuffer))
            self.backendChannel.write(b'\t')
        else:
            self.backendChannel.write(b'\t')
        # self.protocol.handle_HOME()
        # self.protocol.lineBufferIndex = 0

    def showPrompt(self):
        log.msg('show prompt')
        self.response = b'show-prompt'
        self.backendChannel.write(b'\x15\r')