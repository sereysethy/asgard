import shlex
import uuid;
from bashlex import ast
from configparser import NoOptionError
from twisted.python import log
from cowrie.core.config import CowrieConfig

OPERATOR_OR = '||'
OPERATOR_AND = '&&'
OPERATOR_BACKGROUND = '&'
SEMICOLON = ';'
DOUBLE_SEMICOLON = ';;'
PIPE = '|'

OPEN_PARENTHESIS = '('
CLOSE_PARENTHESIS = ')'
OPEN_CURLY_BRACE = '{'
CLOSE_CURLY_BRACE = '}'
LIST = 'list'

class nodevisitor(ast.nodevisitor):
    """
    This class is used to visit the nodes of the AST produced by bashlex.
    It will produce a list of commands that can be executed by the command executor.

    The commands are stored in the cmdpending list. Each command is a dictionary
    that contains the following keys:

        - type: the type of the command:
            - command, compound, list, pipeline, assignment, parameter, redirect, processsubstitution
    """
    def __init__(self, line):
        """
        Initialize the node visitor.
        """
        self.debug = CowrieConfig.getboolean('parser', 'debug', fallback=False)
        self.stateStack = []
        self.cmdStack = []
        self.varStack = []
        self.contextStack = []
        self.file = []
        self.numberAssignment = 0

        self.line = line

        self.stateStackIndex = -1
        self.cmdStackIndex = -1
        self.varStackIndex = -1
        self.contextStackIndex = -1

        self.stateStackHead = None
        self.cmdStateHead   = None
        self.varStackHead = None
        self.contextStackHead = None

        self.isAssignment = False
        self.filename = ''

        self.varCounter = 0
        self.params = []
        self.indexParam = -1

        self.cmdpending = []

        # The variable compound stores different components of the compound
        # commands:
        # - for: iterator, iterator_list
        # - if: condition, then, else_if and else.
        # It will contain a list of dictionary that hold different components of
        # the compound commands.
        self.compound = []
        self.indexCompound = -1

        self.contexts = []
        self.redirects = []     # all redirect objects of this command
        self.redirect = None    # current redirect object

    def _pushCompound(self, c):
        """
        Push a compound command to the compound stack.
        """
        self.indexCompound += 1
        self.compound.append(c)
        if self.debug:
            log.msg('_pushCompound', self.compound)

    def _popCompound(self):
        """
        Pop a compound command from the compound stack.
        """
        self.indexCompound -= 1
        if self.debug:
            log.msg('_popCompound', self.compound[-1])
        return self.compound.pop()

    def _pushParams(self, p):
        """
        Push a parameter to the params stack.
        """
        self.indexParam += 1
        self.params.append(p)
        if self.debug:
            log.msg('_pushParams', self.params)

    def _popParams(self):
        """
        Pop a parameter from the params stack.
        """
        self.indexParam -= 1
        return self.params.pop()

    def _appendParam(self, p):
        """
        Append a parameter to the current parameter list.
        """
        params = self.params[self.indexParam]
        params.append(p)

    def currentCounter(self):
        """
        Return the current counter and increment it.
        """
        current = self.varCounter
        self.varCounter += 1
        return current

    def _randomStrName(self):
        """
        Return a random string name.
        """
        return uuid.uuid4().hex.upper()

    def _popVar(self):
        """
        Pop a variable from the variable stack.
        """
        e = None
        self.varStackHead = None

        if self.varStackIndex >= 0:
            e = self.varStack.pop()
            self.varStackIndex -= 1
            if self.varStackIndex >= 0:
                self.varStackHead = self.varStack[self.varStackIndex]

        if self.debug:
            log.msg('_popVar', self.varStack)
        return e

    def _pushVar(self, v):
        """
        Push a variable to the variable stack.
        """
        self.varStack.append(v)
        self.varStackIndex += 1
        self.varStackHead = v

        if self.debug:
            log.msg('_pushVar', self.varStack)

    def _saveContext(self):
        """
        Save the current context to the context stack.
        """
        self.contexts.append({
            'contextStackIndex': self.contextStackIndex,
            'contextStack': self.contextStack,
            'params': self.params,
            'indexParam': self.indexParam,
            'varStack': self.varStack,
            'varStackIndex': self.varStackIndex,
            'cmdpending': self.cmdpending,
            'redirects': self.redirects,
            'numberAssignment': self.numberAssignment
        })
        self.contextStack = []
        self.contextStackIndex = -1
        self.params = []
        self.indexParam = -1
        self.varStack = []
        self.varStackIndex = -1
        self.cmdpending = []
        self.redirects = []
        self.numberAssignment = 0

        if self.debug:
            log.msg('_saveContext', self.contexts)

    def _restoreContext(self):
        """
        Restore the last context from the context stack.
        """
        e = self.contexts.pop()
        self.contextStack = e['contextStack']
        self.contextStackIndex = e['contextStackIndex']
        self.params = e['params']
        self.indexParam = e['indexParam']
        self.varStack = e['varStack']
        self.varStackIndex = e['varStackIndex']
        self.cmdpending = e['cmdpending']
        self.redirects = e['redirects']
        self.numberAssignment = e['numberAssignment']

        if self.debug:
            log.msg('_restoreContext', self.contexts)

    def _popContext(self):
        """
        Pop a context from the context stack.
        """
        e = None
        self.contextStackHead = None

        if self.contextStackIndex >= 0:
            e = self.contextStack.pop()
            self.contextStackIndex -= 1
            if self.contextStackIndex >= 0:
                self.contextStackHead = self.contextStack[self.contextStackIndex]

        if self.debug:
            log.msg('_popContext', self.contextStack)
        return e

    def _pushContext(self, c):
        """
        Push a context to the context stack.
        """
        self.contextStack.append(c)
        self.contextStackIndex += 1
        self.contextStackHead = c
        if self.debug:
            log.msg('_pushContext:', self.contextStack)

    def _contextHead(self):
        """
        Return the head of the context stack.
        """
        if self.contextStackIndex >= 0:
            if self.debug:
                log.msg('_contextHead:', self.contextStack[self.contextStackIndex])
            return self.contextStack[self.contextStackIndex]
        else:
            if self.debug:
                log.msg('_contextHead: None')
            return None

    def _statePop(self):
        """
        Pop a state from the state stack.
        """
        e = None
        self.stateStackHead = None

        if self.stateStackIndex >= 0:
            e = self.stateStack.pop()
            self.stateStackIndex -= 1
            if self.stateStackIndex >= 0:
                self.stateStackHead = self.stateStack[self.stateStackIndex]

        if self.debug:
            log.msg('_statePop:', self.stateStack)
        return e

    def _statePush(self, e):
        """
        Push a state to the state stack.
        """
        self.stateStack.append(e)
        self.stateStackIndex += 1
        self.stateStackHead = e

        if self.debug:
            log.msg('_statePush:', self.stateStack)

    def _stateHead(self):
        """
        Return the head of the state stack.
        """
        if self.stateStackIndex >= 0:
            return self.stateStack[self.stateStackIndex]
        else:
            return None

    def _isStateStackEmpty(self)->bool:
        """
        Return True if the state stack is empty.

        Arguments:
            None

        Returns:
            bool: True if the state stack is empty, False otherwise.
        """
        if self.stateStackIndex == -1:
            return True
        else:
            return False

    def _cmdPush(self, e):
        """
        Push a command to the command stack.
        """
        self.cmdStack.append(e)
        self.cmdStackIndex += 1
        self.cmdStackHead = e

        if self.debug:
            log.msg('Cmd push: ', self.cmdStack)

    def _cmdPop(self):
        """
        Pop a command from the command stack.
        """
        e = None
        self.cmdStackHead = None

        if self.cmdStackIndex >= 0:
            e = self.cmdStack.pop()
            self.cmdStackIndex -= 1
            if self.cmdStackIndex >= 0:
                self.cmdStackHead = self.cmdStack[self.cmdStackIndex]

        if self.debug:
            log.msg('_cmdPop:', self.cmdStack)
        return e

    def _isCmdStateEmpty(self)->bool:
        """
        Return True if the command stack is empty.

        Arguments:
            None

        Returns:
            bool: True if the command stack is empty, False otherwise.
        """
        if self.cmdStackIndex == -1:
            return True
        else:
            return False

    def visitnode(self, n):
        """
        This function is called when a node is visited.

        Arguments:
            n: node
        Returns:
            None
        """
        self.assignment = False
        nbParts = 0

        # kind of node
        kind = n.kind

        if self.debug:
            log.msg("kind: %s visitnode: %s" % (kind, n))

        if hasattr(n, 'parts'):
            nbParts = len(n.parts)

        if kind == 'command':
            self._saveContext()
            self._statePush(kind)
            self._statePush(len(n.parts))
        elif kind == 'pipeline':
            self._saveContext()
            self._statePush(kind)
        elif kind == 'list':
            self._saveContext()
            self._statePush(kind)
        elif kind == 'compound':
            # for all the compound nodes: for, if, currently we only
            # treate for and if.
            self._saveContext()
            self._statePush(kind)
            self._pushCompound({})
        elif kind == 'reservedword':
            # reservedword can be if, then, else, for, do, in, done
            if self._contextHead() == 'elif':
                c = self._popContext()
                self._pushContext(c + '_' + n.word)
            else:
                # push the reservedword into the context stack.
                # it will keep tract of what we are dearling with.
                self._pushContext(n.word)
        elif kind == 'redirect':
            self._statePush(kind)
            fin = None
            fout = None
            if n.input is not None:
                if isinstance(n.input, ast.node):
                    fin = n.input.word
                else:
                    fin = str(n.input)
            if n.output is not None:
                if isinstance(n.output, ast.node):
                    fout = n.output.word
                else:
                    fout = str(n.output)
            self.redirect = {"input": fin, "output": fout, "type": n.type}
            self.redirects.append(self.redirect.copy())
        elif kind == 'commandsubstitution':
            self._saveContext()
            self._statePush(kind)
        elif kind == 'assignment':
            self._statePush(kind)
            self._cmdPush(n.word)
        elif kind == 'parameter':
            self._statePush(kind)
            self._cmdPush(n.value)
        elif kind == 'pipe':
            self._statePush(kind)
        elif kind == 'word':
            self._statePush(kind)
        elif kind == 'operator':
            self._statePush(kind)
            self._cmdPush(n.op)
        elif kind == 'processsubstitution':
            self._saveContext()
            self._statePush(kind)
        elif kind == 'if':
            self._statePush(kind)
        elif kind == 'for':
            self._saveContext()
            self._statePush(kind)
        elif kind == 'do':
            # will not do anything, up until this point
            # the command between for ... do has been saved in
            # the compound.
            pass

    def visitnodeend(self, n):
        """
        This function is called after a node has been visited.

        Arguments:
            n: node

        Returns:
            None
        """
        nbParts = 0
        kind = n.kind
        cmd = []

        if self.debug:
            log.msg("kind: %s, visitnodeend: %s" % (kind, n))

        if kind == 'compound':
            self._processCompoundNodeEnd(n)
        elif kind == 'list':
            self._processListNodeEnd(n)
        elif kind == 'if':
            self._processCompoundIf(n)
        elif kind == 'processsubstitution':
            self._processSubstitution(n)
        elif kind == 'pipeline':
            self._processPipeline(n)
        elif kind == 'commandsubstitution':
            self._processCommandSubstitution(n)
        elif kind == 'redirect':
            self._processRedirect(n)
        elif kind == 'assignment':
            self.numberAssignment += 1
            self._processAssignment(n)
        elif kind == 'parameter':
            self._statePop()
            param = self._cmdPop()
            newParam = {}
            newParam['type'] = 'parameter'
            newParam['name'] = param
            newParam['param'] = param
            self._pushParams(newParam.copy())
        elif kind == 'word':
            e = self._statePop()
            # we make an exception as when a redirect is a file,
            # it is pushed as word to cmd, so we pop it out.
            if self._stateHead() == 'redirect':
                self._cmdPop()
        elif kind == 'pipe':
            self._processPipe(n)
        elif kind == 'operator':
            self._processOperator(n)
        elif kind == 'command':
            context = self._contextHead()
            if context == 'assignment':
                """ Assignment command """
                cmd = self._commandWithAssignment()
                self._popContext()
                cmdpending = self.cmdpending
                self._restoreContext()
                self.cmdpending.extend(cmdpending)
                self.cmdpending.append(cmd)
                cmd = None
            else:
                """ Normal commmand """
                self._processCommandEnd(n)
        elif kind == 'for':
            self._processCompoundForEnd(n)
        elif kind == 'reservedword':
            if self._contextHead() == 'in':
                self._popContext()
                compound = self._popCompound()
                compound['iterator'] = self._cmdPop()
                self._pushCompound(compound)
            elif self._contextHead() == 'do':
                self._popContext()
                compound = self._popCompound()
                compound['iterator_list'] = self.cmdStack
                self._pushCompound(compound)
                self.cmdStack = []
                self.cmdStackIndex = -1
            elif self._contextHead() == 'done':
                # we arrived at done but we will
                # process it when we end the node For
                self._popContext() # remove done from the context

        if self.debug:
            log.msg('After visitnode, Cmdpending', self.cmdpending)

    def _processCommandEnd(self, n):
        """
        There are two ways that bashlex produces the AST for the compound if.
        In the condition part, if we use the ';' to separate the command from
        the reserved word like 'then', 'fi'. It produces a list. But if we use
        '\n' instead, it produces normal command. That is why we need to catch
        those commands here if the context head if 'if' or 'then'. Here we ignore
        the 'else' part.

        TODO: elif and else part.

        Arguments:
            n: node

        Returns:
            None
        """

        cmd = self._normalCmd()
        # save the current cmdPending before restoring the context
        cmdpending = self.cmdpending
        self._restoreContext()

        # this is the command which follows right after the if
        # so we save it in the current compound collection
        if self._contextHead() == 'if':
            compound = self._popCompound()
            compound['if'] = cmd
            self._pushCompound(compound)
            self._popContext()
        # this is the command which follows right after the then
        # so we save it in the current compound collection
        elif self._contextHead() == 'then':
            compound = self._popCompound()
            compound['then'] = cmd
            self._pushCompound(compound)
            self._popContext()
        else:
            self.cmdpending.extend(cmdpending)
            self.cmdpending.append(cmd)
            cmd = None

    def _processOperator(self, n):
        """
        Process the operator node. It can be '&&', '||', '&', ';', ';;', '|', '|&'

        Arguments:
            n: node
        Returns:
            None
        """
        self._statePop()
        cmd = {}
        cmd['type'] = 'operator'
        cmd['operator'] = self._cmdPop()
        self.cmdpending.append(cmd)

    def _processCompoundNodeEnd(self, n):
        """
        When we reach the end of a compound node, we have constructed different
        parts of the compound command:
        - for: iterator, iterator_list, commands between do and done
        - if: condition, then, elif, elif_then and else.
        We construct a command object of type 'compound', where we store the
        different components of the compound command.

        Arguments:
            n: node
        Returns:
            None
        """
        self._statePop()
        cmdpending = self.cmdpending
        self._restoreContext()
        if self._contextHead() == 'then':
            compound = self._popCompound()
            compound['then'] = cmdpending
            self._pushCompound(compound)
            self._popContext()
            cmdpending = None
        elif self._contextHead() == 'else':
            compound = self._popCompound()
            compound['else'] = cmdpending
            self._pushCompound(compound)
            self._popContext()
            cmdpending = None
        else:
            l = len(cmdpending)
            lastCmd = cmdpending[l - 1]
            lastCmd['last'] = True

            cmd = {}
            cmd['type']    = 'compound'
            cmd['cmd_str'] = self.line[n.pos[0]:n.pos[1]]
            cmd['cmd']     = cmdpending
            cmd['arg']     = []
            cmd['pipe']    = False
            cmd['sub']     = False
            cmd['input']   = None
            cmd['output']  = 'stdout'
            cmd['var']     = ''
            cmd['redirect']  = False
            cmd['last']      = False
            cmd['append']  = False

            self.cmdpending.extend([cmd])

        if self.debug:
            log.msg('after compound, cmdpending: ', self.cmdpending)
            log.msg('after compound, compound: ', self.compound)

    def _processListNodeEnd(self, n):
        """
        When we reach the end of a list node, we have constructed different
        parts of the list command. We construct a command object of type 'list',
        where we store the different components of the list command.
        The list command is a sequence of commands separated by ';' or '\n'.
        We ignore the 'else' part of the list command. The 'else' part is handled
        by the _processCompoundIf function. The 'elif' and 'elif_then' parts are
        also handled by the _processCompoundIf function.

        Arguments:
            n: node
        Returns:
            None
        """
        self._statePop()
        cmdpending = self.cmdpending
        self._restoreContext()

        cmd = {}
        cmd['type']    = 'list'
        cmd['cmd_str'] = self.line[n.pos[0]:n.pos[1]]
        cmd['cmd']     = cmdpending
        cmd['arg']     = []
        cmd['pipe']    = False
        cmd['sub']     = False
        cmd['input']   = None
        cmd['output']  = 'stdout'
        cmd['var']     = ''
        cmd['redirect']  = False
        cmd['last']      = False
        cmd['append']  = False

        context = self._contextHead()
        if context == 'if' or context == 'then':
            compound = self._popCompound()
            compound[context] = cmd
            cmdpending = None
            self._pushCompound(compound)
            self._popContext()
        elif context == 'elif' or context == 'elif_then':
            compound = self._popCompound()
            if context not in compound:
                compound[context] = []
            compound[context].append(cmd)
            cmdpending = None
            self._pushCompound(compound)
            """ we do not pop the context, we use it to distinguish if then
            and elif then """
            if context == 'elif_then':
                self._popContext()
        elif context == 'else':
            compound = self._popCompound()
            compound['else'] = cmd
            cmdpending = None
            self._pushCompound(compound)
            self._popContext()
        elif context == '(':
            self._popContext()
            self.cmdpending.extend(cmdpending)
        elif context == ')':
            self._popContext()
        else:
            self.cmdpending.extend([cmd])

        if self.debug:
            log.msg("after list compound: ", self.compound)
            log.msg("after list cmdpending: ", self.cmdpending)

    def _processCompoundIf(self, n):
        """
        Process the 'if' compound command.

        When we reach the reservedword 'fi', it means we have constructed all
        the different components of an if command:
        - condition: if part
        - then: then part
        - elif: elif_then part
        - elif: else parth
        We construct a comment of type 'if' with 'condition', 'elif', 'elif_then'
        and 'else'.
        """
        if self._contextHead() == 'fi':
            compound = self._popCompound()
            self._statePop()
            self._popContext()
            cmd = {}
            cmd['type'] = 'if'
            cmd['condition'] = [compound['if']]
            cmd['then'] = [compound['then']]
            if 'elif' in compound:
                cmd['elif'] = compound['elif']
            if 'elif_then' in compound:
                cmd['elif_then'] = compound['elif_then']
            if 'else' in compound:
                cmd['else'] = compound['else']
            self.cmdpending.append(cmd)

    def _processCompoundForEnd(self, n):
        """
        When we finished visiting the node for, we have constructed different
        parts of the command for:
        - iterator
        - iterator list
        - commands between 'do' and 'done'.
        We construct a command object of type 'for', where we store the iterator,
        the iterator list and the commands between do and done that need to be
        executed.
        """
        self._statePop()
        # save the current cmdpending
        cmdpending = self.cmdpending
        self._restoreContext()
        compound = self._popCompound()

        cmd = {}
        cmd['type']    = 'for'
        cmd['cmd_str'] = self.line[n.pos[0]:n.pos[1]]
        cmd['iterator'] = compound['iterator']
        cmd['iterator_list'] = compound['iterator_list']
        cmd['cmd']     = cmdpending
        cmd['arg']     = []
        cmd['pipe']    = False
        cmd['sub']     = False
        cmd['input']   = None
        cmd['output']  = 'stdout'
        cmd['var']     = ''
        cmd['redirect']  = False
        cmd['last']      = False
        cmd['append']  = False
        self.cmdpending.extend([cmd])

    def _processPipeline(self, n):
        """
        When we finished visiting the node pipeline, we have constructed different
        parts of the pipeline command. We construct a command object of type 'pipeline',
        where we store the different components of the pipeline command.
        """
        self._statePop()
        cmdpending = self.cmdpending
        self._restoreContext()

        cmd = {}
        cmd['type']    = 'pipeline'
        cmd['cmd_str'] = self.line[n.pos[0]:n.pos[1]]
        cmd['cmd']     = cmdpending
        cmd['arg']     = []
        cmd['pipe']    = True
        cmd['sub']     = False
        cmd['input']   = None
        cmd['output']  = 'stdout'
        cmd['var']     = ''
        cmd['redirect']  = False
        cmd['last']      = False
        cmd['append']  = False
        self.cmdpending.append(cmd)

    def _processRedirect(self, n):
        """
        Process the redirect node. It can be '>', '>>', '<', '<<', '<<<', '>&', '<&', '>|', '>|&'
        """
        r = self.redirect
        if r['input'] is not None:
            _r = r['input'] + r['type']
        else:
            _r = r['type']
        if r['output'] is not None:
            _r += r['output']
        self._cmdPush(_r)
        self._statePop()
        # re-init current redirect after consumption
        self.redirect = None

    def _processAssignment(self, n):
        """
        Process the assignment node. It can be 'VAR=value' or 'VAR=value command'.
        """
        self._statePop()
        word = self._cmdPop()
        k = self.parseAssignement(word)
        self._pushVar(k)
        self._cmdPush(word)
        self._pushContext(n.kind)

    def _processPipe(self, n):
        """
        Mark the last command as a pipe that its output will be assigned to
        an input of the next command in the pipeline
        """
        self._statePop()
        self._cmdPop()      # remove |
        length = len(self.cmdpending)
        lastCmd = self.cmdpending[length - 1]
        lastCmd['pipe'] = True
        lastCmd['output'] = 'input'

    def _processSubstitution(self, n):
        """
        Process the process substitution node. It can be '<(command)' or '>(command)'.
        """
        cmdpending = self.cmdpending
        self._restoreContext()

        self._statePop()
        head = self._stateHead()

        # replace the process substitution with a variable
        sub_var = 'var{}'.format(self.currentCounter())

        cmd = {}
        cmd['type']    = 'processsubstitution'
        cmd['cmd_str'] = self.line[n.pos[0]:n.pos[1]]
        cmd['cmd']     = cmdpending
        cmd['arg']     = []
        cmd['pipe']    = False
        cmd['sub']     = True
        cmd['input']   = None
        cmd['output']  = 'var'
        cmd['var']     = sub_var
        cmd['redirect']  = False
        cmd['last']      = False
        cmd['append']  = False
        cmd['redirects'] = self.redirects

        arg = self._cmdPop()
        arg = '<(echo -e \"$' + sub_var + '\")'
        self._cmdPush(arg)

        newParam = {}
        newParam['type'] = 'parameter'
        newParam['name'] = sub_var
        newParam['param'] = sub_var
        self._pushParams(newParam)

        self.cmdpending.append(cmd)

        if self.debug:
            log.msg('commandsubstitution, cmdpending: ', self.cmdpending)

    def _processCommandSubstitution(self, n):
        """
        Process the command substitution node. It can be '$(command)' or '`command`'.

        There are several cases to consider:
            - Case 1: command substitution is preceded by word, we replace the word
              by the sub_var;
            - Case 2: command substitution is preceded by an assignment, the output
              of each command will be appended to a single variable, output is set
              to 'var', and we create a new variable. In case of a command is a
              pipe, we do make any changes only the output of the last command in
              the pipeline will be assigned to an output variable.
        """
        cmdpending = self.cmdpending
        self._restoreContext()
        self._statePop()

        if self.debug:
            log.msg('commandsubstitution, cmdpending: ', self.cmdpending)


    def _normalCmd(self):
        """
        Process a normal command. It can be 'command arg1 arg2 ...'.
        """
        # init
        cmd = {}
        tmp = []
        nbParts = int(self._statePop())   # remove nbParts from Stack
        cmd ={}

        for i in range(nbParts):
            tmp.append(self._cmdPop())
        """ here we can decide what to do with this command: execute or block? """
        tmp.reverse()

        cmd['type'] = 'command'

        cmd['redirect'] = False
        cmd['output']   = 'stdout'
        cmd['cmd_str']  = ' '.join(tmp)
        cmd['cmd']      = tmp[0]
        cmd['arg']      = tmp[1:]   # can be empty if no arguments
        cmd['pipe']     = False
        cmd['sub']      = False
        cmd['input']    = None
        cmd['last']     = False
        cmd['redirects'] = self.redirects
        cmd['assignments'] = []

        if (self._contextHead() == 'processsubstitution'):
            cmd['append'] = True
        else:
            cmd['append'] = False

        params = self.params

        cmd['params'] = []
        for p in params:
            cmd['params'].append(p['param'])

        self._statePop()   # remove command from state

        return cmd

    def _commandWithAssignment(self):
        """
        Process a command with assignments.
        It can be 'VAR=value command arg1 arg2 ...'.
        """
        # init
        cmd = {}
        tmp = []
        nbParts = int(self._statePop())   # remove nbParts from Stack
        cmd ={}

        for i in range(nbParts):
            tmp.append(self._cmdPop())

        tmp.reverse()

        cmd['type'] = 'command'

        # get the assignment if any
        assignments = []
        for i in range(self.numberAssignment):
            assignments.append(tmp[i])

        cmd['redirect'] = False
        cmd['output']   = 'stdout'
        cmd['cmd_str']  = ' '.join(tmp)
        # if command is preceeded by assignments
        if len(tmp) > 1:
            cmd['cmd'] = tmp[self.numberAssignment]
            cmd['arg'] = tmp[self.numberAssignment+1:]   # can be empty if no arguments
        else:
        # the command is the assignment command
            cmd['type'] = 'assignment'
            cmd['cmd'] = tmp[0]
        cmd['pipe']     = False
        cmd['sub']      = False
        cmd['input']    = None
        cmd['last']     = False
        cmd['redirects'] = self.redirects
        cmd['assignments'] = assignments

        if (self._contextHead() == 'processsubstitution'):
            cmd['append'] = True
        else:
            cmd['append'] = False

        params = self.params

        cmd['params'] = []
        for p in params:
            cmd['params'].append(p['param'])

        self._statePop()   # remove command from state

        return cmd

    def visitoperator(self, n, op):
        pass

    def visitlist(self, n, parts):
        pass

    def visitpipe(self, n, pipe):
        self._cmdPush(pipe)

    def visitpipeline(self, n, parts):
        pass

    def visitcompound(self, n, list, redirects):
        pass

    def visitif(self, node, parts):
        pass

    def visitfor(self, node, parts):
        pass

    def visitwhile(self, node, parts):
        pass

    def visituntil(self, node, parts):
        pass

    def visitcommand(self, n, parts):
        pass

    def visitfunction(self, n, name, body, parts):
        pass

    def visitword(self, n, word):
        """
        Process a word node. It can be a command, an argument,
        a variable, a string, etc.
        """

        # we store input word to preserve quotes or any other special characters
        self._cmdPush(self.line[n.pos[0]:n.pos[1]])

    def visitassignment(self, n, word):
        pass
    def visitreservedword(self, n, word):
        pass
    def visitparameter(self, n, value):
        pass
    def visittilde(self, n, value):
        pass
    def visitredirect(self, n, input, type, output, heredoc):
        pass
    def visitheredoc(self, n, value):
        pass
    def visitprocesssubstitution(self, n, command):
        pass
    def visitcommandsubstitution(self, n, command):
        pass

    def parseAssignement(self, word):
        """
        Parse an assignment word. It can be 'VAR=value' or 'VAR=value command'.
        """
        lexer = shlex.shlex(word, punctuation_chars='+=', posix=True)
        lexer.wordchars += '`;$() |-\'\"'
        lexer.whitespace = ''
        k = {}
        # as value can be empty, so we initialize it beforehand
        k['value'] = ''
        tmp = ''
        state = 'start'
        while True:
            token = lexer.get_token()
            if token == lexer.eof:
                state = 'end'
                break
            elif state == 'start':
                k['var'] = token
                state = 'assignment'
                continue
            elif state == 'assignment':
                k['sign'] = token
                state = 'value'
                continue
            elif state == 'value':
                k['value'] = token
                continue
        return k

    def __parseAssignement(self, word):
        lexer = shlex.shlex(word, punctuation_chars='=', posix=True)
        k = {}
        k['value'] = []
        tmp = ''
        state = 'start'
        while True:
            token = lexer.get_token()
            if token == lexer.eof:
                state = 'end'
                break
            elif state == 'start':
                k['var'] = token
                state = 'assignment'
                continue
            elif state == 'assignment':
                k['sign'] = token
                state = 'value'
                continue
            elif state == 'value' and token != '$':
                k['value'].append(token)
                state = 'end'
                continue
            elif state == 'value' and token == '$':
                state = 'variable'
                tmp += token
                continue
            elif state == 'variable':
                if token == '{':
                    state = 'open_brace'
                    tmp += token
                else:
                    state = 'end'
                    tmp += token
                    k['value'].append(tmp)
                    tmp = ''
                continue
            elif state == 'open_brace':
                if token.isalnum:
                    state = 'name'
                    tmp += token
                    continue
                else:
                    state = 'error'
                    break
            elif state == 'name':
                if token == '}':
                    state = 'end'
                    tmp += token
                    k['value'].append(tmp)
                    tmp = ''
                    continue
                else:
                    state = 'error'
                    break
            elif state == 'end' and token.isalnum():
                k['value'].append(token)
                continue
            elif state == 'end' and token == '$':
                state = 'variable'
                tmp += token
        return k