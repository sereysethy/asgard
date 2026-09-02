from smartproxy.utils import common
from smartproxy.utils import utils

class AttackPatterns():

    states = {}
    INIT_STATE = 0
    FINAL_STATE = 10000

    def __init__(self):
        pass

    def transition(self, cmd):
        patterns = [
            "pattern1",
            "pattern2",
            "pattern3",
            "pattern4",
            "pattern5",
            "pattern6"
        ]

        for pattern in patterns:
            getattr(self, pattern)(cmd)

        reachFinalState = {}
        for pattern in patterns:
            if self.states[pattern] == self.FINAL_STATE:
                reachFinalState[pattern] = True
            else:
                reachFinalState[pattern] = False

        return reachFinalState

    def reset(self):
        """Reset states."""

        self.states = {}

    def getState(self, pattern: str)->int:
        """get state of this pattern from global states.

        If state is not yet set, save it first and initiliase it with an
        INIT_STATE. If state reaches FINAL_STATE, it is re-init with INIT_STATE.

        Parameters
        ----------
            pattern: (str) name of pattern
        Return
        ------
            a previous state or an initial state if it is not yet present
        """
        if pattern not in self.states:
            self.states[pattern] = self.INIT_STATE
        elif self.states[pattern] == self.FINAL_STATE:
            self.states[pattern] = self.INIT_STATE

        return self.states[pattern]

    def saveState(self, pattern: str, state: int)->int:
        """Save a pattern state in global states variables and return it.

        Parameters
        ----------
            pattern: (str) name of pattern
            state: (int) state to save
        Return
        ------
            None
        """
        self.states[pattern] = state

        return self.states[pattern]

    # pattern 1: ./custom
    def pattern1(self, cmd):
        _name = "pattern1"
        _state = self.getState(_name)
        
        if _state == self.INIT_STATE and len(cmd) >= 3 and cmd[0] == "." \
            and cmd[1] == "/" and len(cmd[2:]) > 0:
            _state = self.FINAL_STATE

        self.saveState(_name, _state)

    # pattern 2: echo, base64, sh or bash
    def pattern2(self, cmd):
        _name = "pattern2"
        _state = self.getState(_name)
        _match = False

        _cmd = utils.get_basename(cmd)
        if _state == self.INIT_STATE and _cmd == "echo":
            _state = 1
            _match = True

        if _state == 1 and _cmd == "base64" :
            _state = 2
            _match = True

        if _state == 2 and (_cmd == "sh" or _cmd == "bash"):
            _state = self.FINAL_STATE
            _match = True

        if not _match:
            self.saveState(_name, self.INIT_STATE)
        else:   
            self.saveState(_name, _state)

    # pattern 3: echo, sh
    def pattern3(self, cmd):
        _name = "pattern3"
        _state = self.getState(_name)
        _match = False

        _cmd = utils.get_basename(cmd)
        if _state == self.INIT_STATE and _cmd == "echo":
            _state = 1
            _match = True
        if _state == 1 and (_cmd == "sh" or _cmd == "bash"):
            _state = self.FINAL_STATE
            _match = True

        if not _match:
            self.saveState(_name, self.INIT_STATE)
        else:   
            self.saveState(_name, _state)

    # pattern 4: use shell to execut a shell script in base64
    # base64 --decode __BASE64__ | bash
    def pattern4(self, cmd):
        _name = "pattern4"
        _state = self.getState(_name)
        _match = False
        
        _cmd = utils.get_basename(cmd)
        if _state == self.INIT_STATE and _cmd == "base64":
            _state = 1
            _match = True
        if _state == 1 and (_cmd == "sh" or _cmd == "bash"):
            _state = self.FINAL_STATE
            _match = True

        if not _match:
            self.saveState(_name, self.INIT_STATE)
        else:   
            self.saveState(_name, _state)

    # pattern 5: normal user: take over account
    def pattern5(self, cmd):
        # echo "oldpass\nnewpass\nnewpass|passwd|bash"
        # echo "oldpass\nnewpass\nnewpass|passwd"
        _name = "pattern5"
        _state = self.getState(_name)
        _match = False
        
        _cmd = utils.get_basename(cmd)
        if _state == self.INIT_STATE and _cmd == "echo":
            _state = 1
            _match = True
        if _state == 1 and _cmd == "passwd":
            _state = 2
            _match = True
        if _state == 2 and (_cmd == "sh" or _cmd == "bash"):
            _state = self.FINAL_STATE
            _match = True

        if not _match:
            self.saveState(_name, self.INIT_STATE)
        else:   
            self.saveState(_name, _state)

    # pattern 6: root user: take over account, echo "root:secret"|chpasswd|bash
    def pattern6(self, cmd):
        _name = "pattern6"
        _state = self.getState(_name)
        _match = False
        
        _cmd = utils.get_basename(cmd)
        if _state == self.INIT_STATE and _cmd == "echo":
            _state = 1
            _match = True
        if _state == 1 and _cmd == "chpasswd" :
            _state = 2
            _match = True
        if _state == 2 and (_cmd == "sh" or _cmd == "bash"):
            _state = self.FINAL_STATE
            _match = True
        
        if not _match:
            self.saveState(_name, self.INIT_STATE)
        else:   
            self.saveState(_name, _state)