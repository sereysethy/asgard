# type checking
from typing import Tuple

import numpy as np

from smartproxy.learning.rl.base import TabularLearner

class QLearner(TabularLearner):
    """
    Class that implements Q-learning algorithm.

    Q-learning is a model free and off-policy reinforcement learning algorithm.

    It is model-free because it learns exclusively using samples derived from
    its interactions with the environment, without requiring a model of the
    environment''s dynamics.

    The off-policy nature means it estimates future rewards by following a
    different policy from the one it currently uses for action selection.
    In other words, it chooses actions according to one policy (e.g., ε-greedy)
    but learns the value of the optimal policy.

    Q-learning learns a Q-function denoted :math:`Q(s,a)` that estimates the
    expected cumulative reward for taking action :math:`a` in state :math:`s`.

    The Q-learning update rule is:

    .. math::
        Q(s_t,a_t) \\leftarrow Q(s_t,a_t) + \\alpha [r_{t+1} + \\gamma \\max_{a'} Q(s_{t+1}, a') - Q(s_t,a_t)]

    Where:
        - :math:`s_t`: state observed at time-step :math:`t`
        - :math:`a_t`: action taken at time-step :math:`t`
        - :math:`r_{t+1}`: immediate reward received after taking action :math:`a_t` in state :math:`s_t`
        - :math:`s_{t+1}`: next state observed at time-step :math:`t+1`
        - :math:`\\alpha`: learning rate that controls how much the Q-value is updated
        - :math:`\\gamma`: discount factor that weights future rewards (0 ≤ γ ≤ 1)
        - :math:`\\max_{a'} Q(s_{t+1}, a')`: maximum Q-value over all possible actions in the next state
    """

    def __init__(self, numFeatures: int, numActions: int)->None:
        super().__init__(numFeatures, numActions)

        self.batchTraining: bool = True
        self._callcount : int = 0

    def newEpisode(self)->None:
        self._callcount += 1

        self.epsilon = max(self.minEpsilon, self.epsilon * self.epsilonDecay)
        self.learningRate = max(self.minLearningRate, self.learningRate * self.learningRateDecay)

    def batchUpdateWeights(self, sample:dict, astate: str = None)->Tuple[list, float, float]:
        """
        Update model's weights in batch mode.

        The method takes a list of samples, and walk through
        each sample and calls :func:`updateWeights` to update its weights.

        Args:
            sample: a dictionary of following items which correspond to the
                sample collected during an episode:

                - obs (list[str]): state observation representing the command names
                - basenames (list[str]): the basenames of the command names
                - actions (list[int]): list of action indexes
                - rewards (list[float]): list of observed rewards
                - dones (list[bool]): list of boolean values indicating if the
                  next state observation is final
                - next_obs (list[str]): list of next state observations
            astate: if provided, the method checks in this sample, if it reaches
                `astate`. If `astate` is reached, it returns ``True`` and the
                number of transitions needed to reach that state.

        Returns:
            tuple: Return format depends on the optional `astate` parameters:
                - If `astate=None`: (list[float], float, int):
                    - tdErrors (list[float]): a list of td errors
                    - episodeRewards (float)
                    - episodeLenght (number of commands)
                - if `astate=None`: (list[float], float, int, bool, int):
                    - tdErrors (list[float]): a list of td errors
                    - episodeRewards (float): accumulative rewards
                    - episodeLenght (int): number of commands
                    - reachAState (bool): ``True`` if `astate` is reached, otherwise ``False``
                    - transitionToAState (int): number of transition until reaching \
                    `astate`
        """
        obs     = sample['obs']
        basenames = sample['basenames']
        actions = sample['actions']
        rewards = sample['rewards']
        dones   = sample['dones']
        nextObs = sample['next_obs']

        tdErrors = []

        episodeReward = 0
        episodeLength = len(obs)

        transitionToAState = 0
        reachAState = False

        for i in range(episodeLength):
            state = obs[i]
            basename = basenames[i]
            action = actions[i]
            reward = rewards[i]
            done = dones[i]

            if not done:
                # this is to prevent the out of index error, in case sample
                # is corrupted.
                if i < len(nextObs):
                    nextState = nextObs[i]
                else:
                    nextState = None
                    done = True
            else:
                nextState = None

            tdEerror = self.updateWeights(state, action, reward, \
                                            nextState, done)

            episodeReward += reward

            tdErrors.append(tdEerror)

            if astate:
                if state != astate:
                    transitionToAState += 1
                if state == astate:
                    reachAState = True

        if astate:
            return tdErrors, episodeReward, episodeLength, reachAState, transitionToAState
        else:
            return tdErrors, episodeReward, episodeLength

    def updateWeights(self, state: str, action: int, reward: float, \
            next_state:str, done:bool)->float:
        """
        Update model's weights for a single sample using the update formular:

        .. math::
            Q(s_t,a_t) \\leftarrow Q(s_t,a_t) + \\alpha [r_{t+1} + \\gamma \\max_{a'} Q(s_{t+1}, a') - Q(s_t,a_t)]

        See :class:`QLearner` for more details.

        Args:
            state: state observation representing the command name
            action: action index
            reward: observed reward
            next_state: next state observation
            done: ``True`` indicates the next state observation is final
        Returns:
            Temporal difference (TD) error between two time-steps
        """
        q = self.models[state][action]

        if not done:
            target_q = reward + self.discount * np.max(self._qValues(next_state))
        else:
            target_q = reward

        tdEerror = target_q - q

        self.models[state][action] += self.learningRate * tdEerror

        return tdEerror


class SARSALearner(TabularLearner):
    """
    Class that implements SARSA algorithm.

    SARSA is a model free and on-policy reinforcement learning algorithm.

    It is model-free because it learns exclusively using samples derived from
    its interactions with the environment, without requiring a model of the
    environment''s dynamics.

    The on-policy nature means it estimates future rewards by following the
    same policy that it currently uses for action selection.

    The Q-learning update rule is:

    .. math::
        Q(s_t,a_t) \\leftarrow Q(s_t,a_t) + \\alpha [r_{t+1} + \\gamma Q(s_{t+1}, a_{t+1}) - Q(s_t,a_t)]

    Where:
        - :math:`s_t`: state observed at time-step :math:`t`
        - :math:`a_t`: action taken at time-step :math:`t`
        - :math:`r_{t+1}`: immediate reward received after taking action :math:`a_t` in state :math:`s_t`
        - :math:`s_{t+1}`: next state observed at time-step :math:`t+1`
        - :math:`a_{t+1}`: action taken at time-step while in :math:`s_{t+1}`
        - :math:`\\alpha`: learning rate that controls how much the Q-value is updated
        - :math:`\\gamma`: discount factor that weights future rewards (0 ≤ γ ≤ 1)
    """
    def __init__(self, numFeatures: int, numActions: int)->None:
        super().__init__(numFeatures, numActions)

        self.batchTraining: bool = True
        self._callcount : int = 0

    def newEpisode(self)->None:
        self._callcount += 1

        self.epsilon = max(self.minEpsilon, self.epsilon * self.epsilonDecay)
        self.learningRate = max(self.minLearningRate, self.learningRate * self.learningRateDecay)


    def batchUpdateWeights(self, sample, astate = None)->list[float]:
        """
        Update model's weights in batch mode.

        The method takes a list of samples, and walk through
        each sample and calls :func:`updateWeights` to update its weights.

        Args:
            sample: a dictionary of following items which correspond to the
                sample collected during an episode:

                - obs (list[str]): state observation representing the command names
                - basenames (list[str]): the basenames of the command names
                - actions (list[int]): list of action indexes
                - rewards (list[float]): list of observed rewards
                - dones (list[bool]): list of boolean values indicating if the
                  next state observation is final
                - next_obs (list[str]): list of next state observations
            astate: if provided, the method checks in this sample, if it reaches
                `astate`. If `astate` is reached, it returns ``True`` and the
                number of transitions needed to reach that state.

        Returns:
            tuple: Return format depends on the optional `astate` parameters:
                - If `astate=None`: (list[float], float, int):
                    - tdErrors (list[float]): a list of td errors
                    - episodeRewards (float)
                    - episodeLenght (number of commands)
                - if `astate=None`: (list[float], float, int, bool, int):
                    - tdErrors (list[float]): a list of td errors
                    - episodeRewards (float): accumulative rewards
                    - episodeLenght (int): number of commands
                    - reachAState (bool): ``True`` if `astate` is reached, otherwise ``False``
                    - transitionToAState (int): number of transition until reaching \
                    `astate`
        """
        obs     = sample['obs']
        basenames = sample['basenames']
        actions = sample['actions']
        rewards = sample['rewards']
        dones   = sample['dones']
        nextObs = sample['next_obs']

        tdErrors = []

        episodeReward = 0
        episodeLength = len(obs)

        transitionToAState = 0
        reachAState = False

        for i in range(episodeLength):
            state = obs[i]
            basename = basenames[i]
            action = actions[i]
            reward = rewards[i]
            done = dones[i]

            if not done:
                nextState = nextObs[i]
                nextAction = actions[i+1]
            else:
                nextState = None
                # if last command is 'exit_', it means it was a command that
                # we manually input to terminate a session.
                # So the effective is equal to the length of obs - 1
                if basename == 'exit_':
                    episodeLength -= 1

            tdEerror = self.updateWeights(state, action, reward, \
                                            nextState, nextAction, done)

            episodeReward += reward

            tdErrors.append(tdEerror)

            if astate:
                if state != astate:
                    transitionToAState += 1
                if state == astate:
                    reachAState = True

        if astate:
            return tdErrors, episodeReward, episodeLength, reachAState, transitionToAState
        else:
            return tdErrors, episodeReward, episodeLength

    def updateWeights(self, state: str, action: int, reward: float, \
                    nextState: str, nextAction: int, done: bool)->Tuple[float, int]:
        """
        Update the model weight for a sample :math:`(s_t, a_t, r_t, s_{t+1}, a_{t+1})`.

        See :class:`SARSALearner` for the update fomular.

        Args:
            state: state observation at time-step :math:`t`.
            action: action taken at time-step :math:`t`.
            reward: reward observed at time-step :math:`t`.
            nextState: next state observation after taking an action
            nextAction: action taken when in the next state
            done: ``True`` if `nextState` is final.
        Returns:
            tuple:
                - Temporal different between two states
                - Next action index
        """
        q = self.models[state][action]

        if not done:
            target_q = reward + self.discount * self.models[nextState][nextAction]
        else:
            target_q = reward

        tdEerror = target_q - q

        self.models[state][action] += self.learningRate * tdEerror

        return tdEerror, nextAction