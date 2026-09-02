import numpy as np

class BaseLearner():
    """
    A reinforcement learning agent that interacts with an environment.

    Args:
        numFeatures : The number of features in the state space.
        numActions : The number of possible actions.

    Attributes:
        epsilon: The current :math:`\epsilon` value of the :math:`\epsilon`-greedy
            policy. This sets the exploration probability.
        minEpsilon: Minimum exploration probability
        initEpsilon: Initiial exploration probability
        epsilonDecay: Exploration probability decay

        epsilonGreedy: Use :math:`\epsilon`-greedy policy. Set it ``False`` to
            disable it.

        discount: The discount factor :math:`\gamma` to weight a long
            term reward over an immediate one.
        batchMode: Batch mode is on.

        initLearningRate: Initial learning rate to update the model.

        learningRate: Current learning rate.

        learningRateDecay: Learnig rate decay to reduce the learning rate.

        minLearningRate: Minimum learning rate.
    """
    numFeatures: int
    numActions: int

    randomInit: bool = True

    discount: float = 0.99 # aka gamma

    batchMode: bool = False
    passNextAction: bool = False   # for the _updateWeights method

    learningRate: float = 0.1
    learningRateDecay: float = 25
    minLearningRate: float = 0.1
    initLearningRate: float = 0.1

    epsilon: float = 0.2
    minEpsilon: float = 0.1
    initEpsilon: float = 0.2
    epsilonDecay: float = 25

    epsilonGreedy: bool = True

    #: flags for different modes
    learning: bool = True
    greedy: bool = False

    # this indicates that the training should start after a session ends
    batchTraining: bool = False

    def __init__(self, numFeatures: int, numActions: int)->None:
        self.numActions = numActions
        self.numFeatures = numFeatures

        self.models = None

    def _actionSample(self, actions: int=None):
        """Draw a uniform random action sample.

        Args:
            actions: If provided, the agent randomly sample
                action from `0` to `actions`. Default is ``None``, the agent
                draws randomly an action from the :ref:`numActions`.
        """
        if actions is None:
            _actions = [i for i in range(self.numActions)]
        else:
            _actions = [i for i in range(actions)]

        return np.random.choice(_actions)

    def _qValue(self, state, action):
        """Returns the q value for a given a state-action pair."""
        return NotImplemented

    def _qValues(self, state, possibleActions=None):
        """Returns the q values for a given a state for all possible actions."""
        return NotImplemented

    def getAction(self, state, exploration=True)->int:
        """Returns the best action for a given state.

        Args:
            state: The current state encounted by the agent.
            exploration: If it is ``True``, the action is returned
            in exploration mode, otherwise the best action is always returned.
        """
        return NotImplemented

    def reset(self):
        """
        Reset the agent to its initial state.

        Resets the agent's parameters to their initial values such as `epsilon`,
        `learningRate`, etc.

        Raise:
            NotImplemented
        """

        return NotImplemented

    def newEpisode(self):
        """
        Update agent parameters at the start of a new episode.
        This is where some parameters are initialized before starting
        a new episode.

        Raise:
            NotImplemented
        """

        return NotImplemented

    def getFeatureSample(self):
        """
        Return feature sample using a normal distribution.

        This method should be overwritten to return the correct sample.
        """
        return np.random.random(self.numFeatures)

    def train(self):
        """
        Train the model.

        It will update the model parameters in according to the learning
        algorithm.

        Raise:
            NotImplemented
        """
        return NotImplemented

    def updateWeights(self, state, action, reward, nextState, done):
        """
        Update the model weight for a sample :math:`(s_t, a_t, r_t, s_{t+1})`.

        Args:
            state: state observation at time-step :math:`t`.
            action: action taken at time-step :math:`t`.
            r: reward observed at time-step :math:`t`.
            nextState: next state observation after taking action
            done: ``True`` if `nextState` is final.
        """
        return NotImplemented

class TabularLearner(BaseLearner):
    """
    A parent tabular class that an agent that implements a tabular-based method
    such as SARSA or Q-learning has to inherit.
    The Q-value for each action is represented by a two-dimension list
    (aka the `models`) correspoding to a list of `numFeatures` and `numActions`.

    Args:
        numFeatures: Number of features corresponding to the finite number of
            state observation.
        numActions: Number of actions that an agent can perform.
    """

    def __init__(self, numFeatures: int, numActions: int)->None:
        super().__init__(numFeatures, numActions)
        self.models = []
        self._callcount: int = 0

        for i in range(self.numFeatures):
            _s = []
            for j in range(self.numActions):
                _s.append(0)
            self.models.append(_s)

    def _qValue(self, state, action):
        return self.models[state][action]

    def _qValues(self, state):
        """
        Return vector of q-values for all actions, given the state observation
        (features).
        """

        return self.models[state]

    def _greedyAction(self, state):
        return np.argmax(self._qValues(state))

    def getAction(self, state, exploration:bool=True)->int:
        """
        Select an action for the given state using epsilon-greedy policy.

        Args:
            state: The current state observation from the environment
            exploration: Whether to use exploration
                (epsilon-greedy) or pure exploitation (greedy). Defaults to True.

        Returns:
            The selected action index

        Behavior:
            - If exploration is ``True``, use epsilon-greedy policy where the \
            agent explores (random action) with probability epsilon, otherwise \
            exploits (greedy action) with probability (1-epsilon)

            - If exploration is ``False``, always selects the greedy action \
            (pure exploitation)

        The greedy action is determined by selecting the action with the highest
        Q-value for the given state. Random exploration uses `_actionSample()`
        to ensure uniform sampling from the action space.

        This method is typically called with exploration is ``True`` during
        training and `exploration` is ``False`` during evaluation or testing
        phases. However, it can be set to ``True`` during evaluation or testing
        to maintain an exploratory action for a minimal epsilon value.
        """
        if exploration:
            if (np.random.random() <= self.epsilon):
                return self._actionSample()
            else:
                return np.argmax(self._qValues(state))
        else:
            return np.argmax(self._qValues(state))

    def reset(self)->None:
        """
        Reset the agent to its initial state.

        Resets the agent's parameters to their initial values, including:

        - `epsilon`: Reset to `initEpsilon` for exploration-exploitation balance
        - `learningRate`: Reset to `initLearningRate` for parameter updates
        - `_callcount`: Reset to 0 to track the number of method calls

        This method should be called when starting a new episode or when
        reinitializing the agent between training sessions.
        """

        self._callcount = 0

        self.epsilon = self.initEpsilon
        self.learningRate = self.initLearningRate

    def newEpisode(self)->None:
        """
        Update agent parameters at the start of a new episode.

        This method should be called at the beginning of each new episode to:

        - Increment the episode counter (`_callcount`)
        - Decay epsilon for exploration rate scheduling (epsilon-greedy policy)
        - Decay learning rate for adaptive step size control

        Both epsilon and learning rate are decayed by their respective decay
        factors but are clamped to their minimum values to prevent them from
        becoming too small and hindering learning performance.

        The decay schedule helps the agent transition from exploration to
        exploitation and from large to fine-grained parameter updates as
        training progresses.
        """
        self._callcount += 1

        self.epsilon = max(self.minEpsilon, self.epsilon * self.epsilonDecay)
        self.learningRate = max(self.minLearningRate, self.learningRate * self.learningRateDecay)
