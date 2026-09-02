# ML library
import numpy as np
import numpy.ma as ma
from numpy.random import default_rng
from sklearn.linear_model import SGDRegressor

# custom library
from smartproxy.learning.rl.base import BaseLearner
from smartproxy import tlog

class LinearFALearner(BaseLearner):
    """Function Approximator Base class."""

    def __init__(self, numFeatures: int, numActions: int, learningRate: float, randomState: int, verbose: int)->None:
        super().__init__(numFeatures, numActions)

        tlog.info("Model reproductibility random state: {randomState}", randomState=randomState)
        tlog.info("Model verbosity level: {verbose}", verbose=verbose)

        self.models = []
        self.rng = default_rng(randomState)

        # it is a batch training
        self.batchTraining = True

        for i in range(self.numActions):
            model = SGDRegressor(
                                    learning_rate="constant",
                                    max_iter=1,
                                    eta0=learningRate,
                                    random_state=randomState,
                                    verbose=verbose
                                )

            feature = self.getFeatureSample()
            model.partial_fit([feature], [0])
            self.models.append(model)

    def _qValue(self, state, action):
        """
        It will calcualte the q-value of the state and action.

        The result is a list.
        Params:
        -------
            state (Numpy.array): state observation
            action (int): indext of action

        Returns:
        --------
            q-value (float): value of q-value
        """

        q = self.models[action].predict([state])
        # as the returned result is a list, so we return the first element.
        return q[0]

    def _qValues(self, state, possibleActions=None):
        """Return vector of q-values for all actions, given the state(-features)."""

        qs = []
        if possibleActions:
            for action in possibleActions:
                qs.append(self._qValue(state, action))
        else:
            for action in range(self.numActions):
                qs.append(self._qValue(state, action))

        return qs

    def _greedyAction(self, state):
        return np.argmax(self._qValues(state))

    def getAction(self, state, exploration=True):
        if exploration:
            if (self.rng.random() <= self.epsilon):
                return self._actionSample()
            else:
                return np.argmax(self._qValues(state))
        else:
            return np.argmax(self._qValues(state))

    def getFeatureSample(self):
        return np.zeros(self.numFeatures)

    def reset(self):
        self._callcount = 0

        self.epsilon = self.initEpsilon
        self.learningRate = self.initLearningRate

    def newEpisode(self):
        self._callcount += 1

        self.epsilon = max(self.minEpsilon, self.epsilon * self.epsilonDecay)
        # learning rate is init in the SGDRegressor
        # self.learningRate = max(self.minLearningRate, self.learningRate * self.learningRateDecay)

    def getAttributes(self):
        """Get params of the model."""

        attributes = {}
        for a in range(self.numActions):
            attributes["action_" + str(a)] = {
                        "n_iter_": self.models[a].n_iter_,
                        "t_": self.models[a].t_,
                        "intercept_": self.models[a].intercept_.tolist()
            }

        return attributes.copy()

    def getNumberWeightUpdates(self):
        """Get params of the model."""

        updates = {}
        for a in range(self.numActions):
            updates["action_" + str(a)] = self.models[a].t_

        return updates.copy()

    def displayModelAttributes(self):
        """Display parameters of models."""

        tlog.info("Exploration: epsilon: {}, min epsilon: {}, init epsilon: {}, epsilon decay:{}".format(self.epsilon, self.minEpsilon, self.initEpsilon, self.epsilonDecay))
        tlog.info("Learning rate: {}, learning rate decay:{}".format(self.learningRate, self.learningRateDecay))
        tlog.info("Discount: {}".format(self.discount))

        for a in range(self.numActions):
            tlog.info("Action: {}, n_iter_: {}, t_: {}, intercept_: {}".format(a, self.models[a].n_iter_, self.models[a].t_, self.models[a].intercept_))

class QLinearFALearner(LinearFALearner):
    """ Standard Q-learning with linear FA. """

    def _actionSample(self, mask=None):
        """
        @overwrite
        Draw a uniform random action sample.

        Params
        ------
            mask (list): a list masks the non-applicable action indexes
        Returns
        -------
            index of action chosen randomly
        """

        if mask is None:
            _actions = [i for i in range(self.numActions)]
        else:
            _actions = [i for i in range(self.numActions)]
            _actions = ma.array(_actions, mask = mask)
            _actions = _actions.compressed()
        return np.random.choice(_actions)

    def getAction(self, state, exploration=True, mask=None):
        """
        @overwrite

        Return an action index which correspond to the state.

        Params
        ------
            state (numpy.array): state observation
            exploration (boolean): action selection in exploitation or exploration
            mask (list): a list masks the non-applicable action indexes for
                this state
        Returns
        -------
            index of action
        """

        if exploration:
            if (self.rng.random() <= self.epsilon):
                return self._actionSample(mask)
            else:
                qvalues = self._qValues(state)
                qvalues = ma.array(qvalues, mask = mask)
                return np.argmax(qvalues)
        else:
            qs = self._qValues(state)
            qs = ma.array(qs, mask=mask)
            return np.argmax(qs)

    def batchUpdateWeights(self, sample):
        """
        Update the model weights in batch mode by using the provided sample.

        Params
        ------
            sample (list): list of sample

        Returns
        -------
            average td-error (float)
            episode reward (float)
            episode length (int)
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

        for i in range(episodeLength):
            state = obs[i]
            basename = basenames[i]
            action = actions[i]
            reward = rewards[i]
            done = dones[i]

            if not done:
                nextState = nextObs[i]
            else:
                nextState = None
                # if last command is 'exit_', it means it was a command that
                # we manually input to terminate a session.
                # So the effective is equal to the length of obs - 1
                if basename == 'exit_':
                    episodeLength -= 1

            tdError = self._updateWeights(state, action, reward, \
                                            nextState, done)

            episodeReward += reward
            tdErrors.append(tdError)

        return tdErrors, episodeReward, episodeLength


    def _updateWeights(self, state, action, reward, nextState, done):
        """
        Update the model weight for a single step.

        Params
        ------
            state (numpy.array): state observation
            action (int): action index
            reward (float): reward for taking the action
            nextState (numpy.array): next state observation after taking the
                action
            done (boolean): if we reach the final state
        Returns
        -------
            tdError (float): the td error after updating the model
        """

        q = self._qValue(state, action)

        if not done:
            targetq = reward + self.discount * max(self._qValues(nextState))
        else:
            targetq = reward

        tdError = targetq - q

        self.models[action].partial_fit([state], [targetq])
        return tdError

