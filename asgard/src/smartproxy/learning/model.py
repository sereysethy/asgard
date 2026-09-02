import os
import itertools
from datetime import datetime

import torch
import torch.nn as nn
import numpy as np
import torch.nn.functional as F

from random import choice
from numpy import zeros, dot, outer, exp, clip, ravel, ones, array
from numpy.random import rand, randn

import gym
import math

import sklearn

from sklearn.linear_model import SGDRegressor
from sklearn.kernel_approximation import RBFSampler
from sklearn.pipeline import FeatureUnion
from sklearn.preprocessing import StandardScaler

from smartproxy import tlog

class LinearFunction(nn.Module):
    def __init__(self, numFeatures=None, numActions=None):
        nn.Module.__init__(self)

        self.numActions = numActions
        self.numFeatures = numFeatures
        
        self.models = []
        for i in range(self.numActions):
            model = nn.Linear(self.numFeatures, 1)
            self.models.append(model)

        self.linear = nn.Linear(self.numFeatures, 1)

    def forward(self, x):
        out = self.linear(x)
        return out
    

class LinearFALearner():
    randomInit = True
    
    discount = 0.99 # aka gamma
    
    batchMode = False
    passNextAction = False # for the _updateWeights method
    
    
    learningRate = 0.1      # actual learning rate
    learningRateDecay = 25  # learnig rate decay
    minLearningRate = 0.1   # min initial learning rate
    initLearningRate = 0.1  # initial learning rate
    
    epsilon = 0.2           # exploration probability
    minEpsilon = 0.1        # min exploration probability
    initEpsilon = 0.2       # initiial exploration probability
    epsilonDecay = 25       # exploration probability decay
    
    # default is epsilon greedy exploration
    epsilonGreedy = True
           
    # flags for different modes
    learning = True
    greedy = False
    
    def __init__(self, numFeatures=None, 
                        numActions=None, 
                        scaler=None, 
                        featurizer=None, 
                        learningRate=0.01):
        self.numActions = numActions
        self.numFeatures = numFeatures
        
        self.featurizer = featurizer
        self.scaler = scaler

        self.initLearningRate = learningRate

        self.models = []
        for i in range(self.numActions):
            model = SGDRegressor(learning_rate="constant", max_iter=1, eta0=learningRate, random_state=1)
            
            feature = self.getFeatureSample()
            model.partial_fit([feature], [0])
            self.models.append(model)
            
        self.reset()
    
    def _actionSample(self, actions=None):
        """Draw an action from a uniform distribution."""
        return np.random.choice(actions)

    def _qValue(self, state, action):
        features = self.getFeatures(state)
        q = self.models[action].predict([features])

        return q

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
    
    def getAction(self, state, exploration=True):
        """Return an action given a state."""

        cmdExecStateIndex = state[1]
        
        if cmdExecStateIndex == 0: #start to execute
            possibleActions = [0, 1, 2]
        else: # for running commands
            possibleActions = [3, 4]
            
        if exploration:
            if (np.random.random() < self.epsilon):
                return self._actionSample(possibleActions)
            else:
                return np.argmax(self._qValues(state, possibleActions))
        else:
            return np.argmax(self._qValues(state, possibleActions))
    
    def reset(self):
        """Prepare the model to start learning by initialising hyper params."""

        tlog.info("reset hyper-parameters")
        self._callcount = 0
        
        self.epsilon = self.initEpsilon
        self.learningRate = self.initLearningRate

        tlog.info("epsilon: {}, min epsilon: {}, init epsilon: {}, epsilon decay:{}".format(self.epsilon, self.minEpsilon, self.initEpsilon, self.epsilonDecay))
        tlog.info("lr: {}, lr decay:{}".format(self.learningRate, self.learningRateDecay))
        tlog.info("discount: {}".format(self.discount))

    def newEpisode(self):
        """Start a new episode."""

        self._callcount += 1
        
        self.epsilon = max(self.minEpsilon, self.epsilon * self.epsilonDecay)
        #self.learningRate = self.learningRate * self.learningRateDecay
        
        #self.epsilon = max(self.minEpsilon, min(1., 1. - math.log10((self._callcount + 1) / self.epsilonDecay)))
        #self.learningRate = max(self.minLearningRate, min(1., 1. - math.log10((self._callcount + 1) / self.learningRateDecay)))

    def getFeatureSample(self):
        return np.random.random(self.numFeatures)

    def getFeatures(self, obs):
        """Transform a given obs to a feature using a transformer."""

        if self.scaler and self.featurizer:
            scaled = self.scaler.transform([obs])
            featurized = self.featurizer.transform(scaled)
            return featurized[0]
        else:
            return obs
    
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


class Q_LinFA(LinearFALearner):
    """ Standard Q-learning with linear FA. """
    
    def train(self, episode):
        obs     = episode['obs']
        actions = episode['actions']
        rewards = episode['rewards']
        dones   = episode['dones']
        nextObs = episode['next_obs']

        tdErrors = []
        qs = []
        targetqs = []

        tdErrorsByAction = {}
        qsByAction = {}
        targetqsByAction = {}

        for i in range(len(obs)):
            state = obs[i]
            action = actions[i]
            reward = rewards[i]
            done = dones[i]
            
            if not done:
                nextState = nextObs[i]
            else:
                nextState = None

            error, q, targetq = self._updateWeights(state, action, reward, \
                                            nextState, done)

            tdErrors.append(error)
            qs.append(q)
            targetqs.append(targetq)

            if action in tdErrorsByAction:
                tdErrorsByAction[action].append(error)
                qsByAction[action].append(q)
                targetqsByAction[action].append(targetq)
            else:
                tdErrorsByAction[action] = [error]
                qsByAction[action] = [q]
                targetqsByAction[action] = [targetq]
        
        metric = {
            'td_errors': tdErrors,
            'qs': qs,
            'targetqs': targetqs,
            'td_errors_by_action': tdErrorsByAction,
            'qs_by_action': qsByAction,
            'targetqs_by_action': targetqsByAction
        }

        return metric

    def _updateWeights(self, state, action, reward, nextState, done):
        q = self._qValue(state, action)
        features = self.getFeatures(state)

        if done:
            targetq = [reward]
        else:
            targetq = reward + self.discount * max(self._qValues(nextState))
        
        tdError = targetq - q
        
        self.models[action].partial_fit([features], targetq)
        return tdError[0], q[0], targetq[0]
