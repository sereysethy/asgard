from twisted.python.log import NullFile
from smartproxy.learning.environment.simple import SimpleAtackerEnvV12
from smartproxy.learning.rl.valuebase import QLearner
from joblib import dump, load
import json
import os
from os.path import join
from smartproxy import tlog
import csv
import numpy as np

oldEnv = None
newEnv = None
oldAgent = None
newAgent = None

def loadModel(path):
    return load(path)

def setupNewModel():
    # new agent model
    env = SimpleAtackerEnvV12()
    numActions = env.action_space.n
    numFeatures = env.observation_space.n
    agent = QLearner(numActions=numActions, numFeatures=numFeatures)

    return agent, env

def loadqvalues(path):
    qvalues = {} 
    with open(path, newline='') as csvfile:
        qvaluereader = csv.reader(csvfile, delimiter=',', quotechar='|')
        next(qvaluereader, None)  # skip the headers
        for row in qvaluereader:
            qvalues[row[0]] = [float(x) for x in row[1:]]

    # if os.path.isfile(path):
    #     tlog.info(f"Last model found: {path}")
    #     env = SimpleAtackerEnvV12()
    #     agent = self.loadModel(path)
    # else:
    #     raise FileNotFoundError("Model file not found")

    # return agent, env

    return qvalues

def migrate(qvalues, oldagent, newagent, env):
    for key in qvalues:
        if key in env.COMMAND_TO_IX:
            index = env.COMMAND_TO_IX[key]
            newagent.models[index] = qvalues[key]
        elif key == env.MARKOV_STATE_EMPTY:
            newagent.models[env.EMPTY_COMMAND_IX] = qvalues[key]
        elif key == env.MARKOV_STATE_CUSTOM:
            newagent.models[env.CUSTOM_COMMAND_IX] = qvalues[key]
        elif key == env.MARKOV_STATE_UNKNOWN:
            newagent.models[env.UNKNOWN_COMMAND_IX] = qvalues[key]
        else:
            print("command: `{}' not found".format(key))

    # migrate hyper parameters
    newagent.initEpsilon = oldagent.initEpsilon
    newagent.minEpsilon = oldagent.minEpsilon
    newagent.epsilonDecay = oldagent.epsilonDecay
    
    newagent.initLearningRate = oldagent.initLearningRate
    newagent.minLearningRate = oldagent.minLearningRate
    newagent.learningRateDecay = oldagent.learningRateDecay
    newagent.learningRate = oldagent.learningRate
    
    newagent.discount = oldagent.discount
    newagent.epsilon = oldagent.epsilon
    newAgent._callcount = oldagent._callcount

def writeQValues(path, agent, env):
    """
    This will write q-values to file at location indicated by path

    @param path: q-values file
    @param agent: agent
    @param env: environment
    """
    print("write q-values to file: ", path)
    csvfile = open(path, 'w', newline='')
    csvwriter = csv.writer(csvfile, dialect='excel')
    
    csvwriter.writerow(["command", "allow", "block", "substitute"])
    for cmdIndex in range(len(agent.models)):
        cmd = env.ALL_COMMANDS[cmdIndex]
        csvwriter.writerow([cmd] + agent.models[cmdIndex])

    csvfile.close()

def saveModel(path, agent):
    print("Dump model to: ", path)
    dump(agent, path)

qpath = "var/train_result/models/20210915-151456/q-values_302.csv"
mpath = "var/train_result/models/20210915-151456/model_302.joblib"
newmodelpath = "var/train_result/models/20210915-151456/new_model_302.joblib"
qnewpath = "var/train_result/models/20210915-151456/new_q-values_302.csv"

qvalues = loadqvalues(qpath)
oldAgent = loadModel(mpath)
newAgent, newEnv = setupNewModel()

migrate(qvalues, oldAgent, newAgent, newEnv)

print("Init epsilon: ", newAgent.initEpsilon)
print("Min. epsilon: ", newAgent.minEpsilon)
print("Decayed epsilon: ", newAgent.epsilonDecay)
print("epsilon: ", newAgent.epsilon)

print("Learning rate: ", newAgent.learningRate)
print("Init. learning rate: ", newAgent.initLearningRate)
print("Min. learning rate: ", newAgent.minLearningRate)
print("Decayed learning rate: ", newAgent.learningRateDecay)

print("Discount: ", newAgent.discount)
print("_callcount: ", newAgent._callcount)

# At this point everything should be transferred from old agent to the new agent

# To update hyper parameters, it should be done here
newAgent.epsilonDecay = 0.996

# New hyper parameters
print("============")
print("Init epsilon: ", newAgent.initEpsilon)
print("Min. epsilon: ", newAgent.minEpsilon)
print("Decayed epsilon: ", newAgent.epsilonDecay)
print("epsilon: ", newAgent.epsilon)

print("Learning rate: ", newAgent.learningRate)
print("Init. learning rate: ", newAgent.initLearningRate)
print("Min. learning rate: ", newAgent.minLearningRate)
print("Decayed learning rate: ", newAgent.learningRateDecay)

print("Discount: ", newAgent.discount)
print("_callcount: ", newAgent._callcount)

# Write new model and q-values in csv file 
saveModel(newmodelpath, newAgent)
writeQValues(qnewpath, newAgent, newEnv)