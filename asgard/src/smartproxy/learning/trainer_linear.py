import os
import itertools
from os.path import isfile, join
import json
import argparse
from datetime import datetime

from twisted.internet import reactor, defer
from twisted.python import log

import numpy as np
import gym

import sklearn
from sklearn.linear_model import SGDRegressor
from sklearn.kernel_approximation import RBFSampler
from sklearn.pipeline import FeatureUnion
from sklearn.preprocessing import StandardScaler
from joblib import dump, load

from cowrie.core.config import CowrieConfig

from smartproxy.ssh.factory import SSHClientFactory
from smartproxy.command.shell_linear import ShellLinear as Shell
from container_pool.container import DockerContainer
from smartproxy.learning.attacker import AttackerEmulator
from smartproxy.learning.model import Q_LinFA
from smartproxy.utils import utils
from smartproxy import tlog
from smartproxy.metric.metric import Metric

np.seterr('raise')

parser = argparse.ArgumentParser()

parser.add_argument("--folder", type=str, help="folder containing sample files to do scaling/RBF transform", required=True)
parser.add_argument("--checkpoint-folder", type=str, help="loading model from a checkpoint folder", required=False)
parser.add_argument("--checkpoint-file", type=str, help="file to load model from", required=False)
parser.add_argument("--episode-file", type=str, help="file to load attacker command episodes", required=False)

sample_path = os.path.join("data", "sample")
model_path = os.path.join("data", "model")
result_path = os.path.join("data", "results")

# create a new folder to store trained model
now = datetime.today().strftime("%Y-%m-%d_%H%M%S")
model_dir_path = os.path.join(model_path, now)
os.mkdir(model_dir_path, 0o755)

# create a new folder to store trained samples
sample_dir_path = os.path.join(sample_path, now)
os.mkdir(sample_dir_path, 0o755)

# create a new folder to store results
result_dir_path = os.path.join(result_path, now)
os.mkdir(result_dir_path, 0o755)

# for reproducibility
seed = 42

np.random.seed(seed)

# global variables
username = CowrieConfig().get('proxy', 'backend_user')
password = CowrieConfig().get('proxy', 'backend_pass')
server = CowrieConfig().get('proxy', 'backend_ssh_host')
port = CowrieConfig().getint('proxy', 'backend_ssh_port')

agent = None
checkpoint = 100
samples = []
i_episode = 0
lastEpisode = 0
container = None
config = {}
metric = None

def save_last_run():
    filename = "last_run_file"
    with open(filename, "w") as outfile:
        outfile.write(model_dir_path)

def save_config(episode):
    global config
    global i_episode
    global agent

    pathname = os.path.join(model_dir_path, str(episode) + ".json")
    tlog.info(f"save config to: {pathname}")

    config["lastEpisode"] = i_episode
    config["epsilon"] = agent.epsilon
    config["counter"] = agent._callcount

    with open(pathname, "w") as infile:
        json.dump(config, infile)

def load_config(folder, filename="config.json"):
    global config

    pathname = os.path.join(folder, filename)
    tlog.info(f"load config from: {pathname}")
    with open(pathname, "r") as infile:
        config = json.load(infile)

def load_sample_from_file(folder):
    # load sample to do train scaler and transformer
    folder_path = os.path.join(sample_path, folder)
    samples = []
    for f in os.listdir(folder_path):
        filename = os.path.join(sample_path, folder, f)
        if isfile(filename):
            tlog.info(f"loading sample from file: {filename}")
            with open(filename) as infile:
                for line in infile:
                    episode = json.loads(line)
                    samples += episode['obs']

    return samples

def _cbContainerStartedSuccess(c):
    global container
    global username, password
    global attacker
    global i_episode

    log.msg("Container started successfully")
    username, password = attacker.getCredential()
    createuser_ok = container.usermod(username.encode(), password.encode())
    if not createuser_ok:
        container.stop()
        container = None
        i_episode -= 1
        train()
    else:
        ip, port = container.getNetworkInfo()
        print(ip, port, container.id())
        print(username, password)
        connect_to_backend(ip, port)

def _cbContainerStartedError(reason):
    global container

    log.msg("Container failed to start, disconnect everything")
    log.msg('reason: ', reason)
    if container:
        container.stop()
        container = None
    i_episode -= 1
    train()

def plot_result_checkpoint():
    global metric
    global checkpoint

    # checkpoint
    utils.plot_xy(x=metric.checkpoint["episode_numbers"], y=metric.checkpoint["mean_rewards"], x_label="episode", y_label="Mean rewards", title="Mean rewards", folder=result_dir_path, filename="checkpoint_mean_rewards")

    utils.plot_xy(x=metric.checkpoint["episode_numbers"], y=metric.checkpoint["mean_rewards_last_checkpoint"], x_label="episode", y_label="Mean rewards per checkpoint " + str(checkpoint), title="Mean rewards", folder=result_dir_path, filename="checkpoint_mean_rewards_last_checkpoint")

    utils.plot_xy(x=metric.checkpoint["episode_numbers"], y=metric.checkpoint["mean_episode_lengths"], x_label="episode", y_label="Mean episode length", title="Mean episode length", folder=result_dir_path, filename="checkpoint_mean_episode_lengths")

    utils.plot_xy(x=metric.checkpoint["episode_numbers"], y=metric.checkpoint["mean_td_errors"], x_label="Episode", y_label="Mean TD-error", title="Mean TD-error", folder=result_dir_path, filename="checkpoint_mean_td_error")

    utils.plot_xy(x=metric.checkpoint["episode_numbers"], y=metric.checkpoint["mean_q_values"], x_label="Episode", y_label="Mean Q-values", title="Mean Q-values", folder=result_dir_path, filename="checkpoint_mean_q_values")

    utils.plot_xy(x=metric.checkpoint["episode_numbers"], y=metric.checkpoint["mean_targetq_values"], x_label="episode", y_label="Mean Target Q-values", title="Mean Target Q-values", folder=result_dir_path, filename="checkpoint_mean_targetq_values")

    utils.subplots_checkpoint_mean(metric, result_dir_path, "checkpoint_means_td_q_targetq")

def plot_result_data():
    global metric

    utils.plot_xy(x=metric.data["episode_numbers"], y=metric.data["total_time_steps_per_episode"], x_label="Episode", y_label="Total time steps", title="Total time steps", folder=result_dir_path, filename="data_total_time_steps_per_episode")

    utils.plot_xy(x=metric.data["episode_numbers"], y=metric.data["episode_lengths"], x_label="Episode", y_label="Episode length", title="Episode length", folder=result_dir_path, filename="data_episode_length")

    utils.plot_xy(x=metric.data["episode_numbers"], y=metric.data["exploration_epsilon"], x_label="Episode", y_label="epsilon", title="Exploration", folder=result_dir_path, filename="data_exploration_epsilon")

    utils.subplots_per_action(metric, 0, 'Allow', result_dir_path, "data_action_0_allow")
    utils.subplots_per_action(metric, 1, 'Block', result_dir_path, "data_action_1_block")
    utils.subplots_per_action(metric, 2, 'Substitute', result_dir_path, "data_action_2_substitute")
    utils.subplots_per_action(metric, 3, 'Terminate', result_dir_path, "data_action_3_terminate")
    utils.subplots_per_action(metric, 4, 'Idle', result_dir_path, "data_action_4_idle")

    utils.subplots_actions(metric, result_dir_path, "data_update_iteration")
    
    utils.subplots_per_action_timestep(metric, 0, 'Allow', result_dir_path, "timestep_action_0_allow")
    utils.subplots_per_action_timestep(metric, 1, 'Block', result_dir_path, "timestep_action_1_block")
    utils.subplots_per_action_timestep(metric, 2, 'Substitute', result_dir_path, "timestep_action_2_substitute")
    utils.subplots_per_action_timestep(metric, 3, 'Terminate', result_dir_path, "timestep_action_3_terminate")
    utils.subplots_per_action_timestep(metric, 4, 'Idle', result_dir_path, "timestep_action_4_idle")

    utils.subplots_all_actions(metric, result_dir_path, "data_q_values_all_actions")
    utils.subplots_all_mean_q_actions(metric, result_dir_path, "data_mean_q_values_all_actions")
    utils.subplots_all_mean_td_error_actions(metric, result_dir_path, "data_mean_td-error_all_actions")
    utils.subplots_all_mean_targetq_actions(metric, result_dir_path, "data_mean_targetq_all_actions")

def connect_to_backend(ip, port):
    global container
    global shell

    deferred = defer.Deferred()
    deferred.addCallback(_cbnext)
    deferred.addErrback(_eberror)
    shell = Shell(deferred=deferred,
               container_name=container.id(),
               simulated=False)
    shell.setAgent(agent)
    shell.setAttacker(attacker)
    sshClientfactory = SSHClientFactory(shell=shell, 
                                        username=username,
                                        password=password,
                                        container=container)
    reactor.connectTCP(ip, port, sshClientfactory)

def save_samples(episode):
    global samples
    global sample_path
    
    pathname = os.path.join(sample_dir_path, str(episode) + ".json")

    tlog.info(f"checkpoint: {episode}, dumping sample to file {pathname}")
    
    with open(pathname, 'w') as outfile:
        for s in samples:
            outfile.write(json.dumps(s) + '\n')

def save_model(episode):
    global model_dir_path
    global agent
    
    pathname = os.path.join(model_dir_path, str(episode) + ".joblib")

    tlog.info(f"checkpoint: {episode}, dumping agent model to file {pathname}")
    dump(agent, pathname)

def load_model(folder, filename):
    pathname = os.path.join(folder, filename)

    tlog.info(f"loading agent model from file {pathname} at checkpoint {filename}")
    return load(pathname)


def train():
    global i_episode
    global container
    global agent
    global current_episode

    # start a new episode of attack
    done, i, current_episode = attacker.reset()

    if not done:
        i_episode += 1
        log.msg(f"Training for episode #{i_episode}, filename: {current_episode['filename']}, session: {current_episode['session']}")
        deferred = defer.Deferred()
        deferred.addCallback(_cbContainerStartedSuccess)
        deferred.addErrback(_cbContainerStartedError)
        container = DockerContainer(deferred)

        container.start()
    else:
        reactor.stop()

def calculateReward(thisepisode):
    return np.mean(thisepisode["rewards"])

def updateMetric(m, t, sample):
    """
    Args:
        m (dict): a dictionary containing a current metric for this episode
        t (int): a time step for this episode

    Returns:
        None
    """

    global current_episode
    global metric
    global agent

    session = current_episode["session"]
    filename = current_episode['filename']

    metric.data["session"].append(session)
    metric.data["filename"].append(filename)

    episode_reward = calculateReward(sample)

    metric.data["total_time_steps"] += t
    metric.data["total_time_steps_per_episode"].append(metric.data["total_time_steps"])
    
    for i in m['td_errors_by_action']:
        metric.data["td_errors_by_action"][i] += m['td_errors_by_action'][i]
        metric.data["q_values_by_action"][i] += m['qs_by_action'][i]
        metric.data["targetq_values_by_action"][i] += m['targetqs_by_action'][i]


        metric.data["mean_td_errors_by_action"][i].append(np.mean(m['td_errors_by_action'][i]))
        metric.data["mean_q_values_by_action"][i].append(np.mean(m['qs_by_action'][i]))
        metric.data["mean_targetq_values_by_action"][i].append(np.mean(m['targetqs_by_action'][i]))

        metric.data["episode_number_by_action"][i].append(i_episode)

    metric.data["mean_td_errors"].append(np.mean(m['td_errors']))
    metric.data["mean_q_values"].append(np.mean(m['qs']))
    metric.data["mean_targetq_values"].append(np.mean(m['targetqs']))

    metric.data["episode_rewards"].append(episode_reward)
    metric.data["episode_lengths"].append(t)
    metric.data["episode_numbers"].append(i_episode)

    metric.data["model_attributes_all"].append(agent.getAttributes())
    updates = agent.getNumberWeightUpdates()
    metric.data["model_attributes"]["action_0"].append(updates["action_0"])
    metric.data["model_attributes"]["action_1"].append(updates["action_1"])
    metric.data["model_attributes"]["action_2"].append(updates["action_2"])
    metric.data["model_attributes"]["action_3"].append(updates["action_3"])
    metric.data["model_attributes"]["action_4"].append(updates["action_4"])
    metric.data["exploration_epsilon"].append(agent.epsilon)

def updateMetricPerCheckpoint():
    global metric
    global i_episode
    global checkpoint

    metric.checkpoint["mean_rewards"].append(np.mean(metric.data["episode_rewards"]))
    metric.checkpoint["mean_rewards_last_checkpoint"].append(np.mean(metric.data["episode_rewards"][i_episode - checkpoint:]))
    metric.checkpoint["episode_numbers"].append(i_episode)
    metric.checkpoint["mean_td_errors"].append(np.mean(metric.data["mean_td_errors"]))
    metric.checkpoint["mean_q_values"].append(np.mean(metric.data["mean_q_values"]))
    metric.checkpoint["mean_targetq_values"].append(np.mean(metric.data["mean_targetq_values"]))
    metric.checkpoint["mean_episode_lengths"].append(np.mean(metric.data["episode_lengths"]))

    i = len(metric.checkpoint["episode_numbers"])
    
    tlog.info("Checkpoint at episode: {}, " \
            "TD-error: {:0.4f}, Mean reward: {:0.2f}, " \
            "Mean step:{:0.2f}, Last Mean rewards {:0.2f}/{}".format(
                i_episode,
                metric.checkpoint["mean_td_errors"][i-1],
                metric.checkpoint["mean_rewards"][i-1], 
                metric.checkpoint["mean_episode_lengths"][i-1],
                metric.checkpoint["mean_rewards_last_checkpoint"][i-1],
                checkpoint
            ))


def _cbnext(result):
    global shell, container
    global i_episode
    global samples
    global metric
    global current_episode
    global agent

    if container:
        container.stop()
        container = None

    if shell:
        sample = shell.getSample()
        
        if sample:
            samples.append(sample)
            thisMetric = agent.train(sample)

            # number actions taken = length of episode
            t = len(sample["actions"])

            updateMetric(thisMetric, t, sample)

            if i_episode % checkpoint == 0:
                updateMetricPerCheckpoint()

                save_samples(i_episode)
                save_model(i_episode)
                save_config(i_episode)
                metric.save(folder=model_dir_path, data_filename="metric_data_" + str(i_episode) + ".joblib", checkpoint_filename="metric_checkpoint_" + str(i_episode) + ".joblib")

                samples = []

            agent.newEpisode()
        else:
            i_episode -= 1

    shell = None

    train()

def _eberror(exception):
    global shell, container
    global i_episode, current_episode

    log.msg(str(exception))
    tlog.error(str(exception))
    tlog.error("session number: {}, filename: {}".format(current_episode["session"], current_episode["filename"]))

    if container:
        container.stop()
        container = None
        i_episode -= 1
        shell = None
    train()

if __name__ == "__main__":
    args = parser.parse_args()

    config = {
            "epsilonGreedy": True,
            "minEpsilon": 0.01,
            "initEpsilon": 1,
            "epsilon": 0.0,
            "counter": 0,
            "epsilonDecay": 0.99991,
            "minLearningRate": 0.01,
            "initLearningRate": 0.01,
            "discount": 0.99
        }
                    
    # create attacker enumator that will make connection and input command
    attacker = AttackerEmulator()
    if args.episode_file:
        attacker.loadAttackEpisodesByFilename(args.episode_file)
    else:
        attacker.loadTestAttackEpisodes()
        #attacker.loadAttackEpisodes()

    samples = []
    container = None
    number_features = 400
    number_actions = 5
    
    if args.checkpoint_folder and args.checkpoint_file:
        tlog.info("#### Resume A Training ####")
        agent = load_model(args.checkpoint_folder, args.checkpoint_file)
        agent.displayModelAttributes()
        metric = Metric()
        metric.load(folder=args.checkpoint_folder, data_filename="metric_data.joblib", checkpoint_filename="metric_checkpoint.joblib")
        load_config(folder=args.checkpoint_folder, filename="config.json")
        lastEpisode = config["lastEpisode"]
        tlog.info("continued from last episode: {}".format(lastEpisode))
        i_episode = lastEpisode
    else:
        tlog.info("#### Start A Training ####")
        samples = load_sample_from_file(args.folder)
        # create a scaler, need some samples first
        scaler = sklearn.preprocessing.StandardScaler()
        scaler.fit(samples)

        # create a transformer that consists of 400 components of RBF kernels
        featurizer = sklearn.pipeline.FeatureUnion([
                ("rbf1", RBFSampler(gamma=5.0, n_components=100)),
                ("rbf2", RBFSampler(gamma=2.0, n_components=100)),
                ("rbf3", RBFSampler(gamma=1.0, n_components=100)),
                ("rbf4", RBFSampler(gamma=0.5, n_components=100))
                ])
        featurizer.fit(scaler.transform(samples))
        
        metric = Metric(numActions=number_actions)
        agent = Q_LinFA(numFeatures=number_features,
                        numActions=number_actions, 
                        scaler=scaler,
                        featurizer=featurizer,
                        learningRate=config["initLearningRate"])
        
        agent.epsilonGreedy = config["epsilonGreedy"]
        agent.minEpsilon = config["minEpsilon"]
        agent.initEpsilon = config["initEpsilon"]
        agent.epsilonDecay = config["epsilonDecay"]
        
        agent.initLearningRate = config["initLearningRate"]
        agent.discount = config["discount"]
        i_episode = 0
        agent.reset()

    reactor.callWhenRunning(train)
    reactor.run()

    agent.displayModelAttributes()
    save_samples("sample")
    save_model("model")
    
    save_config("config")
    metric.save(folder=model_dir_path)
    save_last_run()
    agent = None
    shell = None
    
    plot_result_checkpoint()
    plot_result_data()
