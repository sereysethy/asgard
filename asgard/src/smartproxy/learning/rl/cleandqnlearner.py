import time
import random
from datetime import datetime
from os import path
import json
import shutil

# ML library
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
import joblib

import numpy as np
import numpy.ma as ma
import gymnasium as gym
from numpy.random import default_rng

from twisted.internet import reactor

# Cowrie module
from cowrie.core.config import CowrieConfig

# custom library
from smartproxy.learning.rl.base import BaseLearner
from smartproxy import tlog, log
from stable_baselines3.common.buffers import ReplayBuffer
from smartproxy.learning.rl.dqn import QNetwork
from .dqnlogger import DQNMetricLogger

def linear_schedule(start_e: float, end_e: float, duration: int, t: int):
    slope = (end_e - start_e) / duration
    return max(slope * t + start_e, end_e)

class CleanDQNLearner(BaseLearner):
    """Deep Q-Learning (DQN)

    The implementation of the DQN was adapted from the original implementation
    of `CleanRL <https://github.com/vwxyzjn/cleanrl/blob/master/cleanrl/dqn.py>`_.

    The changes made to the original implementations:

    - The update of the targe network's weights where soft update was \
    included. The soft update was inspired by `PyTorch tutorial \
    <https://pytorch.org/tutorials/intermediate/reinforcement_q_learning.html>`_.
    - Use Huber loss instead of MSE
    - Tensorboard integration

    Args:
        numFeatures: Number of input features that represents the state
            observation.
        numActions: Number of actions.
        model_dir: Dictory to save/restore the model.
        tensorboard_dir: Directory to store tensorboard data.
        cuda: Enable cuda if GPU is avaialble. Default value is ``False``.
        debug: Run in debug mode. Default value is ``False``.

    Attributes:
        total_timesteps:

        learning_rate: The learning rate of the ``AdamW`` optimizer.
            Default value is ``1e-4``.

        buffer_size: size of buffer replay memory.
            Default value is set to ``10000``.

        gamma: This is a discount factor :math:`\gamma` to weight immediate
            and long-term rewards received when taking actions.
            Its default value is set to ``0.99``.

        tau: :math:`\\tau` is the update rate of the target network, its
            defautl value is set to ``0.0004``.

            .. note::

                :math:`\\tau` must be set to ``1`` if ``train_frequency`` is
                large like ``10``.

        target_network_frequency: Set the frequency of how often the target
            network should be updated. Default value is ``100``.

        batch_size: The number of transitions sampled from the replay buffer.
            Default value is ``128``.

        start_e: The starting value of epsilon. Default value is ``0.9``.

        end_e: The final value of epsilon. Default value is ``0.05``.

        epsilon_decay: It controls the rate of exponential decay of epsilon,
            higher means a slower decay. Default value is ``0.4``.

        learning_starts: Set the number of calls before the networks start
            to update. Default value is ``200``.

        train_frequency: int = 10

        hidden_layer: Set number of neuron of the hidden layer of the Q-network.
            Default value is ``128``.

        save_every: Set the frequency of saving the model. Default value is ``50``.

        log_every: Set the frequncy of logging learning data to tensorboard.
            Defalut value is ``100``.

        batchTraining: Turns off the tabular training. The value is always set
            to ``False``.

        callcount: Number of calls. It is updated for each action interference.

        global_step: Number of global step.
    """

    # Initialize parameters
    total_timesteps: int = 10000
    # LR is the learning rate of the ``AdamW`` optimizer
    learning_rate: float = 1e-4
    # Size of buffer replay memory
    buffer_size: int = 10000
    # GAMMA is the discount factor as mentioned in the previous section
    gamma: float = 0.99
    # TAU is the update rate of the target network
    tau: float = 0.0004 # 1 if train_frequency is large like 10 ?
    target_network_frequency: int = 100
    # BATCH_SIZE is the number of transitions sampled from the replay buffer
    batch_size: int = 128
    # EPS_START is the starting value of epsilon
    start_e: float = 0.9
    # EPS_END is the final value of epsilon
    end_e: float = 0.05
    # EPS_DECAY controls the rate of exponential decay of epsilon, higher means a slower decay
    epsilon_decay: float = 0.4

    learning_starts: int = 200
    train_frequency: int = 10

    hidden_layer: int = 128

    # to save the model checkpoints
    save_every: int = 50
    log_every: int = 100

    # not like tabular models, the training is on going
    batchTraining: bool = False

    callcount: int
    global_step: int

    def __init__(self, numFeatures:int, numActions:int, model_dir: str, tensorboard_dir: str, cuda:bool=False, debug: bool=False)->None:

        self.debug = debug

        self.numFeatures = numFeatures
        self.numActions = numActions
        self.model_dir = model_dir
        self.tensorboard_dir = tensorboard_dir

        self.global_actions: list[int] = []

        # enable cuda
        if cuda:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device("cpu")

        self.q_network = QNetwork(self.numFeatures, self.numActions, self.hidden_layer).to(self.device)
        self.target_network = QNetwork(self.numFeatures, self.numActions, self.hidden_layer).to(self.device)
        self.target_network.load_state_dict(self.q_network.state_dict())
        self.optimizer = optim.AdamW(self.q_network.parameters(), lr=self.learning_rate, amsgrad=True)

        self.params: dict = {
            "total_timesteps": self.total_timesteps,
            "learning_rate": self.learning_rate,
            "buffer_size": self.buffer_size,
            "gamma": self.gamma,
            "tau": self.tau,
            "target_network_frequency": self.target_network_frequency,
            "batch_size": self.batch_size,
            "start_e": self.start_e,
            "end_e": self.end_e,
            "epsilon_decay": self.epsilon_decay,
            "learning_starts": self.learning_starts,
            "train_frequency": self.train_frequency,
            "hidden_layer": self.hidden_layer,
            "save_every": self.save_every,
            "log_every": self.log_every
        }

        self.metriclogger = DQNMetricLogger()

        self.start_time = time.time()

    def reset(self)->None:
        """
        Initiliaze some parameters such as `callcount`, `espsilon` and
        `global_step`. The method has to be called ``once`` right after
        the agent is created.
        """

        self.callcount = 0
        self.epsilon = self.start_e
        self.global_step = 0

        # keep track of the number of actions taken
        self.global_actions = [0 for i in range(self.numActions)]

    def newEpisode(self)->None:
        """
        Call after an episode ends. This will decay the learning rate and
        exploration probability, in according to the chosen policy.

        This also logs the current epsilon and learning rate to tensorboard.
        """
        # track the number of episodes
        self.callcount += 1

        self.epsilon = max(self.end_e, self.epsilon * self.epsilon_decay)

        # tensorboard: epsilon and learning rate gradually reduced per episode
        self.metriclogger.write_hyper_epsilon("hyperparameters/epsiode/epsilon", self.callcount, self.epsilon)
        self.metriclogger.write_hyper_lr("hyperparameters/epsiode/learning_rate", self.callcount, self.learning_rate)

    def createMemory(self)->None:
        """
        To create a memory buffer using `ReplayBuffer`, this is a separate call because the
        ``buffer_size`` can be varied.
        """

        self.memory = ReplayBuffer(
            self.buffer_size,
            gym.spaces.Box(-1, 1, shape=(self.numFeatures,), dtype=np.float32),
            gym.spaces.Discrete(self.numActions),
            self.device,
            handle_timeout_termination=False,
        )

    def _actionSample(self, mask:list[int]=None)->int:
        """
        Draw a uniform random action sample.

        .. note::
           This method overrides :func:`smartproxy.learning.rl.base.BaseLearner._actionSample`

        Args:
            mask: a list masks the non-applicable action indexes

        Returns:
            index of action chosen randomly
        """
        if mask:
            _actions = [i for i in range(self.numActions)]
            _actions = ma.array(_actions, mask = mask)
            _actions = _actions.compressed()
        else:
            _actions = [i for i in range(self.numActions)]

        return np.random.choice(_actions)

    def getAction(self, obs: np.array, exploration: bool = True, \
                    mask:list[int] = None)->np.int64:
        """
        Return an action index which correspond to the state ``obs``.

        .. note::
           This method overrides :func:`smartproxy.learning.rl.base.BaseLearner.getAction`

        Args:
            obs: A state observation
            exploration: action selection in exploitation or exploration
            mask: a list masks the non-applicable action indexes for
                this state
        Returns:
            index of action
        """

        self.global_step += 1

        state = torch.tensor(obs, dtype=torch.float32, device=self.device).unsqueeze(0)
        sample = random.random()

        # self.epsilon = self.start_e + (self.start_e - self.end_e) * \
        #                 math.exp(-1. * self.global_step / self.epsilon_decay)
        # self.epsilon = linear_schedule(self.start_e, self.end_e,
        #                                 self.epsilon_decay * self.total_timesteps,
        #                                 self.global_step)

        # if self.global_step % self.log_every == 0:
        #     self.metriclogger.write_hyper_epsilon("hyperparameters/step/epsilon", self.global_step, self.epsilon)
        #     self.metriclogger.write_hyper_lr("hyperparameters/step/learning_rate", self.global_step, self.learning_rate)
        self.doTraining()
        with torch.no_grad():
            if exploration:
                if (sample < self.epsilon):
                    action = self._actionSample(mask)
                else:
                    q_values = self.q_network(state).cpu().numpy()
                    if self.debug:
                        log.info(f"unmasked q_values: {q_values}")
                    q_values = ma.array(q_values, mask = mask)
                    if self.debug:
                        log.info(f"masked q_values: {q_values}")
                    action = np.argmax(q_values)
            else:
                q_values = self.q_network(state).cpu().numpy()
                q_values = ma.array(q_values, mask = mask)
                if self.debug:
                    log.info(f"masked q_values: {q_values}")
                action = np.argmax(q_values)

        # increment the count of the selected action
        self.global_actions[action] += 1

        # tensorboard
        if self.global_step % self.log_every == 0:
            self.metriclogger.write_action(self.global_step, self.global_actions)
            self.metriclogger.write_action_params(self.global_step, action, obs)

        return action

    def pushSampleToMemory(self, sample)->None:
        """
        Exposed function that will be called when a sample is collected, the
        sample is then pushed to memory buffer.

        Args:
            sample: A tuple containing a sample of `state`, `action`,
                `next_state` and `reward`.
        """

        state, action, next_state, reward, terminated, info = sample
        # when next_state is None, it means we reach the final state
        # but we will save it as a numpy array of 0 vector to avoid having to
        # converting nan to 0 when passing it through the network;
        # it will not be used in the calculation of the next state.
        if next_state is None:
            next_state = np.zeros(self.numFeatures)
        self.memory.add(state, next_state, action, reward, terminated, info)

    def doTraining(self)->None:
        """
        Trigger the training process. The training only starts after
        the `global_step` is greater than `learning_starts`.

        Once the training starts, the policy network is updated at every call.
        But the target network can be updated either via a soft update or
        at a fix :math:`\\tau` rate if `target_network_frequency` is set to
        ``0``.

        The models are saved every `save_every` step(s).
        """

        if self.debug:
            log.info("do training")

        if self.global_step > self.learning_starts:
            if self.debug:
                tlog.info(f"global step: {self.global_step}")
            # Perform one step of the optimization (on the policy network)
            self._optimizeModel()

            # The target network is updated at (1) every step with a soft
            # update controlled by the hyperparameter TAU or (2) every
            # `target_network_frequency`, which was previously
            # defined.
            if self.global_step % self.target_network_frequency == 0:
                for target_network_param, q_network_param in zip(self.target_network.parameters(), self.q_network.parameters()):
                    target_network_param.data.copy_(
                        self.tau * q_network_param.data + (1.0 - self.tau) * target_network_param.data
                    )

        if self.global_step % self.save_every == 0:
            self.save()

    def _optimizeModel(self):
        """
        Update the target Q-network's weights.
        It performs a single step of the optimization. It first samples a batch,
        concatenates all the tensors
        into a single one, computes :math:`Q(s_t,a_t)` and
        :math:`V(s_{t+1})=max_a Q(s_{t+1},a)`, and combines them into our loss.

        By definition we set :math:`V(s)=0` if `s` is a terminal state.
        We also use a target network to compute :math:`V(s_{t+1})` for added
        stability.
        """

        if self.global_step > self.learning_starts:
            if self.global_step % self.train_frequency == 0:
                data = self.memory.sample(self.batch_size)
                with torch.no_grad():
                    # calculate the next target q-values of the next obs
                    target_q_values = self.target_network(data.next_observations)
                    # masking the values whose actions were not in the selected
                    # action group.
                    target_q_values_masked = self.masked_q_values(target_q_values, data.actions)
                    # this returns max. values and indices of max. values
                    # target_max, _ = self.target_network(data.next_observations).max(dim=1)
                    target_max, _ = target_q_values_masked.max(dim=1)

                    # if dones (terminated), the target_max will be cancelled out because 1 - 1 = 0
                    # data.dones.flatten() will convert TRUE to 1 and FALSE to 0
                    td_target = data.rewards.flatten() + self.gamma * target_max * (1 - data.dones.flatten())

                old_val = self.q_network(data.observations).gather(1, data.actions).squeeze()

                # loss = F.mse_loss(td_target, old_val)
                # Compute Huber loss
                criterion = nn.SmoothL1Loss()
                loss = criterion(old_val, td_target)

                # tensorboard
                if self.global_step % self.log_every == 0:
                    self.metriclogger.write_training_data(self.global_step, loss.item(), old_val.mean().item(), self.start_time)

                # optimize the model
                self.optimizer.zero_grad()
                loss.backward()
                self.optimizer.step()

    def masked_q_values(self, q_values: torch.tensor, actions: torch.tensor):
        """
        Mask `q_values` based on considered actions. There are two groups of action:
            - ``[0, 1, 2]`` which corresponds to `allow`, `block` and `substitute`.
            - ``[3, 4]`` which corresponds to `terminate` and `nop`.

        1) Transform `actions` to `action_mask`
        2) Mask `q_values` using a very large negative value to mask the `q-values`

        Args:
            q_values: A tensor of `(batch, actions)` corresponding to the
                `q_values` for each action.
            actions: A tensor containing actions selected for this batch.

        Returns:
            masked `q_values`
        """

        # recreate a tensor of shape (batch, n_actions) of all actions
        # actions.shape[0] is the batch size
        actions_mask = torch.tensor([[0,1,2,3,4] for _ in range(actions.shape[0])], dtype=torch.float32)
        # convert the created tensor to the action masks
        for i in range(actions.shape[0]):
            # action group 1 [0,1,2]
            if actions[i] <= 2:
                # we should obtain a mask [1,1,1,0,0]
                actions_mask[i] = actions_mask[i] <= 2
            elif actions[i] > 2:
                # group 2, we should obtain a mask [0,0,0,1,1]
                actions_mask[i] = actions_mask[i] > 2

        # use a large negative value to mask the Q-values
        # we should obtain q_values for group action 1 [xx, yy, zz, -10e9, -1e9]
        # we should obtain q_values for group action 2 [-1e9, -1e9, -1e9, xx, yy]
        masked_q_values = q_values + (actions_mask - 1) * 1e9

        return masked_q_values

    def batchUpdateWeights(self, sample:list)->dict[int, float, float]:
        """
        This will simply return information that we will use to do tensorboard
        report.

        Args:
            sample: A list of sample collected during an episode.

        Returns:
            A dictionary containing `global_step`, `episode_reward` and
                `episode_length`.
        """
        # save the global step, as this value is increasing! The agent is shared
        global_step = self.global_step

        cmd_strs = sample["cmd_str"]
        basenames = sample['basenames']
        rewards = sample['rewards']

        episode_reward = np.sum(rewards)
        episode_length = len(cmd_strs)

        # if last command is 'exit_', it means it was a command that
        # we manually input to terminate a session.
        # So the effective is equal to the length of obs - 1
        if basenames and basenames[-1] == 'exit_':
            episode_length -= 1

        return {
            "global_step": global_step,
            "episode_length": episode_length,
            "episode_reward": episode_reward
        }

    def save(self)->None:
        """
        Save model checkpoints.

        We will save the models and along with other parameters, which can be
        used to resume the training. These are items that will be saved:

        - policy net
        - target net
        - callcount
        - epsilon
        - global_step
        """
        save_path = path.join(self.model_dir, f"DQNLearner_{int(self.global_step // self.save_every)}.chkpt")
        torch.save({
                "q_network": self.q_network.state_dict(),
                "target_network": self.target_network.state_dict(),
                "optimizer": self.optimizer.state_dict(),
                "epsilon": self.epsilon,
                "global_step": self.global_step,
                "callcount": self.callcount,
                "global_actions": self.global_actions,
                "start_time": self.start_time
            }, save_path,
        )
        tlog.info(f"DQNLearner saved to {save_path} at step {self.global_step}: Done")

        memory_save_path = path.join(self.model_dir, f"memory_{int(self.global_step // self.save_every)}.z")
        joblib.dump(self.memory, memory_save_path)
        tlog.info(f"Memory saved to {memory_save_path} at step {self.global_step}: Done")

        tensorboard_save_path = path.join(self.model_dir, f"tensorboard_dir_{int(self.global_step // self.save_every)}")
        shutil.copytree(self.tensorboard_dir, tensorboard_save_path)
        tlog.info(f"Tensorboard saved to {tensorboard_save_path} at step {self.global_step}: Done")

    def saveLastModel(self)->dict[str, str]:
        """S
        ave model checkpoints.

        We will save the models and along with other parameters, which can be
        used to resume the training. These are items that will be saved:

        - policy net
        - target net
        - callcount
        - epsilon
        - global_step
        - global actions

        Returns:
            A dictionary containing `dq_path` and `memory_path`
        """
        current_time = datetime.now().strftime("%Y%m%d-%H%M%S")
        save_path = path.join(self.model_dir, f"DQNLearner_last_{current_time}.chkpt")
        try:
            tlog.info("saveLastModel: saving last model...")
            torch.save({
                    "q_network": self.q_network.state_dict(),
                    "target_network": self.target_network.state_dict(),
                    "optimizer": self.optimizer.state_dict(),
                    "epsilon": self.epsilon,
                    "global_step": self.global_step,
                    "callcount": self.callcount,
                    "global_actions": self.global_actions,
                    "start_time": self.start_time
                }, save_path,
            )
        except Exception as e:
            tlog.error(f"saveLastModel: {e}")
        tlog.info(f"Last DQNLearner saved to {save_path}: Done")

        memory_save_path = path.join(self.model_dir, f"memory_last_{current_time}.z")
        joblib.dump(self.memory, memory_save_path)
        tlog.info(f"Last memory buffer saved to {memory_save_path}: Done")

        return {
            "dqn_path": save_path,
            "memory_path": memory_save_path
        }

    def saveResumingFile(self,
                         summary_dir: str,
                         episode_index:int,
                         current_sample_index: int,
                         config: dict)->None:
        """
        Save information to a file that is later used to resume the training.

        Args:
            summary_dir: Folder to write tensorboard data
            episode_index: Current episode number
            current_sample_index: Current sample number
            config: Configuration dictionary
        """
        resume_file = config["resume_file"]
        current_time = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_resume_file = f"{resume_file}_{current_time}"

        tlog.info(f"Save resuming file at: {resume_file}")
        with open(resume_file, "w") as outfile:
            o = {}
            o["model_dir"]   = config["model_dir"]
            o["sample_dir"]  = config["sample_dir"]
            o["dqn_path"]    = config["dqn_path"]
            o["memory_path"] = config["memory_path"]
            o["summary_dir"] = summary_dir
            o["episode_index"] = episode_index
            o["episode_index"] = episode_index
            o["current_sample_index"] = current_sample_index
            o["tensorboard_dir"] = summary_dir
            o["batch_training"] = False

            json.dump(o, outfile, indent=4)

        shutil.copy(resume_file, backup_resume_file)

    def load(self, checkpoint_path: str, memory_path: str)->None:
        """
        Load data from the saved checkpoints.

        Args:
            checkpoint_path: A path where the model checkpoint was saved.
            memory_path: A path where replay buffer memory was saved.
        """
        model = torch.load(checkpoint_path)
        self.q_network.load_state_dict(model["q_network"])
        self.target_network.load_state_dict(model["target_network"])
        self.optimizer.load_state_dict(model["optimizer"])
        self.epsilon = model["epsilon"]
        self.callcount = model["callcount"]
        self.global_step = model["global_step"]
        self.global_actions = model["global_actions"]
        self.memory = joblib.load(memory_path)
        self.start_time = model["start_time"]

        tlog.info(f"DQNLearner is loaded from {checkpoint_path} at step {self.global_step}")
        tlog.info(f"Memory is loaded from {memory_path}")

    def resumeTraining(self, checkpoint_path: str, memory_path: str)->None:
        """
        Wrapper class to continue the training by loading saved model and
        replay buffer memory.

        Args:
            checkpoint_path: A path where the model checkpoint was saved.
            memory_path: A path where replay buffer memory was saved.
        """
        self.load(checkpoint_path, memory_path)

    def createMetriclogger(self, logdir:str)->None:
        """
        Create metric logger.

        Args:
            logdir: Location where previous tensorboard data were saved
        """
        tlog.info(f"Create a new metric writer from {logdir}")
        self.metriclogger.create_writers(self.params, logdir)

    def loadMetriclogger(self, logdir: str)->None:
        """
        Load metric logger to resume training.

        Args:
            logdir: Location where previous tensorboard data were saved.
        """
        tlog.info(f"Resume metric writer from {logdir}")
        self.metriclogger.load_writer(logdir)

    def writeTrainingPerEpisode(self,
                                global_step: int,
                                n_episode: int,
                                count_actions: list, n_steps: int,
                                n_rewards: float)->None:
        """
        Wrapper method to write summery report per episode.

        Args:
            global_step: Global step for the whole training
            n_episode: Number of this episode
            count_actions: List of number of actions taken for this episode.
                Each index correspond to the index of action taken.
            n_steps: Number of steps taken for this episode.
            n_rewards: Number of accumulative rewards for this episode.
        """
        self.metriclogger.write_performance_by_episode(global_step,
                                                  n_episode,
                                                  count_actions,
                                                  n_steps,
                                                  n_rewards)
