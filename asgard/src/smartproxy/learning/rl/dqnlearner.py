import time
import random
from datetime import datetime
from os import path
import json
import shutil

# ML library
import torch
import torch.nn as nn
import torch.optim as optim
import joblib

import numpy as np
import numpy.ma as ma

# custom library
from smartproxy.learning.rl.base import BaseLearner
from smartproxy import tlog, log
from smartproxy.learning.rl.utils import ReplayMemory
from smartproxy.learning.rl.dqn import DQN
from smartproxy.learning.rl.utils import Transition
from .dqnlogger import DQNMetricLogger

def linear_schedule(start_e: float, end_e: float, duration: int, t: int):
    slope = (end_e - start_e) / duration
    return max(slope * t + start_e, end_e)

class DQNLearner(BaseLearner):
    """
    Deep Q-Learning (DQN)

    The implementation of the DQN was adapted from the original implementation
    of `PyTorch tutorial \
    <https://pytorch.org/tutorials/intermediate/reinforcement_q_learning.html>`_.

    See :class:`smartproxy.learning.rl.cleandqnlearner.CleanDQNLearner` for more details.
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

        self.policy_net = DQN(self.numFeatures, self.numActions, self.hidden_layer).to(self.device)
        self.target_net = DQN(self.numFeatures, self.numActions, self.hidden_layer).to(self.device)
        self.target_net.load_state_dict(self.policy_net .state_dict())
        self.optimizer = optim.AdamW(self.policy_net.parameters(), lr=self.learning_rate, amsgrad=True)

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
        It should be called right after the agent is created to initialise
        some parameters.
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
        self.memory = ReplayMemory(self.buffer_size)

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

    def getAction(self, obs: list[float], exploration: bool = True, \
                    mask:list[int] = None)->int:
        """
        Return an action index which correspond to the state.

        .. note::
           This method overrides :func:`smartproxy.learning.rl.base.BaseLearner.getAction`

        Args:
            state (numpy.array): state observation
            exploration (boolean): action selection in exploitation or exploration
            mask (list): a list masks the non-applicable action indexes for
                this state
        Returns:
            index (np.int64): index of action
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
                    q_values = self.policy_net(state).cpu().numpy()
                    if self.debug:
                        log.info(f"unmasked q_values: {q_values}")
                    q_values = ma.array(q_values, mask = mask)
                    if self.debug:
                        log.info(f"masked q_values: {q_values}")
                    action = np.argmax(q_values)
            else:
                q_values = self.policy_net(state).numpy()
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
            sample (tuple): sample containing state, action, next_state and reward
        """

        (state, action, next_state, reward, terminated, info) = sample
        reward = torch.tensor([reward], dtype=torch.float32)
        action = torch.tensor([action], dtype=torch.long).unsqueeze(0)
        state = torch.tensor(state, dtype=torch.float32).unsqueeze(0)
        if isinstance(next_state, np.ndarray):
            next_state = torch.tensor(next_state, dtype=torch.float32).unsqueeze(0)
        self.memory.push(state, action, next_state, reward)

    def doTraining(self)->None:
        """
        Trigger the training process. The training only starts after
        the `global_step` is greater than `learning_starts`.

        Once the training starts, the policy network is updated at every call.
        But the target network can be updated either via a soft update which
        is controlled by :math:`\\tau`.

        The models are saved every `save_every` step(s).
        """
        if self.debug:
            log.info("do training")

        if self.global_step > self.learning_starts:
            if self.debug:
                tlog.info(f"global step: {self.global_step}")
            # Perform one step of the optimization (on the policy network)
            self._optimizeModel()

            # Perform one step of the optimization (on the policy network)
            # To use soft update, set self.target_network_frequency to 1
            # and tau less than 1.
            if self.global_step % self.target_network_frequency == 0:
                # URL: https://pytorch.org/tutorials/intermediate/reinforcement_q_learning.html
                # Soft update of the target network's weights
                # θ′ ← τ θ + (1 −τ )θ′
                target_net_state_dict = self.target_net.state_dict()
                policy_net_state_dict = self.policy_net.state_dict()
                for key in policy_net_state_dict:
                    target_net_state_dict[key] = policy_net_state_dict[key]*self.tau + target_net_state_dict[key]*(1-self.tau)
                self.target_net.load_state_dict(target_net_state_dict)

        if self.global_step % self.save_every == 0:
            self.save()

    def _optimizeModel(self):
        """
        The following code was inspired from the
        `RL tutorial of PyTorch <# URL: https://pytorch.org/tutorials/intermediate/reinforcement_q_learning.html>`_.
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
                transitions = self.memory.sample(self.batch_size)
                # Transpose the batch (see https://stackoverflow.com/a/19343/3343043 for
                # detailed explanation). This converts batch-array of Transitions
                # to Transition of batch-arrays.
                batch = Transition(*zip(*transitions))

                # Compute a mask of non-final states and concatenate the batch elements
                # (a final state would've been the one after which simulation ended)
                non_final_mask = torch.tensor(tuple(map(lambda s: s is not None,
                                                    batch.next_state)), device=self.device, dtype=torch.bool)
                non_final_next_states = [s for s in batch.next_state if s is not None]

                # this is to prevent where the returned sample having all final states
                if not non_final_next_states:
                    return

                # so we have at least one non final state
                non_final_next_states = torch.cat(non_final_next_states)
                state_batch = torch.cat(batch.state)
                action_batch = torch.cat(batch.action)
                reward_batch = torch.cat(batch.reward)

                # Compute Q(s_t, a) - the model computes Q(s_t), then we select the
                # columns of actions taken. These are the actions which would've been taken
                # for each batch state according to policy_net
                state_action_values = self.policy_net(state_batch).gather(1, action_batch)

                # Compute V(s_{t+1}) for all next states.
                # Expected values of actions for non_final_next_states are computed based
                # on the "older" target_net; selecting their best reward with max(1)[0].
                # This is merged based on the mask, such that we'll have either the expected
                # state value or 0 in case the state was final.
                next_state_values = torch.zeros(self.batch_size, device=self.device)
                with torch.no_grad():
                    next_q_values = self.target_net(non_final_next_states)
                    next_q_values_masked = self.masked_q_values(next_q_values, action_batch[non_final_mask])
                    next_state_values[non_final_mask] = next_q_values_masked.max(1)[0]

                # Compute the expected Q values
                expected_state_action_values = reward_batch + (next_state_values * self.gamma)

                # Compute Huber loss
                criterion = nn.SmoothL1Loss()
                loss = criterion(state_action_values, expected_state_action_values.unsqueeze(1))

                # tensorboard
                if self.global_step % self.log_every == 0:
                    self.metriclogger.write_training_data(self.global_step, loss.item(), state_action_values.mean().item(), self.start_time)

                # Optimize the model
                self.optimizer.zero_grad()
                loss.backward()

                # In-place gradient clipping
                # torch.nn.utils.clip_grad_value_(self.policy_net.parameters(), 100)
                self.optimizer.step()

    def masked_q_values(self, q_values: torch.tensor, actions: torch.tensor):
        """
        See :func:`smartproxy.learning.rl.cleandqnlearner.CleanDQNLearner.masked_q_values`
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

    def batchUpdateWeights(self, sample)->dict[int, float]:
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

    def save(self):
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
        torch.save(
            {
                "policy_net": self.policy_net.state_dict(),
                "target_net": self.target_net.state_dict(),
                "optimizer": self.optimizer.state_dict(),
                "epsilon": self.epsilon,
                "global_step": self.global_step,
                "callcount": self.callcount,
                "global_actions": self.global_actions,
                "start_time": self.start_time
            }, save_path,
        )

        memory_save_path = path.join(self.model_dir, f"memory_{int(self.global_step // self.save_every)}.z")
        joblib.dump(self.memory, memory_save_path)

        tlog.info(f"DQNLearner saved to {save_path} at step {self.global_step}")
        tlog.info(f"Memory saved to {memory_save_path} at step {self.global_step}")

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
        torch.save({
                "policy_net": self.policy_net.state_dict(),
                "target_net": self.target_net.state_dict(),
                "optimizer": self.optimizer.state_dict(),
                "epsilon": self.epsilon,
                "global_step": self.global_step,
                "callcount": self.callcount,
                "global_actions": self.global_actions,
                "start_time": self.start_time
            },
            save_path,
        )

        memory_save_path = path.join(self.model_dir, f"memory_last_{current_time}.z")
        joblib.dump(self.memory, memory_save_path)

        tlog.info(f"Last DQNLearner saved to {save_path}")
        tlog.info(f"Last memory buffer saved to {memory_save_path}")

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
        self.policy_net.load_state_dict(model["policy_net"])
        self.target_net.load_state_dict(model["target_net"])
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

    def createMetriclogger(self, logdir)->None:
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
