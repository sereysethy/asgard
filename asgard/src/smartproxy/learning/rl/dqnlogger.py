import time
import os

import numpy as np
from torch.utils.tensorboard import SummaryWriter

CMD_ACTION_LIST = ['allow', 'block', 'substitute', 'terminate', 'nop']
OBSERVATION_LIST = ['cpu', 'mem', 'net_in', 'net_out', 'blk_read','blk_write', 'risk_level']

class DQNMetricLogger():
    def __init__(self):
        self.logdir: str = None
        self.action_writers: dict[SummaryWriter] = {}
        self.obs_writers: dict[SummaryWriter] = {}
        self.writer: SummaryWriter = None

    def create_writers(self, params: dict, logdir: str)->None:
        """Create tensorboard writer to write q-values for actions and writer to
        write training data.
        """

        for action in CMD_ACTION_LIST:
            action_logdir = os.path.join(logdir, action)
            self.action_writers[action] = SummaryWriter(action_logdir, "Number of actions per episode")

        for obs in OBSERVATION_LIST:
            obs_logdir = os.path.join(logdir, obs)
            self.obs_writers[obs] = SummaryWriter(obs_logdir, "Action taken wrt observation")

        train_log_dir = logdir + '/train'
        self.writer = SummaryWriter(train_log_dir, "Training data, per episode and per global step")
        self.writer.add_text(
                "hyperparameters",
                "|param|value|\n|-|-|\n%s" % ("\n".join([f"|{key}|{value}|" for key, value in params.items()])),
                )

    def load_writer(self, logdir)->None:
        """Load writer from logdir. We will load writer to write q-value for actions
        and writer to write training data.
        """

        for action in CMD_ACTION_LIST:
            action_logdir = os.path.join(logdir, action)
            self.action_writers[action] = SummaryWriter(action_logdir)

        for obs in OBSERVATION_LIST:
            obs_logdir = os.path.join(logdir, obs)
            self.obs_writers[obs] = SummaryWriter(obs_logdir)

        train_log_dir = logdir + '/train'
        self.writer = SummaryWriter(train_log_dir)

    def write_hyper_epsilon(self, tags: str, step: int, epsilon: float)->None:
        """Writer hyper-parameters epsilon.

        Params
        ------
            tags (str): decay by episode or by global step
            step (int): step can be an episode index or global step
                depedning on how the policy of decaying epsilon value.
            epsilon (float): current epsilon
        Returns
        -------
            None
        """
        self.writer.add_scalar(tags, epsilon, step)

    def write_hyper_lr(self, tags: str, step: int, lr: float)->None:
        """Writer hyper-parameters epsilon.

        Params
        ------
            tags (str): decay by episode or by global step
            step (int): step can be an episode index or global step
                depedning on how the policy of decaying lr value.
            lr (float): learning rate
        Returns
        -------
            None
        """
        self.writer.add_scalar(tags, lr, step)

    def write_training_data(self, global_step: int, td_loss: float, avg_q_values: float, start_time:float)->None:
        """Writing training data.

        Params
        ------
            global_step (int): global step
            td_loss (float): temporal difference
            avg_q_value (float): average q-values for this batch learning

        Returns
        -------
            None
        """

        self.writer.add_scalar("losses/step/td_loss", td_loss, global_step)
        self.writer.add_scalar("losses/step/q_values", avg_q_values, global_step)
        self.writer.add_scalar("charts/step/SPS", int(global_step / (time.time() - start_time)), global_step)

    def write_performance_by_episode(self,
                                global_step: int, n_episode: int,
                                count_actions: list, n_steps: int,
                                n_rewards: float):
        """
        Writer summery report per episode.

        Params
        ------
            global_step (int): global step for the whole training
            n_episode (int): episode number
            count_actions (list): list of number of actions taken for this episode.
                Each index correspond to the index of action taken.
            n_steps (int): number of steps taken for this episode.
            n_rewards (float): number of accumulative rewards for this episode.
        """

        for i, action in enumerate(CMD_ACTION_LIST):
            self.action_writers[action].add_scalar("action/episode", count_actions[i], n_episode)

        self.writer.add_scalar("charts/episode/length", n_steps, n_episode)
        self.writer.add_scalar("charts/episode/return", n_rewards, n_episode)

    def write_action(self, global_step: int, count_actions:list[int]):
        """Write the number of actions taken so far.

        Params
        ------
            global_step (int): global step for the whole training
            count_actions (list): list of number of actions taken
        """

        for i, action in enumerate(CMD_ACTION_LIST):
            self.action_writers[action].add_scalar("action", count_actions[i], global_step)

    def write_action_params(self, global_step: int, action: int, obs:list)->None:
        """Show the actions selected w.r.t the honeypot parameters. It can show
        if the agent selected a good action when the parameters are below the
        set thresholds.

        Params
        ------
            global_step (int): global step
            action (int): action index taken
            obs (list): observation

        Returns
        -------
            None
        """

        selected_action_name = CMD_ACTION_LIST[action]
        risk_level = np.argmax(obs[-13:-8]) # risk is encoded as a one-hot vector of dim. (5,)
        cpu = obs[-6]
        mem = obs[-5]
        net_in = obs[-4]
        net_out = obs[-3]
        blk_read = obs[-2]
        blk_write = obs[-1]

        self.obs_writers["cpu"].add_scalar("action/resources", cpu, global_step)
        self.obs_writers["mem"].add_scalar("action/resources", mem, global_step)
        self.obs_writers["net_in"].add_scalar("action/resources", net_in, global_step)
        self.obs_writers["net_out"].add_scalar("action/resources", net_out, global_step)
        self.obs_writers["blk_read"].add_scalar("action/resources", blk_read, global_step)
        self.obs_writers["blk_write"].add_scalar("action/resources", blk_write, global_step)
        self.obs_writers["risk_level"].add_scalar("action/resources", risk_level, global_step)

        for action_name in CMD_ACTION_LIST:
            if action_name == selected_action_name:
                self.action_writers[action_name].add_scalar("action/resources", 1, global_step)
            else:
                self.action_writers[action_name].add_scalar("action/resources", 0, global_step)