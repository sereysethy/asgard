import os
from joblib import dump, load
from smartproxy import log_training

class Metric:
    """Class records all metrics during training."""

    data = {
        "filename": [],
        "session": [],
        "episode_rewards": [],
        "episode_lengths": [],
        "episode_numbers": [],
        "total_time_steps": 0,
        "total_time_steps_per_episode": [],

        "td_errors_by_action": [],
        "q_values_by_action": [],
        "targetq_values_by_action": [],

        "mean_td_errors_by_action": [],
        "mean_q_values_by_action": [],
        "mean_targetq_values_by_action": [],
        "episode_number_by_action": [],
        "mean_td_errors": [],
        "mean_q_values": [],
        "mean_targetq_values": [],
        "model_attributes_all": [],
        "model_attributes": {},
        "exploration_epsilon": []
    }

    checkpoint = {
        "mean_episode_lengths": [],
        "mean_rewards": [],
        "episode_numbers": [],
        "mean_rewards_last_checkpoint": [],
        "mean_td_errors": [],
        "mean_q_values": [],
        "mean_targetq_values": []
    }

    def __init__(self, numActions=None):

        if numActions:
            for a in range(numActions):
                self.data["model_attributes"]["action_" + str(a)] = []

                self.data["td_errors_by_action"] = [[] for i in range(numActions)]
                self.data["q_values_by_action"] = [[] for i in range(numActions)]
                self.data["targetq_values_by_action"] = [[] for i in range(numActions)]

                self.data["mean_td_errors_by_action"] = [[] for i in range(numActions)]
                self.data["mean_q_values_by_action"] = [[] for i in range(numActions)]
                self.data["mean_targetq_values_by_action"] = [[] for i in range(numActions)]
                self.data["episode_number_by_action"] = [[] for i in range(numActions)]
                

    def save(self, folder, data_filename=None, checkpoint_filename=None):
        """Save metric using joblib that can be restored later."""

        if data_filename is None:
            data_filename = "metric_data.joblib"

        if checkpoint_filename is None:
            checkpoint_filename = "metric_checkpoint.joblib"

        data_pathname = os.path.join(folder, data_filename)
        checkpoint_pathname = os.path.join(folder, checkpoint_filename)

        log_training.info(f"Save metric data to file: {data_pathname}")
        dump(self.data, data_pathname)
        log_training.info(f"Finished saving metric data to file: {data_pathname}")

        log_training.info(f"Save metric checkpoint to file: {checkpoint_pathname}")
        dump(self.checkpoint, checkpoint_pathname)
        log_training.info(f"Finished saving metric checkpoint to file: {checkpoint_pathname}")

    def load(self, folder, data_filename=None, checkpoint_filename=None):
        """Load metric from saved metric object."""

        if data_filename is None:
            data_filename = "metric_data.joblib"

        if checkpoint_filename is None:
            checkpoint_filename = "metric_checkpoint.joblib"

        data_pathname = os.path.join(folder, data_filename)
        checkpoint_pathname = os.path.join(folder, checkpoint_filename)

        log_training.info(f"Load metric data from file: {data_pathname}")
        self.data = load(data_pathname)

        log_training.info(f"Load metric checkpoint from file: {checkpoint_pathname}")
        self.checkpoint = load(checkpoint_pathname)