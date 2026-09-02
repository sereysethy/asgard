import gym
from gym import spaces
import numpy as np
import random
import tensorflow as tf
from garage.envs import normalize
from garage.experiment.deterministic import set_seed
from garage.tf.envs import TfEnv
from garage.tf.experiment import LocalTFRunner
from garage.envs import Step
from garage.envs.env_spec import EnvSpec
from garage.np.baselines import LinearFeatureBaseline 
from garage.experiment import run_experiment, LocalRunner
from garage.tf.algos import TRPO
from garage.tf.envs import TfEnv
from garage.tf.policies import CategoricalMLPPolicy
from gym.envs.registration import register
from garage.envs import GarageEnv

from smartproxy.learning.env import AttackerEnv

env = AttackerEnv()
# env = TfEnv(normalize(env))
env = GarageEnv(env)  # wrapping custom env using garage.envs.GarageEnv


def train(snapshot_config, *_):
    with LocalTFRunner(snapshot_config=snapshot_config) as runner:
        policy = CategoricalMLPPolicy(
                name="policy",
                env_spec=env.spec,
                hidden_sizes=(32,32))
        baseline=LinearFeatureBaseline(env_spec=env.spec) 
        algo = TRPO(
                env_spec=env.spec,
                policy=policy,
                baseline=baseline,
                max_path_length=50,
                discount=0.99,
                max_kl_step=0.01)
        runner.setup(algo, env)

        runner.train(n_epochs=2, batch_size=10, plot=False)

run_experiment(train, snapshot_mode="last", seed=1,)

# policy = CategoricalMLPPolicy(
#                 name="policy",
#                 env_spec=env.spec,
#                 hidden_sizes=(32,32))
# baseline=LinearFeatureBaseline(env_spec=env.spec) 
# algo = TRPO(
#         env_spec=env.spec,
#         policy=policy,
#         baseline=baseline,
#         max_path_length=50,
#         discount=0.99,
#         max_kl_step=0.01)

# runner = LocalRunner()
# runner.setup(algo, env)
# runner.train(n_epochs=2, batch_size=10, plot=False)