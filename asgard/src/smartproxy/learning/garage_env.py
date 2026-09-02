import gym
import akro
import numpy as np
from smartproxy.learning.preprocess import load_attacker_commands
from twisted.python import failure, log
NUMBER_ACTION = 2
NUMBER_FEATURE = 5
NUMBER_COMMAND = 100

class AttackerEnv(gym.Env):
    """
    Description:
        A pole is attached by an un-actuated joint to a cart, which moves along a frictionless track. The pendulum
        starts upright, and the goal is to prevent it from falling over by increasing and reducing the cart's velocity.
    Source:
        This environment corresponds to the version of the cart-pole problem described by Barto, Sutton, and Anderson
    Observation: 
        Type: Box(5)
        Num	Observation               Min             Max
        0	command                   0               nb_command
        1	cpu                       0               Inf
        2	memory                    0               Inf
        3	networkIn                 0               Inf
        4	networkOut                0               Inf
        
    Actions:
        Type: Discrete(5)
        Num	Action
        0	Allow command to execute
        1	Block command to execute
        2   Slow down command execution
        3   discontinue
        4   re-initialise system
        
        Note: The amount the velocity that is reduced or increased is not fixed; it depends on the angle the pole is
        pointing. This is because the center of gravity of the pole increases the amount of energy needed to move the
        cart underneath it
    Reward:
        Reward is 1 when wget or curl command is tried
        Reward is -1 when a system is compromised at this point we will make an
        assumption that 
    Starting State:
        All observations are assigned a uniform random value in [-0.05..0.05]
    Episode Termination:
        When attacker terminates session either by executing exit command or
        when session is terminated.
    """
    
    metadata = {
        'render.modes': ['human', 'rgb_array'],
        'video.frames_per_second' : 50
    }

    def __init__(self, shell = None):
        self.command_list = load_attacker_commands()
        self.command_to_ix = {word: i for i, word in enumerate(self.command_list)}
        self.shell = shell
        self.reset()

    @property
    def observation_space(self):
        self.min_command = 0
        self.max_command = len(self.command_list)

        self.min_cpu = 0
        self.max_cpu = 100
        
        self.min_memory = 0
        self.max_memory = np.inf

        self.min_network_transmit = 0
        self.max_network_transmit = np.inf

        self.min_network_receive = 0
        self.max_network_receive = np.inf
        
        self.low = np.array([
            self.min_command,
            self.min_cpu,
            self.min_memory, 
            self.min_network_transmit,
            self.min_network_receive])

        self.high = np.array([
            self.max_command,
            self.max_cpu,
            self.max_memory, 
            self.max_network_transmit,
            self.max_network_receive])

        return akro.Box(low=self.low, high=self.high, dtype=np.float32)
                
    @property
    def action_space(self):
        return akro.Discrete(NUMBER_ACTION)

    def step(self, action):
        assert self.action_space.contains(action), "%r (%s) invalid"%(action, type(action))

        done = False

        # reward only if attacker inputs another command otherwise 0
        # if attacker inputs another command, reward +1
        # if cpu, mem, io_face > a threashold, reward -1

        command_ix = np.random.randint(low=0, high=len(self.command_list), dtype=int)
        command_arr = np.array([command_ix])
        param_arr = np.random.uniform(-1, 1, size=(4,))
        self._state = np.concatenate((command_arr, param_arr))

        """
        Execute the command through Shell
        Wait for the next command
        If the next command does not exit, return the next command and false for done
        Else return exit and true for done
        """
        
        self.shell.exec('ls')

        if self.command_list[command_ix] == 'curl' or self.command_list[command_ix] == 'wget':
            reward = 1
        else:
            reward = 0

        if self.command_list[command_ix] == 'exit':
            reward = 0
            done = True

        return np.copy(self._state), reward, done, {}

    def reset(self):
        """
        return a new/initial observation when attacker is disconnected or
        a session ended when attacker input 'exit'
        """
        return np.array([0, 0, 0, 0, 0])

    def close(self):
        return True

# from ray.rllib.utils import PolicyClient
# import gym

# client = PolicyClient("http://localhost:8900")
# env = gym.make("CartPole-v0")

# def run_one_episode(env):
#     obs = env.reset()
#     done = False
#     episode_id = client.start_episode() # We start by requesting a new episode id from the server
#     total_reward = 0
#     while not done:
#         action = client.get_action(episode_id, obs) # TODO call get_action to get the action for the current observation
#         obs, rew, done, info = env.step(action)
#         client.log_action(episode_id, obs, action) # TODO tell the server about the recent returns of the action
#         if done:
#             client.end_episode(episode_id, obs) # TODO tell the server the episode ended
#         total_reward += rew
#     print("Episode reward", total_reward)

# for _ in range(200):
#     run_one_episode(env)