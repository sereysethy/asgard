import gym
from ray.rllib.env.policy_client import PolicyClient
from smartproxy.learning.env import AttackerEnv

client = PolicyClient("http://localhost:9900")
env = AttackerEnv()

def run_one_episode(env):
    obs = env.reset()
    done = False
    episode_id = client.start_episode() # We start by requesting a new episode id from the server
    total_reward = 0
    while not done:
        action = client.get_action(episode_id, obs) # TODO call get_action to get the action for the current observation
        print('action: ', action)
        obs, rew, done, info = env.step(action)
        print('obs: ', obs, 'reward: ', rew)
        client.log_action(episode_id, obs, action) # TODO tell the server about the recent returns of the action
        if done:
            client.end_episode(episode_id, obs) # TODO tell the server the episode ended
        total_reward += rew
    print("Episode reward", total_reward)

for _ in range(1):
    run_one_episode(env)


def train(self):
    i = 0
    for s in self.honeypot_sessions:
        i += 1
        # print("honepot session: ", s)
        self.learn(s, i)
        if i % 1000 == 0:
            print("epoch: ", i)

    self.draw()
    # np.save(os.path.join(path, "mongo", "model"), self.Qs)