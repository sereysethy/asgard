# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

from configparser import NoOptionError
import time

from twisted.conch.openssh_compat import primes
from twisted.conch.ssh import factory, keys, transport
from twisted.cred import portal as tp
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.ssh import connection
from cowrie.ssh import keys as cowriekeys

from cowrie.ssh.userauth import HoneyPotSSHUserAuthServer
from cowrie.ssh_proxy import server_transport as proxyTransport
from cowrie.ssh_proxy.userauth import ProxySSHAuthServer

# BEGIN: SMP
from datetime import datetime
from joblib import dump, load
import json
import os
from os.path import join

import csv
import numpy as np

from smartproxy import tlog
# Use the realssh's shellTransport instead of Cowrie's transport
from smartproxy.realssh import server_transport as shellTransport
from smartproxy.factory import helper_agents, helper_envs
# END: SMP

CMD_INTEREST = ["wget", "curl", "tar", "sudo",
                 "chmod", "uname", "ps", "bash",
                 "last", "cat", "grep", "head",
                 "awk", "free", "nproc", "kill",
                 "ls"]

class CowrieSSHFactory(factory.SSHFactory):
    """
    This factory creates HoneyPotSSHTransport instances
    They listen directly to the TCP port.
    The class was taken from the Cowrie's project.

    It was modified to set up Cowrie to act as the SSH proxy server,
    and also to set up the learning process.
    """

    starttime: float | None = None
    privateKeys: dict[bytes, bytes]
    publicKeys: dict[bytes, bytes]
    primes = None
    portal: tp.Portal | None = None  # gets set by plugin
    ourVersionString: bytes = CowrieConfig.get(
        "ssh", "version", fallback="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
    ).encode("ascii")

    def __init__(self, backend, pool_handler):
        self.pool_handler = pool_handler
        self.backend: str = backend
        self.privateKeys = {}
        self.publicKeys = {}
        self.services = {
            b"ssh-userauth": ProxySSHAuthServer
            if self.backend == "proxy"
            else HoneyPotSSHUserAuthServer,
            b"ssh-connection": connection.CowrieSSHConnection,
        }
        # Limit the number of parallel connections .
        self.MAX_CONNECTION = CowrieConfig.getint('honeypot', 'max_connection', fallback=-1)
        log.msg(f"Number of max. connections allowed: {self.MAX_CONNECTION}")
        self.numberConnection = 0
        super().__init__()

    def logDispatch(self, **args):
        """
        Special delivery to the loggers to avoid scope problems
        """
        args["sessionno"] = "S{}".format(args["sessionno"])
        for output in self.tac.output_plugins:
            output.logDispatch(**args)

    def startFactory(self):
        """
        Check for public and private keys.

        Addtionally, we also load the configuration to create the RL
        agent, and its corresponding environment.
        For Asgard2.0, we also run an infinite loop to monitor
        long-running commands.
        """
        # For use by the uptime command
        self.starttime = time.time()

        # Load/create keys
        try:
            public_key_auth = [
                i.encode("utf-8")
                for i in CowrieConfig.get("ssh", "public_key_auth").split(",")
            ]
        except NoOptionError:
            # no keys defined, use the three most common pub keys of OpenSSH
            public_key_auth = [b"ssh-rsa", b"ecdsa-sha2-nistp256", b"ssh-ed25519"]
        for key in public_key_auth:
            if key == b"ssh-rsa":
                rsaPubKeyString, rsaPrivKeyString = cowriekeys.getRSAKeys()
                self.publicKeys[key] = keys.Key.fromString(data=rsaPubKeyString)
                self.privateKeys[key] = keys.Key.fromString(data=rsaPrivKeyString)
            elif key == b"ssh-dss":
                dsaaPubKeyString, dsaPrivKeyString = cowriekeys.getDSAKeys()
                self.publicKeys[key] = keys.Key.fromString(data=dsaaPubKeyString)
                self.privateKeys[key] = keys.Key.fromString(data=dsaPrivKeyString)
            elif key == b"ecdsa-sha2-nistp256":
                ecdsaPuKeyString, ecdsaPrivKeyString = cowriekeys.getECDSAKeys()
                self.publicKeys[key] = keys.Key.fromString(data=ecdsaPuKeyString)
                self.privateKeys[key] = keys.Key.fromString(data=ecdsaPrivKeyString)
            elif key == b"ssh-ed25519":
                ed25519PubKeyString, ed25519PrivKeyString = cowriekeys.geted25519Keys()
                self.publicKeys[key] = keys.Key.fromString(data=ed25519PubKeyString)
                self.privateKeys[key] = keys.Key.fromString(data=ed25519PrivKeyString)

        _modulis = "/etc/ssh/moduli", "/private/etc/moduli"
        for _moduli in _modulis:
            try:
                self.primes = primes.parseModuliFile(_moduli)
                break
            except OSError:
                pass

        # this can come from backend in the future, check HonSSH's slim client
        self.ourVersionString = CowrieConfig.get(
            "ssh", "version", fallback="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
        ).encode("ascii")

        # create our RL agent and environment
        self.currentDateTime = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.config = self.loadAgentConfig()
        self.setupSummaryWriter()
        self.agent, self.env = self.setup()
        self.episodeRewards = []
        self.episodeLengths = []
        # For Asgard v2: we run an infinite looping call to monitor the running process
        if self.envName == "RobertaEnvV10" or self.envName == "RobertaEnvWebV10":
            from smartproxy.command.process.proxy_shell_roberta import ProxyShellRoberta
            self.proxyShell = ProxyShellRoberta()
            self.proxyShell.addAgentAndEnv(self.agent, self.env)
            self.proxyShell.start()

        log.msg("RL agent and environment setup is done")

        factory.SSHFactory.startFactory(self)
        log.msg("Ready to accept SSH connections")

    def stopFactory(self):
        """
        Do all the saving before stopping the factory.

        If it is a batch training like the classic Q-learning,
        the factory will attempt to save the model and also write
        all the summary states, etc.

        In the case of the more complex leanrning algorithm,
        it shuts down the runnning loop.
        """
        if self.agent.batchTraining:
            self.saveLastModel()
            self.saveSummaryState()
            self.writeLastQValues()
            self.saveHyper()
        else:
            try:
                log.msg("stopFactory: trying to save the last model")
                res = self.agent.saveLastModel()
                self.config["dqn_path"], self.config["memory_path"] = res["dqn_path"], res["memory_path"]
                self.agent.saveResumingFile(self.summaryDir,
                                            self.episodeIndex,
                                            self.currentSampleIndex,
                                            self.config)
                self.saveHyper()
            except Exception as e:
                log.err(f"stopFactory: {e}")

        # Shutting down the running loop to query the long-running commands.
        if self.envName == "OneHotVectorEnvCase23":
            self.proxyShell.stop()
        elif self.envName == "RobertaEnvV10" or self.envName == "RobertaEnvWebV10":
            self.proxyShell.stop()

        factory.SSHFactory.stopFactory(self)

    def buildProtocol(self, addr):
        """
        Create an instance of the server side of the SSH protocol.

        Args:
            addr (twisted.internet.interfaces.IAddress): The address at which the server will listen.

        Args:
            cowrie.ssh.transport.HoneyPotSSHTransport: The built transport.
        """
        t: transport.SSHServerTransport
        if self.backend == "proxy":
            t = proxyTransport.FrontendSSHTransport()
        else:
            # BEGIN SMP
            if self.MAX_CONNECTION > 0:
                if self.numberConnection < self.MAX_CONNECTION:
                    t = shellTransport.HoneyPotSSHTransport()
                    self.numberConnection += 1
                else:
                    return None
            else:
                t = shellTransport.HoneyPotSSHTransport()
            # END SMP

        t.ourVersionString = self.ourVersionString
        t.supportedPublicKeys = list(self.privateKeys.keys())

        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            if b"diffie-hellman-group-exchange-sha1" in ske:
                ske.remove(b"diffie-hellman-group-exchange-sha1")
                log.msg("No moduli, no diffie-hellman-group-exchange-sha1")
            if b"diffie-hellman-group-exchange-sha256" in ske:
                ske.remove(b"diffie-hellman-group-exchange-sha256")
                log.msg("No moduli, no diffie-hellman-group-exchange-sha256")
            t.supportedKeyExchanges = ske

        try:
            t.supportedCiphers = [
                i.encode("utf-8") for i in CowrieConfig.get("ssh", "ciphers").split(",")
            ]
        except NoOptionError:
            # Reorder supported ciphers to resemble current openssh more
            t.supportedCiphers = [
                b"aes128-ctr",
                b"aes192-ctr",
                b"aes256-ctr",
                b"aes256-cbc",
                b"aes192-cbc",
                b"aes128-cbc",
                b"3des-cbc",
                b"blowfish-cbc",
                b"cast128-cbc",
            ]

        try:
            t.supportedMACs = [
                i.encode("utf-8") for i in CowrieConfig.get("ssh", "macs").split(",")
            ]
        except NoOptionError:
            # SHA1 and MD5 are considered insecure now. Use better algos
            # like SHA-256 and SHA-384
            t.supportedMACs = [
                b"hmac-sha2-512",
                b"hmac-sha2-384",
                b"hmac-sha2-256",
                b"hmac-sha1",
                b"hmac-md5",
            ]

        try:
            t.supportedCompressions = [
                i.encode("utf-8")
                for i in CowrieConfig.get("ssh", "compression").split(",")
            ]
        except NoOptionError:
            t.supportedCompressions = [b"zlib@openssh.com", b"zlib", b"none"]

        t.factory = self

        return t

    def loadAgentConfig(self)->dict:
        """
        Load the agent hyperparameters from the configuration file.

        This method reads the configuration file specified in the ``rl``
        section of the Cowrie configuration and returns its contents
        as a dictionary.

        Returns:
            dict: A dictionary containing the agent hyperparameter values.
        """
        filename = CowrieConfig.get("rl", "config_agent_filename")
        with open(filename, "r") as infile:
            o = json.load(infile)
        return o

    def loadEnvConfig(self)->dict:
        """
        Load the environment configuration parameters from the configuration file.

        This method reads the environment configuration file specified in the ``rl``
        section of the Cowrie configuration and returns its contents as a dictionary.

        Returns:
            dict: A dictionary containing the environment configuration parameters.
        """
        filename = CowrieConfig.get("rl", "config_env_filename")
        with open(filename, "r") as infile:
            o = json.load(infile)
        return o

    def saveLastModel(self)->None:
        """called to save the last model after the reactor is stopped.

        This method is different from the `saveModel()` because it will just
        save the last model with the number of episode.
        """

        model_dir = self.config["model_dir"]
        filename = CowrieConfig.get("rl", "model_filename")

        self.writeQValues(self.episodeIndex)
        currentTime = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename += '_' + str(self.episodeIndex) + '_' + currentTime
        self.lastModelFile = join(model_dir, filename + ".joblib")
        tlog.info(f"Dumping agent model to file {self.lastModelFile}")
        dump(self.agent, self.lastModelFile)

    def saveModel(self)->None:
        """called to save model after a certain epoche as defined in `number_epoch`.

        This method is called at several locations, because a session can be
        terminated by different cases:

        - after an attacker is disconnected, a call to doTraining will also
          call this method to save the model.
        - after an attacker is disconnected due to some unknonw circumstance,
          this method is called from a method
          :meth:`cowrie.ssh.transport.HoneyPotSSHTransport.connectionLost()`.

        We skip this saving for ``DQN``.
        """

        if not self.agent.batchTraining:
            return

        model_dir = self.config["model_dir"]
        filename = CowrieConfig.get("rl", "model_filename")
        epoch = CowrieConfig.getint("rl", "number_epoch", fallback=100)
        if (self.episodeIndex + 1) % epoch == 0:
            self.writeQValues(self.episodeIndex)
            filename += '_' + str(self.episodeIndex)
            self.lastModelFile = join(model_dir, filename + ".joblib")
            tlog.info(f"Dumping agent model to file {self.lastModelFile}")
            dump(self.agent, self.lastModelFile)

    def saveHyper(self, filename: str="hyperparams.json"):
        """
        Save hyper-parameters in JSON format.

        Args:
            filename: File name to save hyper-parameters.
                Default is set to `hyperparams.json`
        """
        hyperfile = join(self.config["model_dir"], filename)
        tlog.info(f"Saving hyperparameters to file {hyperfile}")
        with open(hyperfile, 'w') as f:
            json.dump(self.config, f)

    def loadModel(self, path: str):
        """
        Load the saved model from a saved path.

        Args:
            path: Path to load a saved model from.
        """
        tlog.info(f"Loading agent model from file {path}")
        return load(path)

    def setup(self):
        """
        Setup the experiments.

        If it is fresh experiment, it will first create an environment and agent
        as specified in the configuration.
        If it is not a fresh experiment, it will create an environment
        and load the previosly saved agent.

        Returns:
            tuple: A tuple of:
                - an agent: An instance of :class:`smartproxy.learning.rl.base.BaseLearner`
                - an environment: An instance of an environment of type of :class:`smartproxy.learning.environment.env.BaseEnv`
        """

        self.envName = CowrieConfig.get("rl", "environment")

        if self.newTraining:
            # new agent model
            tlog.info(f"Creating the environment: {self.envName}")
            env = helper_envs.createEnv(self.envName)
            agent = self.createAgent(env)
            agent.reset()
        else:
            self.agentName = CowrieConfig.get("rl", "agent")
            tlog.info(f"Loading agent name {self.agentName}")

            if self.agentName == "DQNLearner" or self.agentName == "CleanDQNLearner":
                env = helper_envs.createEnv(self.envName)
                agent = self.createAgent(env)
                agent.resumeTraining(self.config["dqn_path"], self.config["memory_path"])
                agent.loadMetriclogger(self.config["tensorboard_dir"])
            else:
                path = self.config["model_name"]
                # set this agent name, because the agent is loaded from an existing one
                if os.path.isfile(path):
                    tlog.info(f"Last model found: {path}")
                    env = helper_envs.createEnv(self.envName)
                    agent = self.loadModel(path)
                else:
                    raise FileNotFoundError("Model file not found")

        return agent, env

    def createAgent(self, env):
        """
        Create an agent which is defined in the configuration file. This will
        call a helper class that will create a real agent.

        Args:
            env (object): contain the environment

        Returns:
            An instance of agent of :class:`smartproxy.learning.rl.base.BaseLearner`
        """

        # check if cuda is enabled
        self.config['cuda'] = CowrieConfig.getboolean("rl", "cuda", fallback=False)
        tlog.info(f"Cuda enabled: {self.config['cuda']}")

        # check if debug is enabled for this agent
        self.config['agent_debug'] = CowrieConfig.getboolean("rl", "agent_debug", fallback=False)
        tlog.info(f"Agent debug mode enabled: {self.config['agent_debug']}")

        # check if training is resumed after each termination
        self.config['resume_training'] = CowrieConfig.getboolean("rl", "resume_training", fallback=False)
        tlog.info(f"resume_training mode enabled: {self.config['resume_training']}")

        if self.config['resume_training']:
            self.config['resume_file'] = CowrieConfig.get("rl", "resume_file")
            tlog.info(f"resume_file is: {self.config['resume_file']}")

        self.agentName = CowrieConfig.get("rl", "agent")
        tlog.info(f"Load agent name: {self.agentName}")

        numActions = env.action_space.n

        # check if there is a shape then it is a box
        if env.observation_space.shape:
            numFeatures, _ = env.observation_space.shape
        else:
            # otherwise it is a discrete
            numFeatures = env.observation_space.n
        agent = None

        # reproductibility random state
        self.agentRandomState = CowrieConfig.getint("rl",
                                    "agent_random_state",
                                    fallback=42)
        self.config['agent_random_state'] = self.agentRandomState

        # verbosity level
        self.agentVerbosityLevel = CowrieConfig.getint("rl",
                                    "agent_verbosity_level",
                                    fallback=0)
        self.config['agent_verbosity_level'] = self.agentVerbosityLevel

        # use a helper class to create an appropriate agent
        tlog.info(f"Number of features: {numFeatures}, number of actions {numActions}")
        agent = helper_agents.createAgent(self.agentName, numFeatures, \
                                            numActions, self.config)
        tlog.info(f"Agent batch learning: {agent.batchTraining}")

        return agent

    def writeQValues(self, n: int):
        """
        This will write final q-values to a file at the iteration number.

        The file can only be produced if the we use a tabular method.

        Args:
            n: iteration number
        """

        agentName = CowrieConfig.get('rl', 'agent')
        if agentName == 'QLearner' or agentName == 'SARSALearner':
            filename = f"q-values_{n}.csv"
            path = os.path.join(self.config["model_dir"], filename)
            csvfile = open(path, 'w', newline='')
            csvwriter = csv.writer(csvfile, dialect='excel')

            tlog.info(f"Writing q-values at the iteration {n} to csv file: {path}")
            csvwriter.writerow(["command", "allow", "block", "substitute"])
            for cmdIndex in range(len(self.agent.models)):
                cmd = self.env.ALL_COMMANDS[cmdIndex]
                csvwriter.writerow([cmd] + self.agent.models[cmdIndex])

            csvfile.close()
        else:
            tlog.info("Using function approximation cannot write final q-values to csv file")

    def writeLastQValues(self):
        """
        This function will be called to write last q-values to csv files
        when the factory closes.
        """

        agentName = CowrieConfig.get('rl', 'agent')
        if agentName == 'QLearner' or agentName == 'SARSALearner':
            filename = f"q-values_{self.episodeIndex}.csv"
            modelDir = self.config["model_dir"]
            path = os.path.join(modelDir, filename)
            csvfile = open(path, 'w', newline='')
            csvwriter = csv.writer(csvfile, dialect='excel')

            tlog.info(f"Writing final q-values to csv file: {path}")

            csvwriter.writerow(["command", "allow", "block", "substitute"])
            for cmdIndex in range(len(self.agent.models)):
                cmd = self.env.ALL_COMMANDS[cmdIndex]
                csvwriter.writerow([cmd] + self.agent.models[cmdIndex])

            csvfile.close()
        else:
            tlog.info("Using function approximation cannot write final q-values to csv file")

    def setupSummaryWriter(self)->None:
        """
        Setup tensorflow summary writer that will be used to log
        training data in tensorboard format.
        """

        modelDir = CowrieConfig.get("rl", "model_dir")
        sampleDir = CowrieConfig.get("rl", "sample_dir")
        trainDir = CowrieConfig.get("rl", "train_dir")
        resumeTraining = CowrieConfig.getboolean("rl", "resume_training", fallback=False)
        # it will be overriden if training is resumed
        self.currentSampleIndex = 0
        self.newTraining = True

        if resumeTraining:
            # load the resume file
            resumeFile = CowrieConfig.get("rl", "resume_file")
            if os.path.isfile(resumeFile):
                with open(resumeFile, "rb") as fin:
                    try:
                        o = json.load(fin)
                        if o and 'batch_training' not in o:
                            self.summaryDir = o["summary_dir"]
                            self.episodeIndex = o["episode_index"]
                            self.config["model_dir"] = os.path.join(modelDir, self.summaryDir)
                            self.config["sample_dir"] = os.path.join(sampleDir, self.summaryDir)
                            self.config["train_dir"] = os.path.join(trainDir, self.summaryDir)
                            self.config["model_name"] = o["model_name"]
                            self.currentSampleIndex = o["current_sample_index"]
                            self.newTraining = False
                            tlog.info(f"Resume training from folder {self.summaryDir} at episode index: {self.episodeIndex}")
                        else:
                            # this is for DQN, tensorboard data will be written by the agent
                            tensorboardDir = CowrieConfig.get("rl", "tensorboard_dir", fallback=None)
                            self.summaryDir = o["summary_dir"]
                            self.episodeIndex = o["episode_index"]
                            self.config["model_dir"] = os.path.join(modelDir, self.summaryDir)
                            self.config["sample_dir"] = os.path.join(sampleDir, self.summaryDir)
                            self.config["train_dir"] = os.path.join(trainDir, self.summaryDir)
                            self.config["dqn_path"] = o["dqn_path"]
                            self.config["memory_path"] = o["memory_path"]
                            self.config["tensorboard_dir"] = os.path.join(tensorboardDir, self.summaryDir)
                            self.currentSampleIndex = o["current_sample_index"]
                            self.newTraining = False
                            tlog.info(f"Resume training from folder {self.summaryDir} at episode index: {self.episodeIndex}")
                    except json.decoder.JSONDecodeError:
                        pass

        if self.newTraining:
            self.setupNewTraining()

    def setupNewTraining(self)->None:
        """called from the setupSummaryWriter() to setup a new training folders.
        """
        modelDir = CowrieConfig.get("rl", "model_dir")
        sampleDir = CowrieConfig.get("rl", "sample_dir")
        trainDir = CowrieConfig.get("rl", "train_dir")

        # this is for DQN, tensorboard data will be written by the agent
        tensorboardDir = CowrieConfig.get("rl", "tensorboard_dir", fallback=None)

        self.summaryDir = self.currentDateTime
        self.episodeIndex = 0
        self.config["model_dir"] = os.path.join(modelDir, self.summaryDir)
        self.config["sample_dir"] = os.path.join(sampleDir, self.summaryDir)
        self.config["train_dir"] = os.path.join(trainDir, self.summaryDir)
        if tensorboardDir:
            # only for DQN
            self.config["tensorboard_dir"] = os.path.join(tensorboardDir, self.summaryDir)
            os.mkdir(self.config["tensorboard_dir"], 0o755)
        os.mkdir(self.config["model_dir"], 0o755)
        os.mkdir(self.config["sample_dir"], 0o755)
        os.mkdir(self.config["train_dir"], 0o755)
        tlog.info(f"Start a new training at folder {self.summaryDir} at episode index: {self.episodeIndex}")

    def saveSummaryState(self)->None:
        """
        Save summary state file to resume the training.

        If a `resume_training` in ``rl`` section is set to ``True``
        in the Cowrie's configuration file, a summary state file
        is saved to the file named in according to ``resume_file``.
        """
        resumingTraining = CowrieConfig.getboolean("rl", "resume_training", fallback=False)

        if resumingTraining:
            # load the resume file
            resumeFile = CowrieConfig.get("rl", "resume_file")
            with open(resumeFile, "w") as outfile:
                tlog.info(f"Save summary state folder: {self.summaryDir}, episode index: {self.episodeIndex}")
                o = {}
                o["summary_dir"] = self.summaryDir
                o["episode_index"] = self.episodeIndex
                o["model_name"] = self.lastModelFile
                o["current_sample_index"] = self.currentSampleIndex
                json.dump(o, outfile, indent=4)

    def doTraining(self, sessionno: str, sample: dict)->None:
        """
        After each disconnection, the protocol will call this function to
        start a batch training by passing sample data collected and sessionno
        which correspond to this sample for future reference.

        Args:
            sessiono: session number
            sample: A dictionary containing all the interactions during a session.
        """

        # it is a batch training
        if self.agent.batchTraining:
            tdErrors, episodeReward, episodeLength = self.agent.batchUpdateWeights(sample)
            if episodeLength > 0:
                index = self.episodeIndex
                self.episodeRewards.append(episodeReward)
                self.episodeLengths.append(episodeLength)
                self.saveSample(index, sessionno, sample)
                self.saveModel()
                if self.agentName == 'QLearner' or self.agentName == 'SARSALearner':
                    self.summary(index, sessionno, episodeLength, episodeReward, np.mean(tdErrors))
                elif self.agentName == 'QLinearFALearner':
                    self.summaryFA(index, sessionno, episodeLength, episodeReward, np.mean(tdErrors), sample)
                self.episodeIndex += 1
                # only after there is some real update, then we call new episode
                self.agent.newEpisode()
        else:
            result = self.agent.batchUpdateWeights(sample)
            _episodeReward = result["episode_reward"]
            _episodeLength = result["episode_length"]
            _globalStep = result["global_step"]
            if _episodeLength > 0:
                _episodeIndex = self.episodeIndex
                # accumulative rewards and lengths
                self.saveSample(_episodeIndex, sessionno, sample)
                # we will not call save model, there seems be a race condition
                # or thread-related problem.
                # self.saveModel()
                self.episodeIndex += 1
                self.agent.writeTrainingPerEpisode(_globalStep,
                                                   _episodeIndex,
                                                   sample["count_actions"],
                                                   _episodeLength,
                                                   _episodeReward)
                self.agent.newEpisode()

    def summary(self, index, sessionno, episodeLength, episodeReward, avgTDError):
        """
        Write Tensorboard summary of the training data.
        """

        o = {}
        o["step"] = index
        o["sessionno"] = sessionno

        # hyper-parameters
        o["hyper-parameters"] = {}
        o["hyper-parameters"]["epsilon"] = self.agent.epsilon
        o["hyper-parameters"]["learning_rate"] = self.agent.learningRate

        # Per episode
        o["per_episode"] = {}
        o["per_episode"]["number_transitions"] = episodeLength
        o["per_episode"]["reward"] = episodeReward
        o["per_episode"]["td-error"] = avgTDError.tolist()

        # Accumulative
        o["accumulative"] = {}
        o["accumulative"]["number_transitions"] = np.sum(self.episodeLengths).tolist()
        o["accumulative"]["reward"] = np.sum(self.episodeRewards).tolist()

        # q-value: allow
        o["allow"] = {}
        o["allow"]["custom"] = self.agent._qValue(self.env.CUSTOM_COMMAND_IX, self.env.ACTION_ALLOW)
        for cmd in CMD_INTEREST:
            o["allow"][cmd] = self.agent._qValue(self.env.COMMAND_TO_IX[cmd], self.env.ACTION_ALLOW)

        # q-value: block
        o["block"] = {}
        o["block"]["custom"] = self.agent._qValue(self.env.CUSTOM_COMMAND_IX, self.env.ACTION_BLOCK)
        for cmd in CMD_INTEREST:
            o["block"][cmd] = self.agent._qValue(self.env.COMMAND_TO_IX[cmd], self.env.ACTION_BLOCK)

        # q-value: substitute
        o["substitute"] = {}
        o["substitute"]["custom"] = self.agent._qValue(self.env.CUSTOM_COMMAND_IX, self.env.ACTION_SUBSTITUTE)
        for cmd in CMD_INTEREST:
            o["substitute"][cmd] = self.agent._qValue(self.env.COMMAND_TO_IX[cmd], self.env.ACTION_SUBSTITUTE)

        self.saveTrainingData(index, sessionno, o)

    def saveSample(self, index: int, sessionno: str, sample:dict)->None:
        """called after each episode ends (after each disconnection).

        This will sample (commands, args, actions, next_commands, rewards, info
        sessionno) to sample folder.

        Args:
            index: current episode number
            sessiono: unique session id
            sample: dictionary containing sample for that session
        """

        sampleDir = self.config["sample_dir"]
        epoch = CowrieConfig.getint("rl", "number_epoch", fallback=100)

        # create a new file if we save a number of samples equal to `number_epoch`
        if index % epoch == 0:
            mode = 'w'
            name = str(index)
            self.currentSampleIndex = index
        else:
            # we will append if the sample saved is less than `number_epoch`
            mode = 'a'
            name = str(self.currentSampleIndex)

        filename = os.path.join(sampleDir, name + ".json")

        with open(filename, mode) as outfile:
            sample["sessionno"] = sessionno
            json.dump(sample, outfile)
            outfile.write('\n')

    def summaryFA(self, index: int, sessionno: str, episodeLength: int, episodeReward: float, avgTDError: float, sample: dict):
        """
        Write Tensorboard summary of the training data in the case of using
        a function approximation.

        Args:
            index: the current index to keep track of the number of trained
                episodes so far.
            sessionno: the session number that links to the SSH session.
            episodeLength: the number of commands in this session.
            episodeReward: the total rewards collected for this session.
            avgTDError: the average TD error after training.
            sample: a dictionnaire containing the detail of attack data
                including obs, basename, command index, next obs, action, done, etc.
        """

        o = {}
        o["step"] = index
        o["sessionno"] = sessionno

        # hyper-parameters
        o["hyper-parameters"] = {}
        o["hyper-parameters"]["epsilon"] = self.agent.epsilon
        o["hyper-parameters"]["learning_rate"] = self.agent.learningRate

        # Per episode
        o["per_episode"] = {}
        o["per_episode"]["number_transitions"] = episodeLength
        o["per_episode"]["reward"] = episodeReward
        o["per_episode"]["td-error"] = avgTDError.tolist()

        # Accumulative
        o["accumulative"] = {}
        o["accumulative"]["number_transitions"] = np.sum(self.episodeLengths).tolist()
        o["accumulative"]["reward"] = np.sum(self.episodeRewards).tolist()

        # q-value: allow
        o["allow"] = {}
        o["block"] = {}
        o["substitute"] = {}
        o["terminate"] = {}
        o["nop"] = {}
        o["cpu"] = {}
        o["mem"] = {}
        for i in range(len(sample['obs'])):
            cmdIndex = sample['cmd_index'][i]
            cmd = sample['basenames'][i]
            obs = sample['obs'][i]
            state = self.env.commandIndexToMarkovState(cmdIndex)

            if state == self.env.MARKOV_STATE_CUSTOM:
                v = self.agent._qValue(obs, self.env.ACTION_ALLOW)
                o["allow"]["custom"] = v.tolist()
                v = self.agent._qValue(obs, self.env.ACTION_BLOCK)
                o["block"]["custom"] = v.tolist()
                v = self.agent._qValue(obs, self.env.ACTION_SUBSTITUTE)
                o["substitute"]["custom"] = v.tolist()
                v = self.agent._qValue(obs, self.env.ACTION_TERMINATE)
                o["terminate"]["custom"] = v.tolist()
                v = self.agent._qValue(obs, self.env.ACTION_NOP)
                o["nop"]["custom"] = v.tolist()

                o["cpu"]["custom"] = obs[-2]
                o["mem"]["custom"] = obs[-1]

            if state == self.env.MARKOV_STATE_COMMAND:
                if cmd in CMD_INTEREST:
                    v = self.agent._qValue(obs, self.env.ACTION_ALLOW)
                    o["allow"][cmd] = v.tolist()
                    v = self.agent._qValue(obs, self.env.ACTION_BLOCK)
                    o["block"][cmd] = v.tolist()
                    v = self.agent._qValue(obs, self.env.ACTION_SUBSTITUTE)
                    o["substitute"][cmd] = v.tolist()
                    v = self.agent._qValue(obs, self.env.ACTION_TERMINATE)
                    o["terminate"][cmd] = v.tolist()
                    v = self.agent._qValue(obs, self.env.ACTION_NOP)
                    o["nop"][cmd] = v.tolist()

                    o["cpu"][cmd] = obs[-2]
                    o["mem"][cmd] = obs[-1]

        self.saveTrainingData(index, sessionno, o)

    def saveTrainingData(self, index, sessionno, data):
        """
        Save data return from agent after each training. It can be used to
        write Tensorboard summary data.
        """

        sampleDir = self.config["train_dir"]
        epoch = CowrieConfig.getint("rl", "number_epoch", fallback=100)

        if index % epoch == 0:
            mode = 'w'
            name = str(index)
            self.currentSampleIndex = index
        else:
            mode = 'a'
            name = str(self.currentSampleIndex)

        filename = os.path.join(sampleDir, name + ".json")

        with open(filename, mode) as outfile:
            json.dump(data, outfile)
            outfile.write('\n')

    def loseConnection(self):
        """
        This function is called from transport when a connection is lost.

        For each lost connection, it decrements the number of connections,
        as to maintain the number of parallelled connections allowed.
        """
        # decrement number of connection to allow a connection
        if self.MAX_CONNECTION > 0 and self.numberConnection > 0:
            self.numberConnection -= 1
