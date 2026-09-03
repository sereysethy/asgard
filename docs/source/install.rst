============
Installation
============

This explains the setup environment required for development and testing/deployment purposes.

Download the project code
=========================
Clone this project repository.

.. code-block:: shell

    $ git clone git@github.com:sereysethy/asgard.git asgard
    $ cd asgard

Folder structure of the project
-------------------------------

.. code-block:: text

    asgard/
        ├── bin/
        ├── data/
        └── etc/
        └── src/
        └── var/
    docker/
    docs/

- ``asgard``: contain source codes for *Asgard* honeypot.
    - bin: scripts to start and stop the *Asgard* system.
    - data: contains command names and configurations for RL and its environemnts.
    - etc: contains Cowrie's configuration default `cowrie.cfg.dist` files and a custom one `cowrie.cfg`
      that has to be set for each version of the Asgard honeypot. `userdb.txt` has to be properly set,
      it defines username and passwords allowed to log in to the honeypot.
- ``docker``: contains files to build Docker images for Asgard system and run them as Docker containers.
- ``docs``: contains reStructured documentations.

Dependencies
============

Python installation
-------------------

Python can be installed based on your system setting. It is recommended to use
an virtual environment such as *miniconda* or *uv*.

The projects requires a Python version **3.10**, however it should work with any
other newer versions of Python.

There are four groups of dependency, for each, they can be installed using *pip* as follows:

.. code-block:: shell

    $ pip install -r requirement-file.txt

*   `requirements.txt`: As the project was built upon the `Cowrie project <hhttps://github.com/cowrie/cowrie>`_,
    as such, we need to install some of its requirement.
    One of the most important dependency is `Twisted <https://twisted.org/>`_ which is the
    Python framework allowing writing event-based Python program and also offer
    Twisted Conche SSH services.

*   `requirements-dev.txt`: For development purpose.

*   `requirements-output.txt`: To allow Cowrie to write logs to an external system.

*   `asgard1-requirements.txt` and `asgard2-requirements.txt`: These are modules that the project
    needs such as *numpy*, *Gymnasium*, *PyTorch*, etc.

Target system
-------------

Asgard is a proxy-based system, it proxies all the commands to Linux server known
as a target system. The easiest one is to use an SSH server deployed as a Docker container,
(althought a normal Linux server should also work).
This container has to be accessible from the Asgard proxy system. The proxy system
can connect to this SSH server via two types of authentication: password and SSH key.
There is a sub project that details how to build and run SSH server in a docker.

From this point onward, we suppose that we have an SSH server running as a Docker container
named *honeypot* and it exposes an internal (or external) port 2226.

Running the server
==================

To deploy a pre-configured server, the first thing that needs to be done is to
edit the configuration file in *etc* directory. There are two versions of Asgard,
a simple *Asgard1* and an advanced *Asgard2*. These two versions have same code base,
but they have different configuration files.
The configuration file for *Asgard1* is `cowrie_asgard1-0.cfg` and for *Asgard2*
is `cowrie_asgard2-0.cfg`.

For more detail of each version, click on these two links.

*   `Asgard1 <./asgard1.html>`_
*   `Asgard2 <./asgard2.html>`_

Assume that *Asgard1* is used, in this case, copy the `cowrie_asgard1-0.cfg` to `cowrie.cfg`,
and edit the following sections:

*   *proxy*: Specify the backend type ``simple_docker``, and SSH server and its exposed port.

.. code-block:: ini

    [proxy]
    backend = simple_docker

    # =====================================
    # Simple Backend Configuration
    # =====================================
    backend_ssh_host = honeypot
    backend_ssh_port = 2226

*   docker: how to connect to the backend system running as Docker container.
    This is to create a username or modify an existing account, before the proxy actually
    connects to the backend system. The creationg/modification of an account is done
    by executing `docker exec container_name CMD` where `CMD` can be `useradd` or
    `chpasswd`. In this example, the container name is `honeypot` and it also requires
    a `unix_socket` to connect to the Docker engine.

.. code-block:: ini

    [docker]
    debug = true
    unix_socket_path = unix://var/run/docker.sock
    container_name = honeypot

Configuration for *Asgard1*
-----------------------------

To run a simple Asgard server aka `Asgard1 <./asgard1.html>`_, modify
the following `rl` section:

.. code-block:: ini

    [rl]
    ### setting for RL
    model_dir = var/train_result/models
    sample_dir = var/samples/
    model_filename = model
    config_agent_filename = data/config/case1/lr01.json
    tensorboard_dir = var/log/train
    train_dir = var/train_data

    # Resume training after each run, `true`, `false`
    resume_training = false
    # if resume_training is set to true, a resume_file is needed
    # uncomment the following line
    # resume_file = var/train_result/models/saved/resume_file.QLearner

    # after number_epoch, a new resume_file is created
    number_epoch = 100

    ## environment name ##
    environment = SimpleAttackerEnvV12

    # Shell that needs to be called to process/parse commands
    # --------------------------------------------------------

    # > Environment: Asgard1 or Midgard using a Tabular method
    shell_interactive_name = ShellComplexParsing
    shell_exec_name = ShellComplexParsingForExec

    # Agent algorithm
    # ---------------
    agent = QLearner

    # Agent Random State for reproductibility
    agent_random_state = 42
    # use for SGDRegressor to output information related to the model training
    # Norm: 0.10, NNZs: 4, Bias: 0.058824, T: 1, Avg. loss: 0.179133
    # 0: no verbose, 1:
    agent_verbosity_level = 1

    # Enable cuda
    cuda = false

Configuration for *Asgard2*
-----------------------------

To run an advanced Asgard server aka `Asgard2 <./asgard2.html>`_, in addition to
the section `rl`, some other sections are also needed:

.. code-block:: ini

    [monitor]
    debug = true
    ignored_commands = /usr/sbin/sshd,-bash,sshd:,bash

    [parser]
    debug = true

    [shell]
    debug = false

    [proxy_shell]
    # set the configuration of the proxy shell that will loops indefinitely to
    # acquire the state of the running process
    running_thread_looping_time = 2

    [rl]
    ### setting for RL
    model_dir = var/train_result/models
    sample_dir = var/samples/
    model_filename = model

    ## RL agent hyper-parameters
    config_agent_filename = data/config/case3/roberta_dqn_v1-0.json

    ## RL Environment
    config_env_filename = data/config/case3/env_v1-0.json

    ## Tensorboard directory
    tensorboard_dir = var/log/train

    ## Train directory to store log data
    train_dir = var/train_data

    ## True if the agent resumes training after each shutdown, otherwise False.
    resume_training = false

    ## If resume_training is set to True, a resume_file is also needed.
    ## It stores data needed to resume a training.
    resume_file = var/train_result/models/saved/snowwhite_asgard

    ## Number of epoch to save training data such as model checkpoints.
    number_epoch = 100

    ## environment name ##
    # RobertaEnvV10: It uses DQN algorithm and also includes the
    # risk assessment model to encode the command line.
    # RobertaEnvWebV10: It uses DQN algorithm but the risk assessment
    # model is a web service. This is more recommended as it makes
    # the deployment easier to manage.
    environment = RobertaEnvV10


    ## Comment this out, if the environment is set to `RobertaEnvWebV10`
    [command_encoder]
    model_path = data/word2vec/20220125-155606/cmd2vec_model_v7_all_20220125-155606_10_90_8.model

    ## State of compromise (SoC).
    # This values indicates when the agent should consider
    # that it is deeply compromised. Its value is a real number between [0, 1].
    # For instance, if it is set to 0.5, this means that if its resouce consumption
    # is more than 50%, then the agent considers the system is deeply compromised.
    # In case that we want to capture more advanced attack, this value should be set closed to 1.
    performance_threshold = 0.5

    ## This is how the SoC is calculated. It uses different
    # resource metric to evalaute its SoC.
    # Metric 1: Average CPU consumption
    # Metric 2: Average RAM consumption
    # Metric 3: Block disk read in bytes
    # Metric 4: Block disk write in bytes
    # Metric 5: Network inbound in bytes
    # Metric 6: Network outbound in bytes

    # As metrics 3-6 are cumulative and lack natural maximums,
    # we need to define artificial upper limits to express current
    # usage as percentage. These upper value should also reflect
    # the extent to which the honeypot is allowed to be compromised.

    # 15GB
    BLK_READ_BYTE_MAX = 15e+9
    # 15GB
    BLK_WRITE_BYTE_MAX = 15e+9

    # 1GB
    NET_INBOUND_BYTE_MAX = 1e+9
    # 1GB
    NET_OUTBOUND_BYTE_MAX = 1e+9

    # Command risk level threshold is an integer number between [0, 4]
    # 0: lowest risk level, 4: highest risk level
    risk_level_threshold = 3

    # Shell that needs to be called to process/parse commands
    # --------------------------------------------------------

    # > Environment: RobertaEnvV10
    shell_interactive_name = ShellRoberta
    shell_exec_name = ShellComplexOneHotExec

    # Agent algorithm
    # ---------------
    agent = DQNLearner

    # Enable cuda
    cuda = false

.. code-block:: ini

    [redis]
    # redis server serves as communication meduim between other programms such as
    # the monitor
    host = localhost
    port = 6379

    # the redis channel where the monitor publish the running processes
    channel_process_name = channel_process

    # the redis channel where the proxy shell publish the pid of the running process
    # that needs to be terminated.
    channel_process_kill = channel_terminate

Running and stopping the server
-------------------------------

To start the Asgard2 server, run the following command:

.. code-block:: console

    $ bin/cowrie start

After a server is started, it will run in the background.
A pid file will be created to store the process ID.

To stop the server, run the following command:

.. code-block:: console

    $ bin/cowrie stop
