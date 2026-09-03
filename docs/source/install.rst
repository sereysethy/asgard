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
    ├── etc/
    ├── src/
    └── var/
    docker/
    docs/

- ``asgard``: contains source code for the *Asgard* honeypot.
    - ``bin``: scripts to start and stop the *Asgard* system.
    - ``data``: contains command names and configurations for RL and its environments.
    - ``etc``: contains Cowrie's default configuration file ``cowrie.cfg.dist``, plus the
      version-specific templates ``cowrie_asgard1-0.cfg`` and ``cowrie_asgard2-0.cfg``, one
      of which should be copied to ``cowrie.cfg`` and customized for each deployment. ``userdb.txt``
      also lives here and must be properly set, as it defines the usernames and passwords allowed
      to log in to the honeypot.
- ``docker``: contains files to build Docker images for the Asgard system and run them as Docker containers.
- ``docs``: contains reStructuredText documentation.

Dependencies
============

Python installation
-------------------

Python can be installed based on your system setting. It is recommended to use
a virtual environment such as *miniconda* or *uv*.

The project requires Python version **3.10**, however it should work with any
newer version of Python.

There are five groups of dependencies, each of which can be installed using *pip* as follows:

.. code-block:: shell

    $ pip install -r requirement-file.txt

*   ``requirements.txt``: As the project was built upon the `Cowrie project <https://github.com/cowrie/cowrie>`_,
    we need to install some of its requirements. One of the most important dependencies is
    `Twisted <https://twisted.org/>`_, the Python framework that allows writing event-based
    Python programs and also provides Twisted Conch SSH services.

*   ``requirements-dev.txt``: For development purposes.

*   ``requirements-output.txt``: To allow Cowrie to write logs to an external system.

*   ``asgard1-requirements.txt`` and ``asgard2-requirements.txt``: Additional modules the project
    needs, such as *numpy*, *Gymnasium*, and *PyTorch*.

Target system
-------------

Asgard is a proxy-based system; it proxies all commands to a Linux server known
as the target system. The easiest option is to use an SSH server deployed as a Docker container,
although a normal Linux server should also work. This container has to be accessible from the
Asgard proxy system. The proxy system can connect to this SSH server via two types of
authentication: password and SSH key. A sub-project details how to build and run an SSH server
in Docker.

From this point onward, we assume that we have an SSH server running as a Docker container
named *honeypot*, listening on port 22.

Running the server
==================

To deploy a pre-configured server, the first thing that needs to be done is to
edit the configuration file in the ``etc`` directory. There are two versions of Asgard:
a simple *Asgard1* and an advanced *Asgard2*. These two versions share the same code base,
but they have different configuration files. The configuration file for *Asgard1* is
``cowrie_asgard1-0.cfg`` and for *Asgard2* is ``cowrie_asgard2-0.cfg``.

For more detail on each version, see the following links.

*   `Asgard1 <./asgard1.html>`_
*   `Asgard2 <./asgard2.html>`_

Assuming *Asgard1* is used, copy ``cowrie_asgard1-0.cfg`` to ``cowrie.cfg``,
and edit the following sections:

*   ``proxy``: Specify the backend type ``simple_docker``, and the SSH server and its exposed port
(eg. 2226).
This only applys if the SSH server is deployed as a Docker container. If it is deployed as a normal Linux server,
then specify its IP address and port.
In case that it is deployed in the same network, then we can use the container name as the backend host,
and the port that is exposed by the container. These information must be set in the `docker` section.

.. code-block:: ini

    [proxy]
    backend = simple_docker

    # =====================================
    # Simple Backend Configuration
    # =====================================
    backend_ssh_host = honeypot
    backend_ssh_port = 2226

*   ``docker``: how to connect to the backend system running as a Docker container.
    This creates a username or modifies an existing account before the proxy actually
    connects to the backend system. The creation/modification of an account is done
    by executing ``docker exec container_name CMD``, where ``CMD`` can be ``useradd`` or
    ``chpasswd``. In this example, the container name is ``honeypot``, and it also requires
    a ``unix_socket`` to connect to the Docker engine.

.. code-block:: ini

    [docker]
    debug = true
    unix_socket_path = unix://var/run/docker.sock
    container_name = honeypot
    ssh_port = 22

Configuration for Asgard1
--------------------------

To run a simple Asgard server, aka `Asgard1 <./asgard1.html>`_, modify
the following ``rl`` section:

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

    # Agent Random State for reproducibility
    agent_random_state = 42
    # use for SGDRegressor to output information related to the model training
    # Norm: 0.10, NNZs: 4, Bias: 0.058824, T: 1, Avg. loss: 0.179133
    # 0: no verbose, 1: verbose
    agent_verbosity_level = 1

    # Enable cuda
    cuda = false

Configuration for Asgard2
--------------------------

To run an advanced Asgard server, aka `Asgard2 <./asgard2.html>`_, in addition to
the ``rl`` section, some other sections are also needed:

.. code-block:: ini

    [monitor]
    debug = true
    ignored_commands = /usr/sbin/sshd,-bash,sshd:,bash

    [parser]
    debug = true

    [shell]
    debug = false

    [proxy_shell]
    # set the configuration of the proxy shell that will loop indefinitely to
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
    ## It stores data needed to resume training.
    resume_file = var/train_result/models/saved/snowwhite_asgard

    ## Number of epochs between saving training data such as model checkpoints.
    number_epoch = 100

    ## environment name ##
    # RobertaEnvV10: Uses the DQN algorithm and also includes the
    # risk assessment model to encode the command line.
    # RobertaEnvWebV10: Uses the DQN algorithm, but the risk assessment
    # model runs as a web service. This is the recommended setting, as it
    # makes deployment easier to manage.
    environment = RobertaEnvV10

    ## Comment this out if the environment is set to `RobertaEnvWebV10`
    [command_encoder]
    model_path = data/word2vec/20220125-155606/cmd2vec_model_v7_all_20220125-155606_10_90_8.model

    ## State of compromise (SoC).
    # This value indicates when the agent should consider
    # that it is deeply compromised. Its value is a real number between [0, 1].
    # For instance, if it is set to 0.5, this means that if its resource consumption
    # is more than 50%, then the agent considers the system deeply compromised.
    # To capture more advanced attacks, this value should be set closer to 1.
    performance_threshold = 0.5

    ## This is how the SoC is calculated. It uses different
    # resource metrics to evaluate its SoC.
    # Metric 1: Average CPU consumption
    # Metric 2: Average RAM consumption
    # Metric 3: Block disk read in bytes
    # Metric 4: Block disk write in bytes
    # Metric 5: Network inbound in bytes
    # Metric 6: Network outbound in bytes

    # As metrics 3-6 are cumulative and lack natural maximums,
    # we need to define artificial upper limits to express current
    # usage as a percentage. These upper values should also reflect
    # the extent to which the honeypot is allowed to be compromised.

    # 15GB
    BLK_READ_BYTE_MAX = 15e+9
    # 15GB
    BLK_WRITE_BYTE_MAX = 15e+9

    # 1GB
    NET_INBOUND_BYTE_MAX = 1e+9
    # 1GB
    NET_OUTBOUND_BYTE_MAX = 1e+9

    # Command risk level threshold is an integer between [0, 4]
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
    # redis server serves as the communication medium between other programs such as
    # the monitor
    host = localhost
    port = 6379

    # the redis channel where the monitor publishes running processes
    channel_process_name = channel_process

    # the redis channel where the proxy shell publishes the pid of the running process
    # that needs to be terminated
    channel_process_kill = channel_terminate

Running and stopping the server
--------------------------------

The same commands are used to start and stop the server for both *Asgard1* and *Asgard2*,
once the appropriate configuration file has been copied to ``cowrie.cfg``.
*Asgard2* requires additional components to be running, such as the monitor and
risk assessment components. These components can be run as Docker containers
or as normal Linux servers.
For more details, see the `deployment_v2 <./deployment_v2.html>`_ section.

To start the server, run the following command:

.. code-block:: console

    $ bin/cowrie start

After the server is started, it will run in the background.
A pid file will be created to store the process ID.

To stop the server, run the following command:

.. code-block:: console

    $ bin/cowrie stop
