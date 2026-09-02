=====================================================
Deployment of *Asgard1* system as Docker containers
=====================================================

One of the easier thing to deploy Asgard is to use pre-built Docker images.
The following steps will guide you to deploy `Asgard1`` as Docker containers.
There is project folder called *docker* that contains folders and the docker-compose file to orchestrate the deployment of all the containers.

Folder structure of the project
-------------------------------

.. code-block:: text

    docker/
        ├── data/
        |   ├── config/
        |   └── cowrie-etc/
        |   └── cowrie-var/
        |   └── local_home/
        ├── docker-compose.yml.asgard1
        ├── docker-compose.yml.asgard2
        ├── Dockerfile.asgard1
        ├── Dockerfile.asgard2
        ├── env1
        └── env2
        └── honeypot/
            └── Dockerfile

- ``data/config/``: contains configuration files for RL agent and its environment.
  It can contains hyper-parameters for RL model, and other configuration files for the environment.
  For instance, the configuration file for the *Asgard1* is located at `data/config/case1/lr01.json`.
  This configuration file has to be specified in the `cowrie_asgard1-0.cfg` file, in the section `[rl]` as `config_agent_filename = data/config/case1/lr01.json`.
- ``Dockerfile.asgard1``: A Dockerfile to build Docker image for *Asgard1*
- ``Dockerfile.asgard2``: A Dockerfile to build Docker image for *Asgard2*
- ``docker-compose.yml.asgard1``: Docker compose to run *Asgard1* and a target system.
- ``docker-compose.yml.asgard1``: Docker compose to run *Asgard2*, other components and a target system.
- ``env1``: contains environment variables for *Asgard1* system.
- ``env2``: contains environment variables for *Asgard2* system.
- ``data/cowrie-etc/``: contains configuration files for *Asgard* honeypot.
- ``data/cowrie-var/``: contains log files and other data for the honeypot honeypot.
- ``data/local_home/``: contains local home directory for the target system running as a Docker container.
  This has to be mapped to home directory of the target system.

Architecture
------------

:numref:`arch_asgard1` shows the architecture of *Asgard 1*, where the different
components interact with each other. The proxy component and decision engine are
built into the Asgard image, whereas OpenSSH represents the target component and
runs in a separate Docker container.

.. _arch_asgard1:

.. figure:: /_images/arch_asgard1.png
   :width: 800px
   :alt: Architecture showing different system components of *Asgard1*.

   System architecture of *Asgard1*

Building and running the containers
-----------------------------------

Docker images can be built using Dockerfiles or be pulled from Docker Hub.
To build a local image, make sure to provide some appropriate environment values as shown
in `env1`. Other environments are used for ``docker compose``.

Build the image locally:

.. code-block:: console

   docker build \
       --platform linux/amd64,linux/arm64 \
       -f Dockerfile.asgard1 \
       --build-arg COWRIE_USER_ID=1001 \
       --build-arg COWRIE_GROUP_ID=1001 \
       --build-arg DOCKER_GROUP_ID=998 \
       --build-arg COWRIE_SRC=asgard \
       -t asgard1:v1.0.0 \
       ..

Or, pull its image from Docker Hub:

.. code-block:: console

    docker pull stouch/asgard1:v1.0.0

Second, pull the image for a target system, which is a Linux server
running OpenSSH server as a Docker container:

.. code-block:: console

    docker pull stouch/target_system:debian_bullseye

A docker-compose file, docker-compose.yml.asgard1, is provided to orchestrate
deployment of all containers. Before running them, ensure the host user's UID/GID
and the Docker group's GID match those used inside the containers.

This ensures that the Asgard system has access to the target container.

.. code-block:: yaml

    services:
        asgard:
            restart: always
            build:
            context: ..
            dockerfile: ${DOCKERFILE}
            args:
                ARCH: ${ARCH}
                COWRIE_SRC: ${COWRIE_SRC}
                COWRIE_USER_ID: ${COWRIE_USER_ID}
                COWRIE_GROUP_ID: ${COWRIE_GROUP_ID}
                DOCKER_GROUP_ID: ${DOCKER_GROUP_ID}
            image: asgard:${VERSION}-${ARCH}
            container_name: asgard
            user: ${COWRIE_USER}
            group_add:
            - ${DOCKER_GROUP_ID}
            ports:
            - "2222:2222"
            - "2223:2223"
            volumes:
            - ./data/cowrie-etc:/cowrie/cowrie-git/etc
            - ./data/cowrie-var:/cowrie/cowrie-git/var
            - /var/run/docker.sock:/var/run/docker.sock

        target:
            image: ${TARGET_HONEYPOT_IMAGE}
            hostname: ${TARGET_HONEYPOT_HOSTNAME}
            container_name: ${TARGET_HOENYPOT_CONTAINER_NAME}
            volumes:
            - ./data/local_home:/home

        networks:
        default:
            external: true
            name: ${DOCKER_NETWORK_NAME}


Make sure to create an external network before starting these containers.

By default, the Asgard's system listens on port 2222.
To test if everything is working properly, run an ssh client as follows:

.. code-block:: console

    $ ssh -p 2222 user@localhost
    user@localhost's password:
    Linux cdnpixel 7.0.12-linuxkit #1 SMP PREEMPT Fri Aug 14 16:27:59 UTC 2026 aarch64

    The programs included with the Debian GNU/Linux system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.

    Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
    permitted by applicable law.
    Last login: Mon Aug 31 17:20:10 2026 from 172.19.0.6
    -bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
    user@cdnpixel:~$ uname -a
    Linux cdnpixel 7.0.12-linuxkit #1 SMP PREEMPT Fri Aug 14 16:27:59 UTC 2026 aarch64 GNU/Linux