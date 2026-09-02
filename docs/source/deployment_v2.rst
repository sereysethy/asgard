==============================================
Deployment of *Asgard2* as Docker containers
==============================================

The following steps will guide you through deploying *Asgard2* as Docker containers.
Please refer to `Asgard1 <./deployment_v1.html>`_ for a brief introduction to
the Docker folder structure.

Architecture
------------

:numref:`arch_asgard2` shows the architecture of *Asgard2*, where the different
components interact with each other. Similar to *Asgard1*, the proxy component
and decision engine are built into the Asgard image, whereas OpenSSH represents
the target component and runs in a separate Docker container.

Additionally, two more components are needed to provide additional information
to the `decision engine <asgard2.html>`_.

* `Command risk assessment <risk_assessment.html>`_ assesses the risk level
  associated with a command.
* `Monitor <monitor.html>`_ provides environmental information, such as
  resource consumption and running processes observed in the target system.

.. _arch_asgard2:

.. figure:: /_images/arch_asgard2.png
   :width: 800px
   :alt: Architecture showing different system components of *Asgard 1*.

   System architecture of *Asgard2*

Building and running the containers
-----------------------------------

Docker images can be built using Dockerfiles or be pulled from Docker Hub.
To build a local image, make sure to provide some appropriate environment values as shown
in `env_v2`. Other environments are used for ``docker compose``.

Build the image locally:

.. code-block:: console

   docker build \
       --platform linux/amd64,linux/arm64 \
       -f Dockerfile.asgard2 \
       --build-arg COWRIE_USER_ID=1001 \
       --build-arg COWRIE_GROUP_ID=1001 \
       --build-arg DOCKER_GROUP_ID=998 \
       --build-arg COWRIE_SRC=asgard \
       -t asgard2:v1.0.0 \
       ..

As explained above, unlike *Asgard1*, many components are needed to operate
*Asgard2*. These components are also available as Docker images and
can be downloaded from Docker Hub. These components can be replaced or
reimplemented as long as they provide the appropriate data via the interface.
For instance, the monitor component can be replaced by `Google/cAdvisor <https://github.com/google/cadvisor>`_
or some other tool that can collect resource usage of running containers.

Pull the images of *Monitor* and *Asgard2* from Docker hub:

.. code-block::

    docker pull stouch/monitor:v1.0.0

    docker pull stouch/asgard2:v1.0.0


Next, pull the image for a target system, which is a Linux server
running OpenSSH server as a Docker container:

.. code-block:: console

    docker pull stouch/target_system:debian_bullseye

Finally, pull the Command Risk Assessment component; it is a web service.
There are two images: a web server, ``Nginx``, and its WSGI module running
a Python application to infer a trained risk assessment model.

It is important to note that it is also possible to run this component
directly inside the Asgard2 system. It is part of the RL environment
configuration file. All you need to do is specify the type of environment
to use in the Cowrie configuration file, in the ``RL/environment`` section.

.. code-block:: ini

    # - Roberta: RobertaEnvV10, RobertaEnvWebV10

    environment = RobertaEnvV10

``RobertaEnvV10`` uses an environment where the risk assessment is
directly part of the system, whereas ``RobertaEnvWebV10`` calls
a risk assessment component via an external component using a web API
defined in its own configuration:

.. code-block:: console

    docker pull stouch/cmd_risk_assessment:web-v1.0.0
    docker pull stouch/cmd_risk_assessment:wsgi-v1.0.0

Visit its `GitHub <https://github.com/sereysethy/cmd_risk_assessment>`_ for details
on how to run these components.

A docker-compose file, ``docker-compose.yml.asgardv1``, is provided to orchestrate
deployment of all containers. Before running them, ensure the host user's UID/GID
and the Docker group's GID match those used inside the containers.

This ensures that the Asgard system has access to the target container.

.. code-block:: yaml

    services:
        redis:
            image: redis
            ports:
            - "127.0.0.1:6379:6379"

        asgard:
            restart: always
            image: ${IMAGE_ASGARD}
            container_name: asgard
            user: ${COWRIE_USER}
            group_add:
            - ${DOCKER_GROUP_ID}
            depends_on:
            - target
            - redis
            ports:
            - "2222:2222"
            - "2223:2223"
            volumes:
            - ./data/cowrie-etc:/cowrie/cowrie-git/etc
            - ./data/cowrie-var:/cowrie/cowrie-git/var
            - ./data/config:/cowrie/cowrie-git/data/config
            - /var/run/docker.sock:/var/run/docker.sock

        target:
            image: ${TARGET_HONEYPOT_IMAGE}
            hostname: ${TARGET_HONEYPOT_HOSTNAME}
            container_name: ${TARGET_HOENYPOT_CONTAINER_NAME}

        monitor_metric:
            image: ${IMAGE_MONITOR}
            user: ${COWRIE_USER}
            group_add:
            - ${DOCKER_GROUP_ID}
            depends_on:
            - target
            - redis
            command: ['python', 'metric.py']
            container_name: monitor_metric
            volumes:
            - ./data_monitor/config.ini:/monitor/monitor/config.ini
            - /var/run/docker.sock:/var/run/docker.sock
            - ./data_monitor/log:/monitor/log

        monitor_process:
            image: ${IMAGE_MONITOR}
            user: ${COWRIE_USER}
            group_add:
            - ${DOCKER_GROUP_ID}
            depends_on:
            - target
            - redis
            command: ['python', 'process.py']
            container_name: monitor_process
            volumes:
            - ./data_monitor:/monitor/monitor
            - /var/run/docker.sock:/var/run/docker.sock
            - ./data_monitor/log:/monitor/log

        networks:
        default:
            external: true
            name: ${DOCKER_NETWORK_NAME}
