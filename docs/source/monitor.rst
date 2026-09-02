=======
Monitor
=======

Along with *Asgard2*, we also provide a monitor component
which acts as an intermediate with a real monitor component
through a Redis server. The monitor component has its own 
Git repository at the following URL:

`https://github.com/sereysethy/monitor_stats <https://github.com/sereysethy/monitor_stats>`_

In this repository, there are two monitoring programs to collect
data on: 

- Resource consumption (CPU, Memory, Network I/O, Disk I/O)
- Running processes

In addition to that, there is another program that will terminate
a running process by reading redis queue. This queue contains
a list of PIDs of processes to be terminated. As a result,
this program has to be run by the host as a root user.
Its detail how to set it up can be found on its Git repository.

Build Docker monitor images
===========================

It is important to pull the `repository <https://github.com/sereysethy/monitor_stats>`_ and build Docker images
of the two monitors, and also set up the program to automatically kill
the process.

The monitors also require a configuration file ``config.ini``.

Intermediate Monitor component
==============================
Below is the monitor component classes that interact with the
real monitor components through a Redis server.

.. automodule:: smartproxy.monitor.monitorstats