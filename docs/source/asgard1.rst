===========================
Asgard1.0's Decision Engine
===========================

*Asgard1.0* stands for An Adaptive Self-guarded honeypot [1].
It was the first and basic version of an adaptive honeypot 
that found a trade-off between a medium-interaction honeypot and 
a high-interaction honeypot [2].

Asgard1.0 is a Linux-based system that allows the attackers to
connect to and execute Shell commands. It uses a reinforcement learning 
algorithm called :math:`Q`-learning,to learn to respond to attacker's command inputs.

Below is the MDP of Asgard1.0 which represents the environment-agent
interactions.

*   A set of states :math:`S`: a set of linux commands :math:`s \in S` that can be mapped to the following
    set of commands:

    *   :math:`L`: a set of shell commands and some other installed programs 
        during the system setup, some example of commands are ``cd``, ``pwd``, 
        ``echo``, ``cp``, etc.
    *   :math:`D`: a set of download commands that are used to
        download programs from external servers, for instance we have ``wget``, 
        ``curl``, ``ftpget``, etc.
    *   :math:`C`: a set of custom commands which are the commands 
        that attackers have to download from external servers before 
        they can be executed, all commands of this type will be mapped 
        to an element custom, hence :math:`C = \{custom\}`.
*   A set of actions :math:`A = \{allow, block, substitute\}` where:

    -   :math:`allow` allows a command to be executed on the target system.
    -   :math:`block` blocks a command from being executed by returning an
        error message ``Command not found``.

*   A reward function that rewards an agent at time-step :math:`t` when it is 
    in a state :math:`s_t \in S` and taking an action 
    :math:`a_t \in A`.

.. math::

   r_{a}(s_t, a_t) =
   \begin{cases}
       1  & \text{if } s_t \in D \ \text{and}\ a_t \in \{allow\} \\
      -1  & \text{if } s_t \in C \ \text{and}\ a_t \in \{allow\} \\
       0  & \text{otherwise}
   \end{cases}

*   Learning algorithm: it uses :math:`Q`-learning as explained in this
    section :class:`smartproxy.learning.rl.valuebase.QLearner`.
    
Citations
=========

*   [1] Touch, S., & Colin, J. N. (2021, October). 
    Asguard: Adaptive Self-guarded Honeypot. In *WEBIST* (pp. 565-574).
*   [2] Touch, S., & Colin, J. N. (2022). 
    A comparison of an adaptive self-guarded honeypot with conventional honeypots. 
    *Applied Sciences*, *12* (10), 5224.