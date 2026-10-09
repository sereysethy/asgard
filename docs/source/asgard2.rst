===========================
Asgard2.0's Decision Engine
===========================

*Asgard2.0* is a new version of the adaptive self-guarded honeypots, 
which improves the limitations of the previous version (*Asgard1.0*). 
This section describes the design and the *PoC* of the new adaptive 
self-guarded and risk-aware system called *Asgard2.0*. This name reflects 
the improvements made to the previously developed system *Asgard1.0*.

Decision engine
===============

The decision engine is the core of the adaptive honeypot. 
Like *Asgard1.0* and other adaptive systems, it employs a DRL algorithm 
to learn appropriate responses to attacker requests. 
In the following, we describe each component of *Asgard2.0*'s MDP and 
the Deep Q-Network (DQN) [1] algorithm used to train the model.

Environment
^^^^^^^^^^^
A key feature of *Asgard2.0* is its rich state representation, 
enabling the agent to better understand and interact with 
the environment. *Asgard1.0* and other earlier systems only
used the command name, limiting the agent to pre-execution decisions. 
However, post-execution effects -- like reconfiguration, cryptomining, 
or botnet installation -- can deeply impact the system. 
*Asgard2.0* gives the agent greater control and allows for 
continuous background monitoring to minimize long-term damage. 
We consider a deeply compromised honeypot no longer useful and 
recommend its termination, though this depends on how 
``deep compromise`` is defined, which may vary across scenarios. 
This will be discussed when we define reward functions.

In summary, the environment's state representation includes:

-   Full command: This includes the command name, options, and 
    parameters that determine execution behavior. Some parameter 
    combinations may have no system impact. For example, 
    executing ``rm`` without parameters only displays help messages. 

-   Command type: We consider two types of commands: 
    *short-running* and *long-running*. 
    Short-running commands are executed and completed during the 
    interaction (e.g., ``cd``, ``ls``, ``wget``, ``./EXEC``). 
    In contrast, long-running commands continue executing beyond the 
    initial interaction, often as background processes. 
    This distinction allows specific action groups to manage their 
    execution accordingly.

-   Command risk level: This assesses the risk level associated 
    with a command. It is determined by the risk assessment component 
    using an automated risk assessment model based on a LLM
    as described in [1].

-   Target system resource usage:
    This allows the agent to learn the state of the target system after 
    it is being compromised given its system resources are being used.
    As such, we use the following consumption metrics in percentage to represent 
    the target system resource usage:

    -   average CPU, 
    -   average memory,
    -   disk read blocks up to a defined upper limit,
    -   disk write blocks up to a defined upper limit,
    -   network inbound packets up to a defined upper limit,
    -   network outbound packets up to a defined upper limit.

Additionally, a state can also be mapped into different classes based on its attributes, 
which will be useful when we later define its reward functions. 
Whenever possible, a state is categorized by its command name into classes 
similar to those in the state representation of *Asgard1.0*. 
Finally, a state can also be classified according to both its command type 
and its associated risk level.

Actions
^^^^^^^
We define two types of actions given the two types of commands: 
For short-running commands, we define a set

.. math::

   \mathcal{A}_{short} = \left\{allow, block, substitute\right\}
    
which are exactly the same as those defined for `Asgard1.0 <./asgard1.html>`_.
For long-running commands, we define a new set 
:math:`\mathcal{A}_{long} = \left\{terminate, nop\right\}` where :math:`terminate` is 
to terminate a long-running command, and :math:`nop` (no operation) is to allow 
a long-running command to continue to execute.


State of compromise
^^^^^^^^^^^^^^^^^^^
Before we explain how the reward functions are defined to help our system 
achieve its two primary objectives while providing more flexibility compared 
to *Asgard1.0*, we first need to define what is a deep state of compromise.

We hypothesize that a deeply compromised honeypot no longer fulfills its purpose. 
In such cases, the system must either be shut down or recovered by terminating 
the processes responsible for the compromise.
This raises a key question: how do we evaluate the severity 
or depth of a system's compromise?

One possible approach is to use the resource consumption of the target 
system as a metric to characterize its state of compromise. 
As observed in the attack data collected during the real deployment of 
*Asgard1.0*, attackers used compromised 
honeypots to mine cryptocurrency, resulting in excessive CPU usage.
This behavior can potentially indicate a deep compromise when CPU consumption 
exceeds a certain threshold. Similarly, if a honeypot is used to launch brute-force 
or DDoS attacks, compromise can be inferred when the number of outbound 
packets surpasses a defined threshold. As a result, we define a state of compromise
as follows:

\begin{definition}
A state of compromise (:math:`SoC`) for a target system is 
a set of metric attributes corresponding to resource usage, such as CPU, 
memory, disk read/write, network inbound, and network outbound traffic. 
The system is considered deeply compromised when any of these metrics exceed 
their defined thresholds. 
\end{definition}
Formally, the :math:`SoC` can be expressed as 

.. math::

   SoC = \{m_1, m_2, ..., m_i\}

where :math:`m_i = (p_i, c_i, t_i)` and :math:`p_i \in Resource` 
which include CPU, memory, diskRead, diskWrite, netIn, netOut. 
:math:`c_i \in \mathbb{R}^+ \cup \{0\} \text{ (measured value)}`,
:math:`t_i \in \mathbb{R}^+ \text{ (threshold)}`;
the system is considered deeply compromised if :math:`\exists m_i \in SoC : c_i > t_i`.

Reward functions
^^^^^^^^^^^^^^^^
*Asgard1.0* only uses state and action to define its reward function
to allow the agent to learn the two objectives, this approach, however, had limitations, 
as it hindered the system's ability to capture more complex attacks.
To solve this limitation, *Asgard2.0*'s reward function depends 
on three factors: state, :math:`SoC` and action. Our general idea to reward the agent is
as follows: if the system is not deeply compromised and the agent chooses 
to allow all types of commands to execute, the agent is positively rewarded. 
However if the system is deeply compromised, only the short-running command with 
a risk level below a defined global risk level noted :math:`risk_g` should be allowed 
to execute. In any other cases, the agent is negatively punished.

Commonly, a reward in RL problem is given either -1, 0 or 1, 
but in our problem, we choose to give a reward which is proportional to 
the level of :math:`SoC`, if the command class name is not known especially when
the command is composed of other commands (e.g., a pipeline command).
Consequently, we propose the following reward formula which 
is normalized between 0 and 1, for the observed metric :math:`m_i = (p_i, c_i, t_i)` 
is :math:`rp_i = 1 - \frac{c_i}{t_{i}}` where :math:`c_i` is also normalized.

Assume that we fix :math:`t_{g}` to 0.5, this means that once the target system consumes 
more than 50% of its resource by any metric, its reward becomes negative. 
And it is bounded between -1 and 1. To simplify the reward calculation, instead 
of using different threshold value :math:`t_{i}` for each metric, we use *a global threshold* 
:math:`t_{g}` for all the metrics, as a result the proportional reward becomes :math:`rp_i = 1 - \frac{c_i}{t_{g}}`. 

It is important to note that the global threshold :math:`t_{g}` can be chosen to define 
the degree of deep compromise. The higher the value, the greater the extent 
to which the honeypot is allowed to be compromised.

Before we define our final reward functions, we propose two intermediate functions 
namely :math:`r_{class}` which is based on *class of command* 
(eq. :eq:`asgard2.0:eq:rewardbyname`) and 
:math:`r_{risk}` (eq. :eq:`asgard2.0:eq:rewardbyrisk`) which is based 
on risk level of the command. 

.. math::
    :label: asgard2.0:eq:rewardbyname

    \begin{equation}
    r_{class}(s_t, a_t) =
    \scriptsize 
    \begin{cases}
        1 &  \text{if} \ s_t \in D \ \text{and} \ a_t \in \{allow\} \\
        max\left(0, rp_i\right) & \text{if } s_t \in C \ \text{and}\ \exists m_i \in SoC : c_i < t_g \ \text{and} \ a_t \in \{allow\} \\
        min\left(0, rp_i\right) & \text{if} \ s_t \in C \ \text{and}\ \exists m_i \in SoC : c_i > t_g \ \text{and} \ a_t \in \{allow\} \\
        0 & \text{otherwise}
    \end{cases}
    \end{equation}

.. math::
    :label: asgard2.0:eq:rewardbyrisk 
    
    \begin{equation}
    r_{risk}(s_t, a_t) =
    \scriptsize
    \begin{cases}
        max\left(0, rp_i\right) & \text{if } s_t \ge risk_g\, \text{and}\, \exists m_i \in SoC : c_i < t_g \ \text{and}\, a_t \in \{allow\} \\
        min(0, rp_i) & \text{if } s_t \ge risk_g \ \text{and}\ \exists m_i \in SoC : c_i > t_g \ \text{and} \ a_t \in \{allow\} \\
        max\left(0, rp_i\right) & \text{if } s_t < risk_g \ \text{and}\ \exists m_i \in SoC : c_i < t_g \ \text{and} \ a_t \in \{allow\} \\
        -min(0, rp_i) & \text{if } s_t  < risk_g \ \text{and}\ \exists m_i \in SoC : c_i > t_g \ \text{and} \ a_t \in \{allow\} \\
        0 & \text{otherwise}
    \end{cases}
    \end{equation}

Finally, we use the above two intermediate reward functions and the proportional 
reward :math:`rp_i` to define the reward function for each type of command: 
Short-running command (See :eq:`asgard2.0:eq:rewardshort`) and
Long-running command (eq. :eq:`asgard2.0:eq:reward_long`):

.. math::
    :label: asgard2.0:eq:rewardshort

    \begin{equation}
    r_{short}(s_t, a_t) =
    \scriptsize
    \begin{cases}
        max\left(r_{class}, r_{risk}\right) & \text{if } r_{class}(s_t, a_t) > 0\ \text{or} \ r_{risk}(s_t, a_t) > 0  \\
        min\left(r_{class}, r_{risk}\right) & \text{otherwise}
    \end{cases}
    \end{equation}

.. math::
    :label: asgard2.0:eq:reward_long

    \begin{equation}
    r_{long}(s_t, a_t) =
    \scriptsize
    \begin{cases}
        max\left(0, rp_i\right) & \text{if } \exists m_i \in SoC : c_i < t_g \ \text{and} \ a_t \in \{nop\} \\
        -max\left(0, rp_i\right) & \text{if } \exists m_i \in SoC : c_i < t_g \ \text{and} \ a_t \in \{terminate\} \\
        min\left(0, rp_i\right) & \text{if } \exists m_i \in SoC : c_i > t_g \ \text{and} \ a_t \in \{nop\} \\
        -min\left(0, rp_i\right) & \text{if } \exists m_i \in SoC : c_i > t_g \ \text{and} \ a_t \in \{terminate\} \\
    \end{cases}
    \end{equation}

Learning algorithm
^^^^^^^^^^^^^^^^^^
*Asgard2.0* uses DQN, a deep reinforcement learning algorithm
as explained in this `section <./dqn.html>`_.

Citations
=========

[1] Touch, S., Fink, J., & Colin, J. N. (2024, November). 
    Automated Risk Assessment of Shell-Based Attacks Using a LLM. 
    In: *Collart-Dutilleul, S., Ouchani, S., Cuppens, N., Cuppens, F. (eds) Risks and Security of Internet and Systems. CRiSIS 2024.*
    Lecture Notes in Computer Science, vol 15456. Springer, Cham. `https://doi.org/10.1007/978-3-031-89350-6_11 <https://doi.org/10.1007/978-3-031-89350-6_11>`_

[2] Touch, S., & Colin, J. N. (2025, September). 
    An adaptive self-guarded and risk-aware honeypot using DRL. 
    In: *Laborde, R., et al. Computer Security. ESORICS 2025 International Workshops. ESORICS 2025.* 
    Lecture Notes in Computer Science, vol 16232. Springer, Cham. `https://doi.org/10.1007/978-3-032-16092-8_11 <https://doi.org/10.1007/978-3-032-16092-8_11>`_

[3] Volodymyr Mnih et al. (2015). Human-level control through deep reinforcement learning. 
    *Nature*, 518(7540), 529–533. `https://doi.org/10.1038/nature14236 <https://doi.org/10.1038/nature14236>`_
