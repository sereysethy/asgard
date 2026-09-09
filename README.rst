ASGARD - An Adaptive Self-guarded Honeypot: An Abstract Model
#############################################################

This repository contains the implementation of the Asgard model,
which is based on `Cowrie <https://github.com/cowrie/cowrie/>`_,
a medium to high interaction SSH and Telnet honeypot.
Cowrie is maintained by Michel Oosterhof.

What is Asgard?
***************
Asgard is an abstract model which can be instantiated to build different
kinds of adaptive, self-guarded honeypots.
It differs from traditional honeypots and other smart honeypots mainly
in how honeypot security risk is managed: a honeypot is considered
an asset rather than just a security tool, and as a result, it must be protected.

In other words, it learns to balance two contradictory objectives for a honeypot:
(1) attack data collection and (2) security of the honeypot.

To achieve the first objective, the honeypot has to be probed,
attacked, and compromised. However, once it is fully compromised,
the second objective comes into play:
the honeypot can minimize the security risk to the network
where it is deployed by limiting any outgoing attacks.
All of this is intelligently managed thanks to its decision module,
which uses learning algorithms, specifically reinforcement 
learning algorithms, and a rich environment state.

The abstract model is the outcome of the PhD research work of Sereysethy Touch.

To learn more about the Asgard model, please refer to the following papers:

*   Touch, S., & Colin, J. N. (2025, September).
    An adaptive self-guarded and risk-aware honeypot using DRL.
    In: *Laborde, R., et al. Computer Security. ESORICS 2025 International Workshops. ESORICS 2025.*
    Lecture Notes in Computer Science, vol 16232. Springer, Cham. `https://doi.org/10.1007/978-3-032-16092-8_11 <https://doi.org/10.1007/978-3-032-16092-8_11>`_
*   Touch, S., & Colin, J. N. (2022).
    A comparison of an adaptive self-guarded honeypot with conventional honeypots.
    *Applied Sciences*, *12* (10), 5224. `https://doi.org/10.3390/app12105224 <https://doi.org/10.3390/app12105224>`_
*   Touch, S., & Colin, J. N. (2021, October).
    Asguard: Adaptive Self-guarded Honeypot. In *WEBIST* (pp. 565-574). `https://doi.org/10.5220/0010719100003058 <https://doi.org/10.5220/0010719100003058>`_

Documentation
*************
To learn how to install and use Asgard, please refer to the `documentation <https://asgard.readthedocs.io/en/latest/index.html>`_.