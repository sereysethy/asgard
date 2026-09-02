.. Asgard documentation master file, created by
   sphinx-quickstart on Mon Aug 11 18:50:56 2025.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

*Asgard*'s documentation!
==================================

*Asgard* is an abstract model which can be instantiated to build different kinds
of adaptive, self-guarded honeypots. It differs from traditional honeypots
and other smart honeypots mainly in how honeypot security risk is managed:
a honeypot is considered an asset rather than just a security tool that has
to be protected. In other words, it learns to balance two contradictory
objectives for a honeypot: *(1) attack data collection* and *(2) security of the
honeypot*. To achieve the first objective, the honeypot has to be probed,
attacked, and compromised. However, once it is fully compromised, that is
when the second objective comes into play: the honeypot can minimize the
security risk to the network where it is deployed by limiting any outgoing
attacks. All of this is intelligently managed thanks to its decision module,
which uses a learning algorithm, specifically Reinforcement Learning algorithms, 
and a rich environment state.

The abstract model is the outcome of the PhD research work of Sereysethy Touch.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   install
   deployment_v1
   deployment_v2
   asgard1
   asgard2
   risk_assessment
   monitor
   api

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
