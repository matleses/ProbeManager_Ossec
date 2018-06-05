=======================
OSSEC for Probe Manager
=======================


|Licence| |Version|

.. image:: https://api.codacy.com/project/badge/Grade/707a0a4841194a1080fa90fb8ce572c5?branch=develop
   :alt: Codacy Badge
   :target: https://www.codacy.com/app/treussart/ProbeManager_Ossec?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=treussart/ProbeManager_Ossec&amp;utm_campaign=Badge_Grade

.. image:: https://api.codacy.com/project/badge/Grade/707a0a4841194a1080fa90fb8ce572c5?branch=develop
   :alt: Codacy Coverage
   :target: https://www.codacy.com/app/treussart/ProbeManager_Ossec?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=treussart/ProbeManager_Ossec&amp;utm_campaign=Badge_Coverage

.. |Licence| image:: https://img.shields.io/github/license/treussart/ProbeManager_Ossec.svg
.. |Version| image:: https://img.shields.io/github/tag/treussart/ProbeManager_Ossec.svg


Presentation
~~~~~~~~~~~~

Module for `Ossec IDS <https://ossec.github.io/index.html>`_


Compatible version
==================

 * OSSEC version 2.9.3 RELEASE


Features
========

 * Install and update Ossec agent HIDS on a remote server.
 * Configure the settings and test the configuration.
 * Add, Delete, Update scripts and signatures.
 * Tests signatures and scripts compliance.
 * Grouping rules into groups and assign this to probes.


Installation
~~~~~~~~~~~~

Install with `ProbeManager <https://github.com/treussart/ProbeManager/>`_

Usage
=====

For the first installation, it's necessary to create a configuration for the server (by default in localhost).
Give the IP address of the server and the general configuration.

After you can add new Ossec agent.

Administration Page of the module :
-----------------------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Ossec/develop/data/admin-index.png
  :align: center
  :width: 80%

Page to add an Ossec Server Configuration :
-------------------------------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Ossec/develop/data/admin-conf-server-add.png
  :align: center
  :width: 70%

* External IP: The IP address seen by the agents to connect.
* Conf file text: Give the configuration of the probe.

Page to add a rule via Rules utility :
--------------------------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Ossec/develop/data/admin-rule-utility-add.png
  :align: center
  :width: 70%

* Rulesets: Choose the sets of rules that will contain this rule.
* Action: addfile, addsite, adddns.
* Log format: (When addfile is selected) syslog, iis, apache ...
* Domain/Log path: Give the path of the file when addfile and a domain name for addsite and adddns.

