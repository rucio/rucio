.. _releasepolicy_toplevel:

Release policy
==============

Rucio follows a release policy with **feature** (named) releases. Approximately every 4 months we produce a feature release with a version number like **1.x.0** (with x > 0). A feature release marks the start of a release line. This release line is maintained with bi-weekly patch releases, containing bug fixes or minor enhancements, with version numbers like **1.19.y** (with y > 0). Versions within one release line are always backwards compatible, thus they do not include database schema changes, API modifications, or other backward-compatibility breaking changes.

Support period
--------------

A release line is only maintained with patch releases until the start of the next release line, thus approximately 4 months. Typically once a year we will designate a release line a **Long-term Support** (LTS) release line. This release line will be supported with **security** and **critical** patches for approximately two years. It is foreseen to have an overlap of at least 12 months between two LTS release lines, to give communities a comfortable time window to deploy the new LTS release.

================  ======================== ================ ====================
Version           Code name                Release date     Supported until
================  ======================== ================ ====================
1.24              Aquadonkey               2020-11          ~2021-02
**1.23 LTS**      The incredible Donkey    2020-07          at least 2022-07
1.22              Green Donkey             2020-02          2020-06
1.21              Donkeys of the Galaxy    2019-11          2020-02
**1.20 LTS**      Wonder Donkey            2019-06          2021-07-10
1.19              Fantastic Donkeys        2019-02          2019-06
1.18              Invisible Donkey         2018-09          2019-02
1.17              Donkey Surfer            2018-06          2018-09
1.16              Doctor Donkey            2018-04          2018-06
1.15              Daredonkey               2018-02          2018-04
1.14              Professor D              2017-11          2018-02
1.13              Donkerine                2017-09          2017-11
1.12              Captain Donkey           2017-07          2017-09
1.11              Batdonkey                2017-05          2017-07
1.10              Irondonkey               2017-02          2017-05
1.9               Superdonkey              2016-10          2017-02
1.8               Spiderdonkey             2016-09          2016-10
1.7               Donkey One               2016-08          2016-09
1.6               The Donkey awakens       2016-05          2016-08
1.5               Return of the Donkey     2016-04          2016-05
1.4               The Donkey strikes back  2016-02          2016-04
1.3                                        2016-01          2016-02
1.2                                        2015-10          2016-01
1.1                                        2015-08          2016-10
1.0                                        2015-07          2015-08
(0.3)                                      2015-03          2015-07
(0.2)                                      2014-10          2015-03
(0.1.7)                                    2014-01          2014-10
================  ======================== ================ ====================
