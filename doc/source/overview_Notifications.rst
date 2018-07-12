-------------
Notifications
-------------

External applications can require synchronisation on events relative to data availability and can subscribe to particular 
events, e.g., dataset state changes, replication rule state changes, etc. Rucio publishes messages via the `STOMP`_ protocol (to e.g. `ActiveMQ`_) when these events happen.

.. _STOMP: https://stomp.github.io
.. _ActiveMQ: https://activemq.apache.org
