Monitoring
===========

There are three different monitoring components:
 * Rucio internal monitoring using Graphite/Grafana
 * Transfer monitoring using the messages sent by Hermes
 * File/Dataset Access monitoring using the traces


-------------------
Internal Monitoring
-------------------

This is to monitor the internals of Rucio servers and daemons, e.g., submission rate of 
the conveyor, state of conveyor queues, reaper deletion rate, server response times, 
server active session, etc. We use Graphite [#f1]_ for this. It’s easy to setup and 
then you have to point your Rucio instance to the Graphite server using the 
"carbon_server” options in the “monitor” section in etc/rucio.cfg.

The different Rucio components will then send metrics using those “record” functions you
will find all over the code. Graphite has a built-in web interface to show graphs but
more comfortable to use is the Grafana [#f2]_ tool. 

The internal monitoring functions are defined in core/monitor.py, it includes: 

1) record_counter. This is to send the StatsD counter metrics. Counters are the most basic and default type. They are treated as a count of a type of event per second, and are, in Graphite, typically averaged over one minute. That is, when looking at a graph, you are usually seeing the average number of events per second during a one-minute period.

2) record_timer. Timers are meant to track how long something took. They are an invaluable tool for tracking application performance. The statsd server collects all timers under the stats.timers prefix, and will calculate the lower bound, mean, 90th percentile, upper bound, and count of each timer for each period (by the time you see it in Graphite, that’s usually per minute).

3) record_timer_block. This is the same to record_timer, just for simple using, to calculate timer of a certain code block.

4) record_gauge. Gauges are a constant data type. They are not subject to averaging, and they don’t change unless you change them. That is, once you set a gauge value, it will be a flat line on the graph until you change it again.

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Set up the Rucio internal monitoring dashboard
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set up a rucio server for development::

    git clone https://github.com/rucio/rucio.git
    docker-compose --file etc/docker/dev/docker-compose.yml up -d
    
The command will fire up four containers: dev_rucio_1, dev_graphite_1, dev_mysql_1, dev_activemq_1. Dev_graphite_1 is the one collecting internal metrics from Rucio. The configurations of Rucio internal metrics sender are defined under the [monitor] section of rucio.cfg. Change the carbon_server and carbon_port according to your setting::
    
    [monitor]
    carbon_server = graphite
    carbon_port = 8125
    user_scope = docker

The Graphite builtin web page is on port 80 of the host. To use Grafana, setup Grafana and enable the graphite data source::

    docker pull grafana/grafana
    docker run -d --name=grafana -p 3000:3000 grafana/grafana

The Grafana web-portal is on port 3000 of the host. Add one data source of the type Graphite, choose access method to "Browser" and set URL to http://ip:80, where ip is the address of the server hosting the Graphite container dev_graphite_1.

A set of pre-defined Grafana Rucio internal plots is provided `here <https://github.com/rucio/rucio/blob/master/tools/monitoring/visualization/rucio-internal.json>`__. Users could import them directly into Grafana. 

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The list of Rucio internal metrics
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
1) Core::

    credential.signswift, credential.signs3 (timer)
    trace.nongrid_trace
    core.request.* (counter) 
    core.request.archive_request.* (timer)
    rule.add_rule, rule.add_rule.*, rule.delete_rule, rule.evaluate_did_detach, rule.evaluate_did_attach.(timer)
    trace.trace (counter)

2) Transfertool::

    transfertool.fts3.delegate_proxy.success.*, transfertool.fts3.delegate_proxy.fail.* (timer)
    transfertool.fts3.submit_transfer.[externalhost] (timer)
    transfertool.fts3.[externalhost].submission.success/failure (counter)
    transfertool.fts3.[externalhost].cancel.success/failure (counter)
    transfertool.fts3.[externalhost].update_priority.success/failure  (counter)
    transfertool.fts3.[externalhost].query.success/failure  (counter)
    transfertool.fts3.[externalhost].whoami.failure (counter)
    transfertool.fts3.[externalhost].Version.failure (counter)
    transfertool.fts3.[externalhost].query_details.failure (counter)
    transfertool.fts3.[externalhost].bulk_query.failure (counter)
    transfertool.fts3.[externalhost].query_latest.failure (counter)
    transfertool.fts3myproxy.[externalhost].submission.success/failure (counter)

3) Judge:: 

    rule.judge.excpetions.*

4) Transmogrified::

    transmogrifier.addnewrule.errortype.* (counter)
    transmogrifier.addnewrule.activity.* (counter)
    transmogrifier.did.*.processed (counter)

5) Tracer::

    daemons.tracer.kronos.* (counter)

6) Reaper::

    reaper.list_unlocked_replicas, reaper.delete_replicas (timer)
    reaper.deletion.being_deleted, reaper.deletion.done (counter)
    daemons.reaper.delete.[scheme].[rse] (timer)

7) Undertaker::

    undertaker.delete_dids, undertaker.delete_dids.exceptions.LocksDetected (counter)
    undertaker.rules, undertaker.parent_content, undertaker.content, undertaker.dids (timer)
    undertaker.content.rowcount (counter)

8) Replicarecover::

    replica.recoverer.exceptions.* (counter)

9) Hermes::

    daemons.hermes.reconnect.* (counter)

10) Coneyor::

     daemons.conveyor.[submitter].submit_bulk_transfer.per_file, daemons.conveyor.[submitter].submit_bulk_transfer.files (timer)
     daemons.conveyor.[submitter].submit_bulk_transfer (counter)
     daemons.conveyor.finisher.000-get_next (timer)
     daemons.conveyor.finisher.handle_requests (timer & counter)
     daemons.conveyor.common.update_request_state.request-requeue_and_archive (timer)
     daemons.conveyor.poller.000-get_next (timer)
     daemons.conveyor.poller.bulk_query_transfers (timer)
     daemons.conveyor.poller.transfer_lost (counter)
     daemons.conveyor.poller.query_transfer_exception (counter)
     daemons.conveyor.poller.update_request_state.* (counter)
     daemons.conveyor.receiver.error
     daemons.conveyor.receiver.message_all
     daemons.conveyor.receiver.message_rucio
     daemons.conveyor.receiver.update_request_state.*
     daemons.conveyor.receiver.set_transfer_update_time
     daemons.messaging.fts3.reconnect.*
     daemons.conveyor.stager.get_stagein_transfers.per_transfer, daemons.conveyor.stager.get_stagein_transfers.transfer (timer)
     daemons.conveyor.stager.get_stagein_transfers (count)
     daemons.conveyor.stager.bulk_group_transfer (timer)
     daemons.conveyor.submitter.get_stagein_transfers.per_transfer, daemons.conveyor.submitter.get_stagein_transfers.transfer (timer)
     daemons.conveyor.submitter.get_stagein_transfers (count)
     daemons.conveyor.submitter.bulk_group_transfer (timer)
     daemons.conveyor.throttler.set_rse_transfer_limits.[rse].max_transfers/transfers/waitings (gauge)
     daemons.conveyor.throttler.delete_rse_transfer_limits.[rse] (counter)
     daemons.conveyor.throttler.delete_rse_transfer_limits.[activity].[rse] (counter)
     daemons.conveyor.throttler.set_rse_transfer_limits.[activitiy].[rse] (gauge)
     daemons.conveyor.throttler.release_waiting_requests.[activity].[rse].[account] (counter)

11) Necromancer::
    
     necromancer.badfiles.lostfile, necromancer.badfiles.recovering (counter)


-------------------
Transfer monitoring
-------------------

If a transfer is submitted, queued, waiting, done or failed  messages are sent to
ActiveMQ via Hermes and are also archived in the messages_history table. Same is true for deletions.
In the case of ATLAS we have a dedicated monitoring infrastructure that reads
the messages from `ActiveMQ`_, aggregates them and then writes the aggregated data
into ElasticSearch/InfluxDB from where it then can be visualised using Kibana/Grafana.

.. _ActiveMQ: https://activemq.apache.org

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Set up the Rucio internal monitoring dashboard
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1) Configure Rucio

Rucio need to be configured to enable the message broker. In Rucio, message are sent by the Hermes daemon. Settings are defined in therucio.cfg under the [messaging-hermes] section::

    [messaging-hermes]
    username = 
    password = 
    port = 61613
    nonssl_port = 61613
    use_ssl = False
    ssl_key_file = /etc/grid-security/hostkey.pem
    ssl_cert_file = /etc/grid-security/hostcert.pem
    destination = /topic/rucio.events
    brokers = activemq
    voname = atlas
    email_from = 
    email_test = 

The default settings are listed above. If ssl is not used, set use_ssl to False and define username and password. They should be "admin", "admin" for the default activemq settings. If you are not using the containers created by the docker-compose command, change the brokers and port to the server hosting the message queue.

2) Setup Elasticsearch and Kibana

Next is to setup and configure Elasticsearch and Kibana for storing and visualising the messages. This is an example of creating them in containers::

    docker run -d -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" --name elasticsearch docker.elastic.co/elasticsearch/elasticsearch:7.8.1
    docker run -d  --link elasticsearch -p 5601:5601 --name kibana docker.elastic.co/kibana/kibana:7.8.1

3) Import Elasticsearch indices

Before transferring messages from the message queue to Elasticsearch, indices need to be defined in Elasticsearch. This is a list of the message formats of Rucio.


**Transfer events**::

    {
      created_at: when the message was created (yyyy-MM-dd HH:mm:ss.SSSSSS)
      event_type: type of this event (transfer-submitted, transfer-submittion_failed, transfer-queued, transfer-failed, transfer-done)
      payload: {
        account: account submitting the request
        activity: activity of the request
        bytes: size of the transferred file (byte)
        checksum-adler: checksum using adler algorithm
        checksum-md5: checksum using md5 alrogithm
        created_at: Time when the message was created (yyyy-MM-dd HH:mm:ss.SSSSSS)
        dst-rse: destination rse
        dst-type: type of destination rse (disk, tape)
        dst-url: destination url of the transferred file
        duration: duration of the transfer (second)
        event_type: type of this event (transfer-submitted, transfer-submittion_failed, transfer-queued, transfer-failed, transfer-done)
        file-size: same as bytes
        guid: guid of the transfer
        name: name of transferred file
        previous-request-id: id of previous request
        protocol: transfer protocol
        reason: reason of the failure
        request-id: id of this request
        scope: scope of the transferred data
        src-rse: source rse
        src-type: type of source rse (disk, tape)
        src-url: source file url
        started_at: start time of the transfer
        submitted_at: submittion time of the transfer
        tool-id: id of the transfer tool in rucio (rucio-conveyor)
        transfer-endpoint: endpoint holder of the transfer (fts)
        transfer-id: uuid of this transfer
        transfer-link: link of this transfer (in form of fts url)
        transferred_at: done time of this transfer
      }
    }

**Deletion events**::

    {
      created_at: when the message was created (yyyy-MM-dd HH:mm:ss.SSSSSS)
      event_type: type of this event (deletion-done,deletion-failed)
      payload: {
        scope: scope of the deleted replica
        name: name of the deleted replica
        rse: rse holding the deleted replica
        file-size: size of the file
        bytes: size of the file
        url: url of the file
        duration: duration of the deletion
        protocol: prococol used in the deletion
        reason: reason of the failure
      }
    }

The formats of them are defined in `rucio-transfer.json <https://github.com/rucio/rucio/blob/master/tools/monitoring/rucio-transfer.json>`__ and `rucio_deletion.json <https://github.com/rucio/rucio/blob/master/tools/monitoring/rucio-deletion.json>`__ which could be imported into Kibana. 

Rucio also sends messages when adding/deleting rules/DIDs and for file/dataset access. So the monitoring is not limitted to data transferring.

4) Transmit messages from message queue to Elastisearch

This could be done via Logstash. Please refer to https://www.elastic.co/blog/integrating-jms-with-elasticsearch-service-using-logstash.

Alternatively you could use a simple python script `extract.py <https://github.com/rucio/rucio/blob/master/tools/monitoring/extract.py>`__. for this after installing the required tools::

    pip install --upgrade pip
    pip install elasticsearch 
    wget https://files.pythonhosted.org/packages/52/7e/22ca617f61e0d5904e06c1ebd5d453adf30099526c0b64dca8d74fff0cad/stomp.py-4.1.22.tar.gz
    tar -zxvf stomp.py-4.1.22.tar.gz
    cd stomp.py-4.1.22
    python setup.py install

Change the configurations (message broker and elastisearch cluster) in exporter.py and start it. It could be made as a systemd service for convenience.

5) Create Kibana dashboards based on the imported messages.

A set of pre-defined dashboards can be found `here <https://github.com/rucio/rucio/tree/master/tools/monitoring/visualization>`__. in json format which could be imported to Kibana directly. But you may have to resolve different UUIDs in Kibana.

-----------------
Access monitoring
-----------------

The traces are sent by the pilots or the rucio clients whenever a file is downloaded/uploaded. This is simillar with the data transferring monitoring.

----------------------
Rucio database dumping
----------------------

Besides the internal, data transferring/deletion/accessing monitoring, it's also possible to dump the Rucio internal database directly to Elasticsearch. Then information like data location, accounting, RSE summary could be visualised using Kibana or Grafana. 

We provide several examples of dumping Rucio DB tables using the logstash jdbc plugin and making plots based on them.

To start a logstash pipeline, run::
 
    logstash -f rse.conf

Where the rse.conf contains::
 
    input {
      jdbc {
        jdbc_connection_string => ""
        jdbc_user => ""
        jdbc_password => ""
        jdbc_driver_library => "/usr/share/logstash/java/postgresql-42.2.6.jar"
        jdbc_driver_class => "org.postgresql.Driver"
        statement => "SELECT rses.rse, rse_usage.source, rse_usage.used, rse_usage.free, rse_usage.files FROM rse_usage INNER JOIN rses ON rse_usage.rse_id=rses.id WHERE rse_usage.files IS NOT NULL AND rse_usage.files!=0;"
      }
    }
    output {
      elasticsearch {
        hosts => [""]
        action => "index"
        index => "rucio_rse"
        user => ""
        password => ""
      }
    }

The rse pipeline dumps data like how large is the total space, how large is the used space, how many files are saved on each RSE etc. Please fill in the jdbc connection details and Elastisearch connection details in the config file.

More pipeline definitions can be found `here <https://github.com/rucio/rucio/tree/master/tools/monitoring/logstash-pipeline>`__, and users could design their own DB queries for their specific monitoring needs. Also users could directly import the Elasticsearch indices and Kibana dashboard from `these <https://github.com/rucio/rucio/tree/master/tools/monitoring/visualization/db_dump>`__ json files.

.. rubric:: Footnotes

.. [#f1] https://graphiteapp.org/
.. [#f2] https://grafana.com/ 
