Monitoring
===========

There are mainly three different things:
 * Rucio internal monitoring using Graphite/Grafana
 * Transfer monitoring using the messages sent by Hermes
 * File/Dataset Access monitoring using the traces



Internal Monitoring:
--------------------

This is to monitor the internals of Rucio server and daemons, e.g., submission rate of the conveyor, state of conveyor queues, reaper deletion rate, server response times, server active session, etc. We use Graphite[1] for this. It’s easy to setup and then you just have to point your Rucio instance to the Graphite server using the “carbon_server” options in the “monitor” section in etc/rucio.cfg. The different Rucio components then will send metrics using those “record_*” functions you will find all over the code. Graphite has a built-in web interface to show graphs but more comfortable to use is Grafana. You can find an example dashboard from us here [2].


Transfer monitoring:
-------------------_
If a transfer is submitted, queued, waiting, done or failed messages are sent out using Hermes to ActiveMQ and are also archived in the messages_history table. Same is true for deletions. In our case we have a dedicated monitoring infrastructure by the CERN IT monitoring group, that reads the messages from ActiveMQ, aggregates them and then writes the aggregated data into Elasticsearch/InfluxDB from where it then can be visualised using Kibana/Grafana. You told me that you already have you own Elasticsearch running. So, I think for your use case and scale it would be enough if you would take message from ActiveMQ and write them directly to ES using Logstash [3]. From there it should then be easy to create plots.


Access monitoring:
------------------

And last there are the traces. Those are sent by the pilots or the rucio clients whenever a file is downloaded/uploaded. We use them on one hand to update the “accessed_at” column on the DIDS, COLLECTION_REPLICAS, DATASET_LOCKS and REPLICAS table and on the other hand to create popularity reports which then can be used to check which datasetd have been used a lot or not at all. For this to work you would need to setup a tracer server. We have separate machines for that but it can also be on your normal Rucio server. The clients/pilots are then sending traces there using HTTP POST. The server then has to be configured in the “trace” section in etc/rucio.cfg to send to your ActiveMQ server. From there you can then again write the traces to Elasticsearch. To update the “accessed_at” column we have a specific daemon called Kronos. This daemon read the traces from ActiveMQ and then updates the corresponding DB tables.
