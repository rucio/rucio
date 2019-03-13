========================================
Setting up Rucio in a Kubernetes cluster
========================================


Ingress configuration
---------------------
Depending on the platform hosting the Kubernetes cluster, a variety of ingress controllers are available. The cluster currently used only supports Traefik so this readme only describes this but any other ingress controllers should work as well.

First, to be able to serve https request a valid certificate/key is needed. Those have to be added to the cluster as a secret::

    $ kubectl create secret tls tls-secret --key tls.key --cert tls.crt --namespace=kube-system

Next, the provided traefic.toml configuration file has to be added to the cluster::

    $ kubectl create configmap traefik-conf --from-file=ingress/traefik.toml --namespace=kube-system

Then the daemonset configuration can be applied to the cluster::

    $ kubectl apply -f ingress/traefik-ds.yaml

This will create the traefik daemonset and mount the certificate along with the configuration file. The daemonset works with a node selector, i.e., the ingress controller will only be run on nodes that are labeled. You can label a node with::

    $ kubectl label node <node-name> role=ingress

After that the ingress controller should be up and running. You can check by trying to access the dashboard at: http://<node-name>:8080/dashboard/


Starting a server instance
--------------------------

A server deployment is available under server/deployment.yaml. This will start up two pods running Rucio without TLS, expose port 80 as a service and add a new rule to the ingress with TLS termination.
But before applying this deployment a valid rucio.cfg has to be added to the cluster::

    $ kubectl create secret generic server-cfg --from-file=rucio.cfg

After that the deployment can be applied::

    $ kubectl apply -f server/deployment.yaml

After a short time Rucio should be up an running. You can quickly test by opening https://<ingress-node>/ping


Collecting log files
--------------------

Configuration files to setup Filebeat/Logstash to collect log files and send them to a central Elasticsearch instance can be found in the logging folder.

The first step is to setup Logstash. A sample configuration can be found at logging/pipeline.conf. The output module has to be configured with actual ES cluster information. Then it can be stored in the cluster::

    $ kubectl create secret generic logstash-pipeline --from-file=logging/pipeline.conf

Then Logstash can be started with::

    $ kubectl apply -f logging/logstash.yaml

After Logstash is running Filebeat can be configured with::

    $ kubectl apply -f logging/filebeat-clusterrole.yaml
      kubectl apply -f logging/filebeat-config.yaml
      kubectl apply -f logging/filebeat-ds.yaml

After that Filebeat will run on all nodes, collect the logs and send them to Logstash. Logstash will then parse and filter them and store them in ES.
