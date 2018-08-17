# Rucio

##  Data Management for science in the Big Data era.

Rucio is a project that provides services and associated libraries for allowing scientific collaborations to manage large volumes of data spread across facilities at multiple institutions and organisations. Rucio has been developed by the `ATLAS <https://atlas.cern/>`_ experiment. It offers advanced features, is highly scalable and modular.

## QuickStart

Download the tgz archive or clone this repository and run either of the two commands:

```bash
$ helm install rucio-server-0.1.0.tgz
```

```bash
$ helm install rucio-server/
```

## Introduction

This chart bootstraps a Rucio server deployment and service on a Kubernetes cluster using the Helm Package manager.

## Installing the Chart

To install the chart with the release name `my-release`:

```bash
$ helm install --name my-release rucio-server-0.1.0.tgz
```

The command deploys a Rucio server on the Kubernetes cluster in the default configuration, i.e., 2 replicas using an un-initialised SQLite database without an ingress. To fully use this chart an already bootstraped database is necessary. The server can then be configured to use the DB.

To install the chart so that is will connected to a MySQL DB running at `mysql.db` with the user `rucio` and password `rucio`:

```bash
$ helm install --name my-release --set config.database.default="mysql://rucio:rucio@mysql.db/rucio" rucio-server-0.1.0.tgz
```

## Configuration

The default configuration values for this chart are listed in `values.yaml` our you can get them with:

```bash
$ helm inspect values rucio-server-0.1.0.tgz
```

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install` as shown before.

Alternatively, a YAML file that specifies the values for the parameters can be provided while installing the chart. For example,

```bash
$ helm install --name my-release -f values.yaml rucio-server-0.1.0.tgz
```

## Ingress

The default installation does not include an ingress controller. It can be enabled by setting `ingress.enabled:true`. More configuration parameters can be found in the `values.yaml`.

If you want to use TLS with the ingress a valid certifcate/key is needed. It can be configurated directly in the `values.yaml`. Alternatively, it is also possible to manage it outside of Helm:

```bash
$ kubectl create secret tls rucio-server.tls-secret --key=tls.key --cert=tls.crt
```

## Authentication Ingress

The ingress controller for the authentication servers is configurated separately. So it's possible, if necessary, to use different entrypoints for the regular servers and the authentication server. The ingress can be enabled with `authIngress.enabled:true`. The rest of the configuration parameters are the same as for the regular servers.

## Uninstalling the Chart

To uninstall/delete the `my-release` deployment:

```bash
$ helm delete my-release --purge
```

The command removes all the Kubernetes components associated with the chart and deletes the release.
