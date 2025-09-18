# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from rucio.common.types import ConfigOption


class Alembic:
    name = "alembic"
    cfg = ConfigOption(
        name, "cfg",
        "Path to the configuration file (.ini) for Alembic",
    )


class Auditor:
    name = "auditor"
    cache = ConfigOption(name, "cache", "Path to the folder to store the `rucio-auditor` cache. Example: `/opt/rucio/auditor-cache`")
    results = ConfigOption(name, "results", "Path to the folder to store the `rucio-auditor` results. Example: `/opt/rucio/auditor-results`")
    logdir = ConfigOption(name, "logdir", "Path of the directory for logs, joined with `auditor.log``")
    threshold = ConfigOption(name, "threshold", "floating number used in a sanity check, comparing the number of entries with the total number of files on the RSE", float, 0.1)


class BB8:
    name = "bb8"
    dump_production_day = ConfigOption(name, "dump_production_day", "Day of the week of the most recent dump. If not set, the last 7 days are used.")
    url_template_str = ConfigOption(name, "dump_url_template", "URL of the template (structure) of a dump")


class Bootstrap:
    name = "bootstrap"
    userpass_identity = ConfigOption(
        name, "userpass_identity",
        "Name of the root account",
        str, "ddmlab"
    )
    userpass_pwd = ConfigOption(
        name, "userpass_pwd",
        "Password of the root account which name is specified in `userpass_identity`",
        str, "secret"
    )
    userpass_email = ConfigOption(
        name, "userpass_email",
        "Mail of the root account which name is specified in `userpass_identity`",
        str, "ph-adp-ddm-lab@cern.ch"
    )
    x509_identity = ConfigOption(
        name, "x509_identity",
        "Identity of the X.509 certificate",
        str, "emailAddress=ph-adp-ddm-lab@cern.ch,CN=DDMLAB Client Certificate,OU=PH-ADP-CO,O=CERN,ST=Geneva,C=CH"
    )
    x509_email = ConfigOption(
        name, "x509_email",
        "Email of the X.509 identity specified in `x509_identity`",
        str, "ph-adp-ddm-lab@cern.ch"
    )
    gss_identity = ConfigOption(
        name, "gss_identity",
        "Identity of the Kerberos auth method.",
        str, "ddmlab@CERN.CH"
    )
    gss_email = ConfigOption(
        name, "gss_email",
        "Email of the Kerberos auth method which identity is specified in `gss_identity`.",
        str, "ph-adp-ddm-lab@cern.ch"
    )
    ssh_identity = ConfigOption(name, "ssh_identity", "SSH auth using an RSA key.")
    ssh_email = ConfigOption(
        name, "ssh_email",
        "Email of the SSH auth method which identity is specified in `ssh_identity`.",
        str, "ph-adp-ddm-lab@cern.ch"
    )


class Cache:
    name = "cache"
    use_external_for_auth_tokens = ConfigOption(name, "use_external_cache_for_auth_tokens", "Use remote cache provider for auth tokens. If False, use a private in-memory cache.", type_=bool, default=False)


class Common:
    name = "common"
    logformat = ConfigOption(name, "logformat", "Formatter of the log. See [the logging formatter documentation](https://docs.python.org/3/library/logging.html#logging.Formatter)", default='%(asctime)s\t%(name)s\t%(process)d\t%(levelname)s\t%(message)s')
    loglevel = ConfigOption(name, "loglevel", "Set the root logger level to the specified level.", default="DEBUG")
    extract_scope = ConfigOption(name, "extract_scope", "Extraction algorithm for scope. Equivalent to [policy] extract_scope")
    mail_template_dir = ConfigOption(name, "mailtemplatedir", "Path of the folder with mail templates (.tmpl)")


class Credentials:
    name = "credentials"
    gcs = ConfigOption(name, "gcs", "Path of the Google Cloud Storage credentials", default='/opt/rucio/etc/google-cloud-storage-test.json')


class Client:
    name = "client"
    metadata_default_plugin = ConfigOption(name, "metadata_default_plugin", "", default='DID_COLUMN')


class Conveyor:
    name = "conveyor"
    timeout = ConfigOption(name, "poll_timeout", "Timeout", float)
    scheme = ConfigOption(name, "scheme", "Schemes to process", list, [])
    failover = ConfigOption(name, "failover_scheme", "Failover schemes", list, [])
    submit_timeout = ConfigOption(name, "submit_timeout", "Timeout", float)
    bring_online = ConfigOption(name, "bring_online", "Integer, bring online timeout", int, 43200)
    usercert = ConfigOption(name, "usercert", "Path to the certificate for the FTS3 implementation of a Rucio transfertool")


class Core:
    name = 'core'
    # Misspelling here is intentional
    geoip_license_key = ConfigOption(name, "geoip_licence_key", "License key for GeoLite2. Get a free license key at [the signup page](https://www.maxmind.com/en/geolite2/signup).")
    geoip_ignore_error = ConfigOption(name, "geoip_ignore_error", "Whether to ignore errors when downloading and parsing the GeoIP database. Otherwise exceptions will be raised for errors", bool, default=True)
    default_mail_from = ConfigOption(name, "default_mail_from", "Default email")


class Database:
    name = 'database'
    schema = ConfigOption(
        name, "schema",
        "Schema to be applied to a database, if not set in config, try to create automatically.",
    )


class Download:
    name = "download"
    transfer_speed_timeout = ConfigOption(
        name,
        'transfer_speed_timeout',
        "Minimum allowed average transfer speed (in KBps). Used to dynamically compute the timeout if `--transfer-timeout` not set. Is not supported for `--pfn`.",
        type_=float,
        default=500
    )


class MessagingCache:
    name = "messaging-cache"
    brokers = ConfigOption(name, "brokers", "Default message broker name for `rucio-cache-client`. Ignored if `rucio-cache-client` executed with `--broker`", list)
    destination = ConfigOption(name, "destination", "Default message broker topic fo `rucio-cache-client`. Ignored if `rucio-cache-client` executed with `--destination`")
    ssl_key_file = ConfigOption(name, "ssl_key_file", "Default certificate file for `rucio-cache-client`")
    ssl_cert_file = ConfigOption(name, "ssl_cert_file", "Default certificate key file for `rucio-cache-client`")


class MessagingFTS3:
    name = "messaging-fts3"
    brokers = ConfigOption(name, "brokers", "Brokers")
    un = ConfigOption(name, "username", "Username of the broker. Only used if `use_ssl` is not set")
    pw = ConfigOption(name, "password", "Password of the `username`. Only used if `use_ssl` is not set.")
    port = ConfigOption(name, "nonssl_port", " Port of the broker if `use_ssl` is not set.", int)
    ssl_key = ConfigOption(name, "ssl_key_file", "Path of the certificate key file defined in `ssl_cert_file`")
    ssl_cert = ConfigOption(name, "ssl_cert_file", "Path of the certificate file")
    destination = ConfigOption(name, "destination", "Name of the destination topic")


class MessagingHermes:
    name = "messaging_hermes"
    brokers = ConfigOption(name, "brokers", "Brokers")
    port = ConfigOption(name, "port", "Port of the broker if `use_ssl` is set", int)
    un = ConfigOption(name, "username", "Username of the broker. Only used if `use_ssl` is not set")
    pw = ConfigOption(name, "password", "Password of the `username`. Only used if `use_ssl` is not set.")
    nonssl_port = ConfigOption(name, "nonssl_port", " Port of the broker if `use_ssl` is not set.", int)
    ssl_key = ConfigOption(name, "ssl_key_file", "Path of the certificate key file defined in `ssl_cert_file`")
    ssl_cert = ConfigOption(name, "ssl_cert_file", "Path of the certificate file")
    destination = ConfigOption(name, "destination", "Name of the destination topic")


class Hermes:
    name = "hermes"
    elastic_endpoint = ConfigOption(name, "elastic_endpoint", "URL of Elasticsearch. Mandatory if `elastic` is specified in `services_list`")
    influxdb_endpoint = ConfigOption(name, "influxdb_endpoint", "URL of InfluxDB. Mandatory if `influx` is specified in `services_list`.")


class Metadata:
    name = 'metadata'
    plugins = ConfigOption(name, "plugins", "Metadata handler modules", default="rucio.core.did_meta_plugins.json_meta.JSONDidMeta")


class Monitor:
    name = "monitor"
    carbon_server = ConfigOption(
        name, "carbon_server",
        "Hostname or IP address of the `statsd` server"
    )
    carbon_port = ConfigOption(
        name, "carbon_port",
        "Port of the `statsd` server",
        int, 8125
    )
    user_scope = ConfigOption(
        name, "user_scope",
        "Prefix to distinguish and group stats from an application or environment",
        str, "rucio"
    )
    enable_metrics = ConfigOption(
        name, "enable_metrics",
        "Enable `statsd` metrics",
        bool, False
    )
    metrics_port = ConfigOption(
        name, "metrics_port",
        "Port of Prometheus Python Client",
        int, 8080
    )


class Necromancer:
    name = "necromancer"
    cache_time = ConfigOption(name, "cache_time", "Expiration time in seconds passed to the dogpile system", int, default=600)


class NonGridTrace:
    name = 'nongrid-trace'
    loglevel = ConfigOption(name, "loglevel", "Set the root logger level to the specified level", default="DEBUG")
    logformat = ConfigOption(name, "logformat", "Formatter of the log", default="%(message)s")
    tracedir = ConfigOption(name, "tracedir", "Path of the directory for traces", default='/var/log/rucio')
    port = ConfigOption(name, "port", "Port of the broker.", int)
    topic = ConfigOption(name, "topic", "Name of the destination topic.")
    username = ConfigOption(name, "username", "Username of the broker")
    password = ConfigOption(name, "password", "Password of the `username`")


class OIDC:
    name = 'oidc'
    ipsecrets = ConfigOption(name, "ipsecrets", "Path of the idpsecrets JSON")


class Policy:
    name = 'policy'
    support = ConfigOption(name, "support", "Contact information")
    support_rucio = ConfigOption(name, "support_rucio", " Rucio contact information", default="https://github.com/rucio/rucio/issues")
    permission = ConfigOption(name, "permission", "Same as `permission/policy`")
    extract_scope = ConfigOption(name, "extract_scope", "Extraction algorithm for scope. Equivalent to [common] extract_scope")


class Permission:
    name = "permission"
    policy = ConfigOption(name, "policy", "Permission policy", default='def')


class SAML:
    name = 'saml'
    cfg = ConfigOption(name, "config_path", "Path to the SAML config folder")


class Trace:
    name = "trace"
    loglevel = ConfigOption(
        name, "loglevel",
        "Set the root logger level to the specified level",
        str, "DEBUG"
    )
    logformat = ConfigOption(
        name, "logformat",
        "Formatter of the log",
        str, "%(message)s"
    )
    tracedir = ConfigOption(
        name, "tracedir",
        "Path of the directory for traces",
        str, "/var/log/rucio/trace"
    )
    brokers = ConfigOption(
        name, "brokers",
        "List of broker addresses",
        list
    )
    port = ConfigOption(
        name, "port",
        "Port of the broker",
        int
    )
    username = ConfigOption(
        name, "username",
        "Username of the broker",
        str
    )
    password = ConfigOption(
        name, "password",
        "Password of the `username`",
        str
    )


class TracerKronos:
    name = "tracer-kronos"
    prefetch_size = ConfigOption(
        name, "prefetch_size",
        "`activemq.prefetchSize`, see [activemq documentation](https://activemq.apache.org/what-is-the-prefetch-limit-for)",
        int
    )
    subscription_id = ConfigOption(
        name, "subscription_id",
        "A unique id to represent the subscription",
        str
    )
    username = ConfigOption(
        name, "username",
        "Username of the broker. Mandatory if `use_ssl` is not set.",
        str
    )
    password = ConfigOption(
        name, "password",
        "Password of the `username`. Mandatory if `use_ssl` is not set.",
        str
    )
    excluded_usrdns = ConfigOption(
        name, "excluded_usrdns",
        "Example: `CN=proxy,CN=Robot: Ganga Robot,CN=722147,CN=gangarbt`",
        list
    )
    brokers = ConfigOption(
        name, "brokers",
        "Brokers",
        list
    )
    port = ConfigOption(
        name, "port",
        "Port of the broker.",
        int
    )
    reconnect_attempts = ConfigOption(
        name, "reconnect_attempts",
        "Maximum attempts to reconnect",
        int
    )
    ssl_key_file = ConfigOption(
        name, "ssl_key_file",
        "Path of the certificate key file defined in `ssl_cert_file`. Mandatory if `use_ssl` is set.",
        str
    )
    ssl_cert_file = ConfigOption(
        name, "ssl_cert_file",
        "Path of the certificate file. Mandatory if `use_ssl` is set.",
        str
    )
    queue = ConfigOption(
        name, "queue",
        "The topic or queue to subscribe to",
        str
    )


class WebUI:
    name = "webui"
    urls = ConfigOption(name, "urls", "A CSV specifying urls of Rucio WebUI 2.0 clients. Required for correctly handling pre-flight CORS requests.")
    auth_type = ConfigOption(name, "auth_type", "Preferred server side config for webui authentication")
    auth_user = ConfigOption(name, "auth_issuer", "Mandatory if `auth_type` = `oidc`")


class API:
    name = "api"
    endpoints = ConfigOption(name, "endpoints", "Endpoints separated by commas. When empty, all endpoints are loaded", list, [])


class Config:
    """
    All of the sections the config *can* have
    Each section has their own set of options with defaults
    """
    api = API
    auditor = Auditor
    bb8 = BB8
    download = Download
    client = Client
    policy = Policy
    common = Common
    metadata = Metadata
    permission = Permission
    cache = Cache
    credentials = Credentials
    nongrid_trace = NonGridTrace
    necromancer = Necromancer
    oidc = OIDC
    core = Core
    trace = Trace
    messaging_cache = MessagingCache
    conveyor = Conveyor
    messaging_fts3 = MessagingFTS3
    messaging_hermes = MessagingHermes
    tracer_kronos = TracerKronos
    database = Database
    alembic = Alembic
    saml = SAML
    webui = WebUI
    bootstrap = Bootstrap
    monitor = Monitor
    hermes = Hermes
