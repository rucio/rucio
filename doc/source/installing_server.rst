Installing Rucio server
=======================

Prerequisites
~~~~~~~~~~~~~

The Rucio server runs on Python 2.7, 3.6 and 3.7 on any Unix-like platform.

Install via pip
~~~~~~~~~~~~~~~

Heads up: We recommend to use the docker-based install (see next section) as it will configure many things for you automatically. Only use the pip-based install if you have a good reason and know how to configure your webservices manually:

``pip install rucio``

This will pull the latest release from `PyPi <https://pypi.python.org/pypi/rucio/>`_. The Rucio server also needs several Python dependencies. These are all listed in the file ``tools/pip-requires`` and will be pulled in as necessary.

Install via Docker
~~~~~~~~~~~~~~~~~~

A simple server without SSL can be started like this:

``docker run --name=rucio-server -p 80:80 -d rucio/rucio-server``

This will start up a simple server using sqlite based on an automatically generated configuration. You can check if the server is running with `curl http://localhost/ping`

This should return the Rucio version used in the container. Any other curl requests will not work as the database backend is not initialized as this image is meant to be used with an already bootstrapped database backend. I.e., that the container has to be configured to point to the correct database. There are two ways to manage the Rucio configuration: using environment variables or by mounting a full rucio.cfg.

If you want to set the connection string for the database it can be done using the `RUCIO_CFG_DATABASE_DEFAULT` environment variable, e.g., to start a container connecting to a MySQL DB running at `mysql.db` you could use something like this:

``docker run --name=rucio-server -e RUCIO_CFG_DATABASE_DEFAULT="mysql+pymysql://rucio:rucio@mysql.db/rucio" -p 80:80 -d rucio/rucio-server``

The are much more configuration parameters available that will be listed at the end of this readme.

Another way to configure Rucio is to directly mount a complete rucio.cfg into the container. This will then be used instead of the auto-generated one, e.g., if you have a rucio.cfg ready on your host system under `/tmp/rucio.cfg` you could start a container like this:

``docker run --name=rucio-server -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -p 80:80 -d rucio/rucio-server``

The rucio.cfg is used to configure the database backend.

If you want to enable SSL you would need to set the `RUCIO_ENABLE_SSL` variable and also need to include the host certificate, key and the the CA certificate as volumes. E.g.,:

``docker run --name=rucio-server -v /tmp/ca.pem:/etc/grid-security/ca.pem -v /tmp/hostcert.pem:/etc/grid-security/hostcert.pem -v /tmp/hostkey.pem:/etc/grid-security/hostkey.pem -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -p 443:443 -e RUCIO_ENABLE_SSL=True -d rucio/rucio-server``

By default the output of the Apache web server is written directly to stdout and stderr. If you would rather direct them into separate files it can be done using the `RUCIO_ENABLE_LOGS` variable. The storage folder of the logs can be used as a volume:

``docker run --name=rucio-server -v /tmp/rucio.cfg:/opt/rucio/etc/rucio.cfg -v /tmp/logs:/var/log/httpd -p 80:80 -e RUCIO_ENABLE_LOGFILE=True -d rucio/rucio-server``

Environment Variables
~~~~~~~~~~~~~~~~~~~~~

As shown in the examples above the rucio-server image can be configured using environment variables that are passed with `docker run`. Below is a list of all available variables and their behaviour:

`RUCIO_ENABLE_SSL`
------------------
By default, the rucio server runs without SSL on port 80. If you want to enable SSL set this variable to `True`. If you enable SSL you will also have to provide the host certificate and key and the certificate authority file. The server will look for `hostcert.pem`, `hostkey.pem` and `ca.pem` under `/etc/grid-security` so you will have to mount them as volumes. Furthermore you will also have to expose port 443.

`RUCIO_CA_PATH`
---------------
If you are using SSL and want use `SSLCACertificatePath` and `SSLCARevocationPath` you can do so by specifying the path in this variable.

`RUCIO_DEFINE_ALIASES`
----------------------
By default, the web server is configured with all common rest endpoints except the authentication endpoint. If you want to specify your own set of aliases you can set this variable to `True`. The web server then expects an alias file under `/opt/rucio/etc/aliases.conf`

`RUCIO_ENABLE_LOGFILE`
----------------------
By default, the log output of the web server is written to stdout and stderr. If you set this variable to `True` the output will be written to `access_log` and `error_log` under `/var/log/httpd`.

`RUCIO_LOG_LEVEL`
-----------------
The default log level is `info`. You can change it using this variable.

`RUCIO_LOG_FORMAT`
------------------
The default rucio log format is `%h\t%t\t%{X-Rucio-Forwarded-For}i\t%T\t%D\t\"%{X-Rucio-Auth-Token}i\"\t%{X-Rucio-RequestId}i\t%{X-Rucio-Client-Ref}i\t\"%r\"\t%>s\t%b`
You can set your own format using this variable.

`RUCIO_HOSTNAME`
----------------
This variable sets the server name in the apache config.

`RUCIO_SERVER_ADMIN`
--------------------
This variable sets the server admin in the apache config.

`RUCIO_CFG` configuration parameters:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Environment variables can be used to set values for the auto-generated rucio.cfg. The names are derived from the actual names in the configuration file prefixed by `RUCIO_CFG`, e.g., the `default` value in the `database` section becomes `RUCIO_CFG_DATABASE_DEFAULT`.
All available environment variables are:

* RUCIO_CFG_COMMON_LOGDIR
* RUCIO_CFG_COMMON_LOGLEVEL
* RUCIO_CFG_COMMON_MAILTEMPLATEDIR
* RUCIO_CFG_DATABASE_DEFAULT
* RUCIO_CFG_DATABASE_SCHEMA
* RUCIO_CFG_DATABASE_POOL_RESET_ON_RETURN
* RUCIO_CFG_DATABASE_ECHO
* RUCIO_CFG_DATABASE_POLL_RECYCLE
* RUCIO_CFG_DATABASE_POOL_SIZE
* RUCIO_CFG_DATABASE_POOL_TIMEOUT
* RUCIO_CFG_DATABASE_MAX_OVERFLOW
* RUCIO_CFG_DATABASE_POWUSERACCOUNT
* RUCIO_CFG_DATABASE_USERPASSWORD
* RUCIO_CFG_MONITOR_CARBON_SERVER
* RUCIO_CFG_MONITOR_CARBON_PORT
* RUCIO_CFG_MONITOR_USER_SCOPE
* RUCIO_CFG_TRACE_TRACEDIR
* RUCIO_CFG_TRACE_BROKERS
* RUCIO_CFG_TRACE_PORT
* RUCIO_CFG_TRACE_USERNAME
* RUCIO_CFG_TRACE_PASSWORD
* RUCIO_CFG_TRACE_TOPIC
* RUCIO_CFG_PERMISSION_POLICY
* RUCIO_CFG_PERMISSION_SCHEMA
* RUCIO_CFG_PERMISSION_LFN2PFN_ALGORITHM_DEFAULT
* RUCIO_CFG_PERMISSION_SUPPORT
* RUCIO_CFG_PERMISSION_SUPPORT_RUCIO
* RUCIO_CFG_WEBUI_USERCERT

Server Configuration for Open ID Connect AuthN/Z
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to be able to use JSON web tokens (JWTs) and related OAuth2.0 authentication and authorization with Rucio, one first needs to have an account with the Identity Provider (IdP) which will act as Rucio Admin account representing the Rucio Application. Currently supported IdPs use Identity Access Management (IAM) system. Once, you have got your Rucio Admin IAM account (and its `sub` claim identifier), you will need to `register two IAM Rucio clients <https://indigo-iam.github.io/docs/v/current/user-guide/client-registration.html>`_ linked to this account. Once it is done, please save the relevant client_id, client_secret and registration access token (RAT some place safe, you will be needing them. In both clients, one needs to setup the redirect_uris to include both `https://<your_server_name>/auth/oidc_token` and `https://<your_server_name>/auth/oidc_code` paths. We will use one client as Rucio Auth IAM client (i.e. client for the authentication and authorization on the Rucio server). This client needs to have `token exchange`, `token refresh` and `authorization code grant` enabled. For the former two you might need to contact the IAM admin as such settings are usually not accessible to IAM users. In addition, you will need to request your IAM admin to allow your client returning refresh tokens with lifetime being visible in their unverified header. In addition Rucio assumes refresh tokens to expire immediatelly after their first use, which has to be also confirmed by your IAM admin. Second client, let's call it Rucio Admin IAM client, will be used by a Rucio probe script `check_voms` in order to synchronize existing Rucio accounts with Rucio identities. Rucio will also use this client's credentials in order to request token for itself. The IAM administrator must include the `scim:read` scope and allow `client credentials` grant type for the Rucio Admin IAM client in order to grant you rights to pre-provision IAM users for Rucio. Examples of the configuration of these two clients follow below:

Example of the Rucio Auth IAM client configuration::

   {
     "client_id": "AbcCDe123...",
     "registration_access_token": "AbcCDe123...",
     "redirect_uris": [
       "https://rucio-auth.cern.ch/auth/oidc_token",
       "https://rucio-auth.cern.ch/auth/oidc_code",
     ],
     "client_name": "rucio-admin-client",
     "client_uri": null,
     "logo_uri": null,
     "contacts": [
       "jaroslav.guenther@gmail.com"
     ],
     "tos_uri": null,
     "token_endpoint_auth_method": "client_secret_basic",
     "scope": "address fts phone openid profile offline_access rucio email wlcg wlcg.groups fts:submit-transfer",
     "grant_types": [
       "refresh_token",
       "urn:ietf:params:oauth:grant-type:token-exchange",
       "authorization_code"
     ],
     "response_types": [
       "code"
     ],
     "policy_uri": null,
     "jwks_uri": null,
     "jwks": null,
     "jwksType": "URI",
     "application_type": null,
     "sector_identifier_uri": null,
     "subject_type": null,
     "request_object_signing_alg": null,
     "userinfo_signed_response_alg": null,
     "userinfo_encrypted_response_alg": null,
     "userinfo_encrypted_response_enc": null,
     "id_token_signed_response_alg": null,
     "id_token_encrypted_response_alg": null,
     "id_token_encrypted_response_enc": null,
     "default_max_age": 60000,
     "require_auth_time": true,
     "default_acr_values": null,
     "initiate_login_uri": null,
     "post_logout_redirect_uris": null,
     "claims_redirect_uris": [],
     "request_uris": [],
     "software_statement": null,
     "software_id": null,
     "software_version": null,
     "code_challenge_method": null,
     "registration_client_uri": "https://wlcg.cloud.cnaf.infn.it/register/fdc297fc-0907-4a68-9022-3ccc7dd2501a",
     "client_secret_expires_at": 0,
     "client_id_issued_at": 1574700620
   }


Example of the Rucio Admin IAM client configuration::

   {
     "client_id": "AbcDe123...",
     "registration_access_token": "AbcDe123...",
     "client_secret": "AbcDe123...",
     "redirect_uris": [],
     "client_name": null,
     "client_uri": null,
     "logo_uri": null,
     "contacts": [
       "jaroslav.guenther@gmail.com"
     ],
     "tos_uri": null,
     "token_endpoint_auth_method": "client_secret_basic",
     "scope": "address scim:read phone email wlcg profile fts:submit-transfer rucio fts fts:submit-transfer",
     "grant_types": [
       "client_credentials"
     ],
     "response_types": [],
     "policy_uri": null,
     "jwks_uri": null,
     "jwks": null,
     "jwksType": "URI",
     "application_type": null,
     "sector_identifier_uri": null,
     "subject_type": null,
     "request_object_signing_alg": null,
     "userinfo_signed_response_alg": null,
     "userinfo_encrypted_response_alg": null,
     "userinfo_encrypted_response_enc": null,
     "id_token_signed_response_alg": null,
     "id_token_encrypted_response_alg": null,
     "id_token_encrypted_response_enc": null,
     "default_max_age": 60000,
     "require_auth_time": true,
     "default_acr_values": null,
     "initiate_login_uri": null,
     "post_logout_redirect_uris": null,
     "claims_redirect_uris": [],
     "request_uris": [],
     "software_statement": null,
     "software_id": null,
     "software_version": null,
     "code_challenge_method": null,
     "registration_client_uri": "https://wlcg.cloud.cnaf.infn.it/register/5b5e5d37-926b-4b42-8a98-a0b4b28baf18",
     "client_secret_expires_at": 0,
     "client_id_issued_at": 1574700703
   }


To make the Rucio server aware of the two clients above, one has to exchange the empty dictionary in `etc/idpsecrets.json` file with one containing the relevant information. Example of such dictionary (for multiple IdPs) follows::

   {
    "<IdP nickname>": {
     "redirect_uris": [
      "https://<server_name>/auth/oidc_token",
      "https://<server_name>/auth/oidc_code"
     ],
     "registration_access_token": "<RAT_string>",
     "client_secret": "<client_secret>",
    "SCIM": {
      "client_secret": "<client_secret>",
      "grant_type": "client_credentials",
      "registration_access_token": "<RAT_string>"
     },
     "issuer": "https://<issuer_server_name>/"
    },
    "wlcg": {
     "redirect_uris": [
      "https://rucio-auth.cern.ch/auth/oidc_token",
      "https://rucio-auth.cern.ch/auth/oidc_code"
     ],
     "registration_access_token": "eyJraWQiOi ...",
     "client_id": "fdc297fc-09 ...",
     "client_secret": "APFVcga_X ...",
     "SCIM": {
      "client_secret": "IQqAcMOa ...",
      "grant_type": "client_credentials",
      "registration_access_token": "eyJraW ...",
      "client_id": "5b5e5d3 ..."
     },
     "issuer": "https://wlcg.cloud.cnaf.infn.it/"
    },
    "xdc": { ... },
   }


After this is done, please make sure your `rucio.cfg` file contains the following section::

   [oidc]
   idpsecrets = /path/to/your/idpsecrets.json
   admin_issuer = <IdP_nickname>
   expected_audience = '<rucio>'
   expected_scope = 'openid profile'

Parameters 'idpsecrets' and 'admin_issuer' have to be present. <IdP_nickname> stands for your preferred IdP (e.g. "wlcg"). The IdP specified under admin_issuer will be contacted to get information about Rucio Users (SCIM) and to request tokens for the Rucio 'root' account. The expected_scope and expected_audence parameters are optional and if not filled, the Rucio server will set them to 'openid profile' and 'rucio' respectively. The expected scopes and audiences have to be configured correspondinly on the side of your registered clienst at your IdP (usually you can control accepted scopes and audiences for your clients via an IdP web interface).

To finalise the process, one should assign the OIDC identities to the relevant Rucio admin_account_name (e.g. 'root', 'ddmadmin'). This identity ID is composed of the IAM account sub claim and issuer url such as demonstrated below::

   rucio-admin identity add --account admin_account_name --type OIDC --id "SUB=b3127dc7-2be3-417b-9647-6bf61238ad01, ISS=https://wlcg.cloud.cnaf.infn.it/" --email "wlcg-doma-rucio@cern.ch"

A second identity has to be added to the same admin_account_name representing the client_credentials flow of the Rucio application, i.e. of the Rucio Admin IAM client from above. This identity consists of the client_id of the Rucio Admin IAM client and the issuer (the token obtained via the client credentials flow using the Rucio Admin IAM client will contain in the SUB claim the client_id instead of the IAM account SUB claim)::

   rucio-admin identity add --account admin_account_name --type OIDC --id "SUB=5b5e5d37-926b-4b42-8a98-a0b4b28baf18, ISS=https://wlcg.cloud.cnaf.infn.it/" --email "wlcg-doma-rucio@cern.ch"

Note: In case you can not/will not run the Rucio check_scim probe script in order to sync Rucio accounts with their IAM identities, you should assign the appropriate OIDC identity manually (as in the example above) to each Rucio account which is meant to use the OIDC authN/Z.

In case you wish to use OIDC by default in order to login to the Rucio WebUI, one has to configure also another block in the `rucio.cfg` file::

   [webui]
   auth_type = oidc
   auth_issuer = <IdP nickname from the idpsecrets.json file>

This is not obligatory section, if not filled a user will get directed to a page with login choices.

In order to ensure the correct lifetime management of the tokens and auth sessions, one also has to run the rucio-oauth-daemon run on the server!

Rucio servers may run also conveyor daemon, which is responsible for submission of the transfers created in connection with existing Rucio rule. In case both, the source and destination RSEs have attribute {'oidc_support': True} assigned, the Rucio account which created such a rule will be used to request a JWT token for OAuth2 authentication with FTS. The issuer of user's token will be used to get a valid OIDC token with the requested audience and scope for FTS transfer. This new token will have either the same identity of the user (received after user's token exchange with IdP) or it will have the identity of the Rucio Admin IAM client (client_id will be in the 'sub' claim) (received after client credentials token flow of the admin). If in any of the two formerly mentioned cases, valid token is present in Rucio DB beforehand, it will be used in the header of the transfer request to FTS and no new token demand will be made to IdP. The OIDC authentication mechanism shall be configured by the following parameters in the rucio.cfg file::

  [conveyor]
  allow_user_oidc_tokens = False
  request_oidc_scope = 'fts:submit-transfer'
  request_oidc_audience = 'fts'

If 'allow_user_oidc_tokens' is set to True the system will attempt to exchange a valid OIDC token (if any) of the account that owns the rule/transfer for a token that has the 'request_oidc_scope' and 'request_oidc_audience'. If set to False, the system will use the IdP issuer of the account that owns the transfer, will get a Rucio admin client token with the 'request_oidc_scope' and 'request_oidc_audience' and authenticate against FTS with the Rucio admin client credentials on behalf of the user. The allowed scopes and audiences have to be again also configured correspondingly for your clients at the IdP side (usually through IdP web interface).

Note aside: For some IdPs it may happen that the scope and audience claims are not a part of the token payload. For this reason Rucio has a fall-back mechanism to get this information using the IdPs introspection endpoint. To allow Rucio to introspect tokens that were not issued by its clients, please talk to the IdP admin who should enable this functionality for your clients.


