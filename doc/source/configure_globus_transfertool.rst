Configure Rucio To Use Globus Online as a Transfer Tool
=======================================================

This document walks through an example configuration of Rucio to use Globus Online as a transfer tool. There are four configuration points shown here: registration of your application with Globus, RSE setup (properties and parameters), the Rucio configuration file `rucio.cfg` and the Globus configuration file `config.yml`.

Use of both Globus Server endpoints and Globus Personal endpoints has been tested with the below approach.  Creation of the Globus endpoints is outside the scope here.  Some knowledge of Rucio setup and familiarity with Globus configuration is presumed.

Register Application with Globus
--------------------------------

Using Globus Online as a transfer tool requires `registering <https://developers.globus.org>`_ the client application with Globus Online.  Be sure to select Native App and include a scope for `urn:globus:auth:scope:transfer.api.globus.org:all`.  Once you have the Client ID you’ll need to install the globus sdk and run the below Python code to obtain a refresh token.

There is a `helpful walk-through <https://globus-sdk-python.readthedocs.io/en/stable/tutorial/>`_ that goes into more detail around OAuth and token retrieval.

Obtain a refresh token to access Globus resources::

  # obtain authorization code
  import globus_sdk
  CLIENT_ID = '' # your client ID obtained from registering application
  client = globus_sdk.NativeAppAuthClient(CLIENT_ID)
  client.oauth2_start_flow(refresh_tokens=True)
  client.oauth2_get_authorize_url() # Use the URL returned here to obtain an authorization code
  AUTH_CODE = '' # Use the authorization code returned by authenticating to Globus Online

  # use the authorization code to create a refresh token
  token_response = client.oauth2_exchange_code_for_tokens(AUTH_CODE)
  refresh_token = token_response.by_resource_server['transfer.api.globus.org']['refresh_token']


RSE Setup
---------
Below shows a typical setup for a test RSE.  Options for CLI given when supported.

The following code will create a non-determinisic RSE.

Python::

  # set up the target non-deterministic rse (TEST_RSE)
  from rucio.client.rseclient import RSEClient
  rseclient = RSEClient()
  rse_name = 'TEST_RSE' # rse name MUST BE UPPER CASE
  rse_properties = {'ASN': 'ASN', 'availability': 7, 'deterministic': False, 'volatile': False, 'city': 'Upton', 'region_code': 'DE', 'country_name': 'US', 'continent': 'NA', 'time_zone': 'America/New_York', 'ISP': None, 'staging_area': False, 'rse_type': 'DISK', 'longitude': 40.868352, 'latitude': -72.878871}
  r = rseclient.add_rse(rse_name, **rse_properties) # r is true on success

CLI alternative: RSE creation not supported at time of writing of this document as there is no way to pass the properties.

The following code creates a schema to connect to Globus for the RSE created above.

Python::

  from rucio.client.rseclient import RSEClient
  rseclient = RSEClient()
  rse_name = 'TEST_RSE' # rse name MUST BE UPPER CASE
  # Globus scheme
  prefix = '/~/scratch-space/' # Be sure to use a relative path for your endpoint
  params = {'scheme': 'globus', 'prefix': prefix, 'impl': 'rucio.rse.protocols.globus.GlobusRSEProtocol', 'third_party_copy': 1, 'domains': {"lan": {"read": 1,"write": 1,"delete": 1},"wan": {"read": 1,"write": 1,"delete": 1}}}
  p = rseclient.add_protocol(rse_name, params) # p is true on success

CLI alternative: (the `hostname` value is required for the CLI command but is arbitrary as it is ultimately not used in the scheme)::

  > rucio-admin rse add-protocol --scheme 'globus' --prefix '/~/scratch-space' --impl 'rucio.rse.protocols.globus.GlobusRSEProtocol' --domain-json '{"wan": {"read": 1, "write": 1, "third_party_copy": 1, "delete": 1}, "lan": {"read": 1, "write": 1, "third_party_copy": 1, "delete": 1}}' --hostname 'globus_online' TEST_RSE

The following code sets some attributes for the RSE.

Python::

  from rucio.client.rseclient import RSEClient
  rseclient = RSEClient()
  rse_name = 'TEST_RSE' # rse name MUST BE UPPER CASE

  result = rseclient.add_rse_attribute(rse = rse_name, key = 'naming_convention', value = 'bnl') # This is the value for relative SURL
  result = rseclient.add_rse_attribute(rse = rse_name, key = 'globus_endpoint_id', value = 'd6ae63d8-503f-11e9-a620-0a54e005f849')
  result = rseclient.add_rse_attribute(rse = rse_name, key = 'istape', value = False)

CLI alternative::

  > rucio-admin rse set-attribute --rse TEST_RSE --key naming_convention --value bnl
  > rucio-admin rse set-attribute --rse TEST_RSE --key globus_endpoint_id --value d6ae63d8-503f-11e9-a620-0a54e005f849
  > rucio-admin rse set-attribute --rse TEST_RSE --key istape --value false

Rucio Configuration File
------------------------

The Rucio configuration file `rucio.cfg` should contain the following for the conveyor mechanism.  More schemes can be included but `globus` is required.  You only need the `file` scheme if you plan on using the upload method for replicas.  If the transfertype value is `bulk` Rucio will bundle many files into a transfer task.  If `single` then each file will be submitted on individual transfer tasks.::

  [conveyor]
  scheme = file,globus
  transfertool = globus
  transfertype = bulk
  globus_auth_app = MyGlobusAuthApp

`globus_auth_app` is the application given in `config.yml` (see below)

Globus Configuration File
-------------------------

The Globus configuration file `./lib/rucio/transfertool/config.yml` is a file of YAML syntax and should include at minimum the registered application name, the client ID and refresh token::

  globus:
    apps:
      RucioGlobusXferNativeApp:
        client_id: a758...
        refresh_token: Agjo...
