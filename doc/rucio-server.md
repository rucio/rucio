Setting up a Rucio server
=========================


# What is the Rucio server?

This instruction is about how to install the central Rucio server and
get it up and running. This server is a WSGI application written in
Python and has to run on a WSGI capable web server such as Apache. The
server provides a REST API and interacts with a database. The actual
tasks are then performed by intermediate-level daemons. These read the
database and can interact with low level components includingx
storage.

This architecture gives big flexibility in choices of authentication,
transfer protocols, and storage systems, and no special software has
to run on the storage systems as long as they provide a supported
protocol and authN/authZ mechanism. However, this can also make
first-time setup a nontrivial task. The Rucio developers recommend all
users to run the Docker containers they provide. To learn about setup
and configuration however, it may still be preferrable to install the
Rucio server and necessary daemons from source. Another reason is that
the provided containers and instructions for use are all built on
CentOS, which may be incompatible with more up to date host operating
systems. In the following we describe how to deploy a Rucio
server on an Ubuntu 20.04 LTS server system.

# Prerequisites

In order to install Rucio from source you must have a system with
Python and the usual setup and compilation tools. We assume this to be
available. Installing in a Python virtual environment may be
preferrable for compatibility of dependencies. In the test setup
described here, we instead started a fresh LXD container and installed
all packages system-wide. Both the host and the container run Ubuntu
20.04 LTS.

# Dependencies

## Install a web server

A web server with support for the Python Web Server Gateway Interface
(WSGI) is necessary. We adapted the Apache configuration files from
the Dockers to the Debian/Ubuntu standard, as described below. Several
optional Apache modules must be installed and configured for Rucio to
work. Thus, as root/sudo:
    apt install apache2 libapache2-mod-wsgi-py3 gridsite 

Then enable the required Apache modules by creating symlinks in
mods-enabled. a2enmod as root does this for you:

	$sudo a2enmod wsgi

Repeat this step for other required modules: 

    authn, cache_disk, headers, proxy, rewrite, ssl, zgridsite

(CHECKME which required modules are not enabled by default?)


## Install required Python packages

The Rucio distribution comes with a dependencies.txt file and setup
will try to install the listed dependencies automatically as
usual. Some of the packages may already be included in a standard
Ubuntu install, but however some packages on PyPI or in the Ubuntu
package archives are incompatible. These have to be installed or
replaced separately.

* **itsdangerous** is too new in PyPI but a compatible package exists in Ubuntu 20.04 
     
    $sudo apt install python3-itsdangerous
		
* **python-requests** is also incompatible, too old in Ubuntu archives and by default too new in PyPI, so reinstall the package like this
   
    $sudo pip3 install --upgrade requests==2.24.0
	
(? FIXME any other dependencies to replace?)
	
## Install database and support

The database is the heart of Rucio operations.  Rucio supports several
popular databases: MySQL, PostgreSQL, etc. PostgreSQL is a good choice
and can be installed like so

    $sudo apt install postgresql postgresql-contrib python3-psycopg2

## Install SSL certificates and utilities

For https and certificate based authentication to work it is of
supreme importance to get SSL certificates and certificate authorites
(CAs) right.  (Checkme: required packages)

After a successful install, CA certificates should be stored in

    /etc/grid-security/certificates

Obtain a public host certificate that matches the hostname of the
server. You have to create a certificate signing request (CSR) and
request a certificate at YOUR certificate authority so the procedure
may vary.  Save the certificate chain file (host certificate before
intermediate certificates) and unencrypted private key in for example
    
	 /etc/grid-security/hostcert.pem
	 /etc/grid-security/hostkey.pem
	 
(Checkme: file permissions?)

For certificate based authentication, also get a personal certificate
(or export the one you have) and make sure it is saved as
    
	 $HOME/.globus/usercert.pem and
	 $HOME/.globus/userkey.pem
	 
This personal certificate will later be used to create a short-lived
so called grid proxy certificate for user authentication. With CAs
properly configured the proxy certificate will allow the https
connection to transfer your identity (certificate Distinguished Name)
securely to the server.

(? Checkme: instructions on certificate export and **grid-proxy-init**)

# Get the Rucio software

Next it is time to download and install the Rucio server and daemons.

This is a normal source install procedure

    $git clone https://github.com/rucio/rucio.git
    $cd rucio
    $sudo pip3 install .
   
If everything worked (Note the dependencies section above) the daemons
will be installed in **/usr/local/bin**, all named rucio-something, configuration in **/usr/local/rucio**, and
the server packages in **/usr/local/lib/pythonVERSION/dist-packages/rucio**

where VERSION is the Python version number e.g. 3.8.


# Create the Rucio configuration file

Rucio will look for its configuration files in **/opt/rucio/etc**. So make a link from **/opt** to **/usr/local/rucio**:
      
    $sudo -s
	#cd /opt
	#ln -s /usr/local/rucio .

Make sure that there is a directory **/opt/rucio/etc/mail_templates**.
Then at a minimum the following two files have to be created and edited:

* alembic.ini (Database settings)
* rucio.cfg 

Templates are provided and examples can also be found in the appendix.
 
# Set up the database

Next the database has to be configured and populated with the right records including root user credentials.

## Create a PostgreSQL database
As mentioned we will use PostgreSQL so by default you have to perform the following operations as the Postgres superuser:

    $sudo -u posgres -s
	
First create a database named **rucio**:

    $createdb rucio
	
Then add a user, also named **rucio**:

    $createuser --interactive -P

Follow the instruction prompts that appear:

    Enter name of role to add: rucio
	Enter password for new role: secret
    Enter it again: secret
    Shall the new role be a superuser? y
	Shall the new role be allowed to create databases? n
    Shall the new role be allowed to create more new roles? n

(Checkme: required permissions+)


Next enter the PostgreSQL CLI and make sure that you can connect to the database:

    $psql
    \c rucio
	
Set permissions for user **rucio**:

    #GRANT ALL PRIVILEGES ON DATABASE rucio TO rucio;
	
Add a schema, also named **rucio**:
    
	#CREATE SCHEMA rucio; 
    #GRANT ALL PRIVILEGES ON SCHEMA rucio TO rucio;

Then, exit the CLI.

Also make sure that local users can log in with password on the TCP port of the PostgreSQL server. This is configured in the file

   
    /etc/postgresql/VERSION/main/pg_hba.conf (Postgres Host based authentication)

VERSION here is the version number of the running PostgreSQL server; note that
there may be several versions installed in parallel so make sure that
it matches the server used for Rucio.

There should be a line like the following

    # IPv4 local connections:
    host    all             all             127.0.0.1/32            md5

With this properly configured local login should work (note that the
**-h localhost** argument may be necessary to connect on the TCP
port instead of the UNIX socket):
    
	$psql -h localhost --user rucio --password secret
    
## Configure Rucio to use the database

The database configuration has to be set in **alembic.ini** (used to create the database??) and **rucio.cfg** (used by server and clients).
In **alembic.ini**, set 

    [alembic]
	...
	sqlalchemy.url=postgresql://rucio:secret@localhost:5432/rucio
    version_table_schema=rucio
	
In **rucio.cfg** set

* section [alembic]: path to the above file
* section [database]:

     default = postgresql://rucio:secret@localhost/rucio

* section [bootstrap]: This section is used to populate the database when its contents are created. It is used to set the credentials of the root user to access the server and tools. Note, all items from the template should exist or the bootstrap script will fail a try/except clause and insert hardcoded default values, which will not be useful to users outside CERN!

See the template and example in the appendix.

Finally populate the database by running the following script in the distribution:
     
	 tools/bootstrap.py


# Configure Apache

This final step is usually the most complicated one in getting a WSGI
service up and running.  As Debian and Ubuntu also separate the Apache
configuration files into subdirectories and use includes heavily,
the templates from the CentOS dockers will have to be split and adapted a bit.


## Remove defaults
We assume that Apache and required modules have been installed and enabled as above.
Then a new virtual site has to be enabled for your Rucio server.
So disable any default sites, typically:

    $sudo a2dissite 000-default
	
## IPv4 and IPv6

IPv6 is not available on the local network so on my install I changed ports.conf: every line reading
 
    Listen <PORTNO>
    
was changed to

    Listen 0.0.0.0:<PORTNO>

Explicitly specifying an IPv4 address such as this "wildcard" one disables IPv6.

## Apache security

Check  **/etc/apache2/conf-available/security.conf**: some entries should maybe be added or modified


## Apache options and WSGI settings

Create  **/etc/apache2/conf-available/rucio.conf** as in the template and enable it

	$sudo a2enconf rucio
	
## New virtual site with SSL support

Create a new site configuration file e.g. **/etc/apache2/sites-available/rucio.conf** and enable it

    $sudo a2ensite rucio
	
Finally (re)start the Apache server.

# Test that your server runs

At this stage the WSGI server should hopefully be running. It is time
to configure the client program and try to connect.  We assume that
X509 authentication was configured(host certificate is valid and
client certificate DN inserted in the bootstrap step).  The client
program **/usr/local/bin/rucio** will be available on the server after
the install procedure. It can also be installed on another computer
such as your local machine. In either case the address of the server
should be set in **rucio.cfg** [clients]. Also make sure that any
firewalls allow connections between client and server.

With your client certificate and certificate utility software properly
set up (?Fixme find some documentation), generate a proxy certificate
with

    $grid-proxy-init
	
or (as is the case in the EISCAT local install, to allow authentication to dCache storage with VO attributes)

    $voms-proxy-init --voms <my.vo>:/<my>/<group>/Role=<my-role>

Next, either set certificate and user details in **rucio.cfg** [clients] section, or

    $export X509_USER_PROXY=/tmp/x509up_u<nnnn>

Insert the proper name of your generated proxy certificate file here --- typically it ends with your UID number e.g. 1000.

    $export RUCIO_USER=root
	
Now the command line client **/usr/local/bin/rucio** should be able to connect to the server:


    $rucio ping

This should reply with the version number, e.g. 1.27.0
	
	$rucio whoami
	
This should give a reply similar to the following, including the account name:

	status     : ACTIVE
	email      : None
	deleted_at : None
	updated_at : 2022-02-23T12:18:11
	account_type : SERVICE
	account    : root
	suspended_at : None
	created_at : 2022-02-23T12:18:11


# Troubleshooting

Rucio developers can be contacted by email or on Slack.

# Connect to storage

In order to upload files, you now have to define a Rucio storage element (RSE). All uploads are handled **client-side** --- the server only tells the client the details about location and upload protocol of the server.

## Define an RSE
The first step is to create the RSE with **rucio-admin**

	$rucio-admin -v -u root rse add MY_STORE
	
This tells the server that there is a storage element named "MY_STORE" and sets some default properties of it, including upload quota. Note however that no location or file transfer protocol is defined in this stage! But the server knows that the RSE exists:

    $rucio list-rses
    MY_STORE

The default configuration of the RSE can be inspected with:
    
    $rucio-admin rse info MY_STORE
	
For testing it may also be necessary to remove the default per-user quota of **root** like this:

    $rucio-admin account set-limits root MY_STORE infinity

## Add a protocol to the RSE

In order to associate the defined RSE with actual physical storage, at least one **protocol** has to be added to the empty protocol section of the RSE configuration.

Many different file transfer implementations are supported and the one recommended by the developers is **gfal**, the multi-protocol Grid File Access Library. Gfal is however very CentOS-centric and I had no luck with the Debian packages nor installing from source. So in this example the WebDAV implementation is shown instead. The WebDAV access module was debugged by the author and allows uploading to a WebDAV-enabled dCache server with X509 authentication.

The **rucio-admin add-protocol** command is used. Required arguments include hostname, scheme and port of the storage server, Python implementation (module name) to use for file transfer, etc. 

The following configuration corresponds to a WebDAV server accessible at
    
	https://my.storage.server:8443/my/storage/user

    $rucio-admin -v -u root rse add-protocol --hostname my.storage.server --scheme https --impl rucio.rse.protocols.webdav.Default --prefix '/my/storage/user' --port 8443 --domain-json '{"lan": {"read": 0, "write": 0, "delete": 0}, "wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy": 1}}'

An "ugly" part of this is that the RSE must be configured as **writable from the wan domain**. This is not enabled by default and the only way to configure it at present is to provide the above extra configuration in JSON format.

## Test the RSE
Create a Rucio scope for your user and data:

	 $rucio-admin -u root -v scope add --account root --scope TEST
	 
Check that the scope exists:

	 $rucio-admin scope list

Also add a dataset in the scope:

     $rucio add-dataset TEST:MYDATA

With a properly configured client:

    $rucio -v -u root upload --rse MY_STORE --scope TEST my-file.dat
	
Finally attache the file to the dataset:
    
	$rucio attach TEST:MYDATA TEST:my-file.dat
	
Now the file should be visible in the dataset:
 
    $rucio ls TEST:*
	
You should also be able to download the dataset:

    $rucio download -u root -v TEST:MYDATA
	
This should create a subdirectory MYDATA with the file my-file.dat
	
From here on, follow the documentation about how to create containers and datasets, add files to them, and add metadata.



# Appendix: Rucio configuration examples


## alembic.ini


	[alembic]

	sqlalchemy.url=postgresql://rucio:secret@localhost:5432/rucio
	version_table_schema=rucio

    # Do not modify this
    ...



## rucio.cfg
Note: **auth** should be added to [api] endpoints config

    [common]
	logdir = /var/log/rucio/log
	loglevel = DEBUG 
	logformat = %%(asctime)s\t%%(process)d\t%%(levelname)s\t%%(message)s
	mailtemplatedir=/opt/rucio/etc/mail_templates

	[client]
	rucio_host = https://rucio-host.my.domain:443
	auth_host = https://rucio-host.my.domain:443
	auth_type = x509_proxy
	# set ID here or in env variables
	# client_x509_proxy = /tmp/x509up_u1000
	# account = root

	[upload]
	transfer_timeout = 3600
	preferred_impl = WebDAV

	[download]
	transfer_timeout = 3600
	preferred_impl = WebDav

	[database]
	default = postgresql://rucio:secret@localhost/rucio
	pool_recycle=3600
	echo=0
	pool_reset_on_return=rollback

	[alembic]
	cfg = /opt/rucio/etc/alembic.ini

	[api]
	endpoints = accountlimits, accounts, auth, config, credentials, dids, export, heartbeats, identities, import, lifetime_exceptions, locks, meta, ping, redirect, replicas, requests, rses, rules, scopes, subscriptions

	[conveyor]
	scheme = https,davs
	transfertool = fts3
	ftshosts = https://dcache.my.domain:2880

	[bootstrap]
	userpass_identity = root
	userpass_pwd = secret
	userpass_email = webmaster@my.domain
	x509_identity = / ... my certificate DN .../
	x509_email = myname@my.domain
	gss_identity = myname@MY.DOMAIN
	gss_email = myname@my.domain
	ssh_identity = ssh-rsa ... my SSH key ...
	ssh_email =  myname@my.domain


# Appendix: Apache configuration examples

## **/etc/apache2/conf-available/rucio.conf** (remember **sudo a2enconf rucio**)

	EnableSendfile on
	Timeout 60
	KeepAlive on
	KeepAliveTimeout 5
	MaxKeepAliveRequests 128
	ServerLimit 10
	StartServers 4
	ThreadLimit 128
	ThreadsPerChild 128
	MinSpareThreads 256
	MaxSpareThreads 512
	MaxRequestWorkers 1280
	MaxConnectionsPerChild 2048
	WSGIRestrictEmbedded On
	WSGIDaemonProcess rucio processes=4 threads=4
	WSGIApplicationGroup rucio



## **/etc/apache2/sites-available/rucio.conf** (remember **sudo a2ensite rucio**)
(Checkme: is everything necessary? How enable Web UI properly?)


	<IfModule mod_ssl.c>
	SSLSessionCache shmcb:/var/log/apache2/ssl_scache(512000)
	<VirtualHost _default_:443>
		ServerName rucio-host.my.doamin
		ServerAdmin webmaster@my.domain
		DocumentRoot /var/www/html
		AddDefaultCharset UTF-8
		LogLevel debug
		ErrorLog ${APACHE_LOG_DIR}/error.log
		CustomLog ${APACHE_LOG_DIR}/access.log combined

		SSLEngine on
		SSLCertificateFile /etc/grid-security/hostchain.pem
		SSLCertificateKeyFile /etc/grid-security/hostkey.pem
		SSLCertificateChainFile /etc/grid-security/hostchain.pem
		SSLCACertificatePath /etc/grid-security/certificates
		SSLVerifyClient optional_no_ca
		SSLVerifyDepth  10
		SSLOptions +StdEnvVars
		SSLProxyEngine On
        SSLProxyCheckPeerCN Off

		<Directory />
    		Options FollowSymLinks
    		AllowOverride None
    		Require all granted
	     </Directory>	
		 <Directory "/var/www">
             AllowOverride None
             Require all granted
         </Directory>
		 <Directory "/var/www/html">
		 	 Options Indexes FollowSymLinks
			 AllowOverride None
			 Require all granted
	     </Directory>
		 <IfModule dir_module>
    		 DirectoryIndex index.html
		 </IfModule>

		 ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
		 <Directory "/var/www/cgi-bin">
             AllowOverride None
             Options None
             Require all granted
         </Directory>
                
	 	 <IfModule log_config_module>
    		 LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
    		 LogFormat "%h %l %u %t \"%r\" %>s %b" common
              <IfModule logio_module>
      		      LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %I %O" combinedio
    		  </IfModule>
        </IfModule>
        
         <IfModule mime_module>
		     TypesConfig /etc/mime.types
             AddType application/x-compress .Z
             AddType application/x-gzip .gz .tgz
             AddType text/html .shtml
             AddOutputFilter INCLUDES .shtml
         </IfModule>

         <IfModule mime_magic_module>
             MIMEMagicFile conf/magic
         </IfModule>

		 Header set X-Rucio-Host "%{HTTP_HOST}e"
		 RequestHeader add X-Rucio-RequestId "%{UNIQUE_ID}e"

		 CacheEnable disk /
		 CacheRoot /tmp
		 EnableSendfile on
		 HostnameLookups off

		 AllowEncodedSlashes on

	     ProxyPass /proxy             https://localhost
         ProxyPassReverse /proxy      https://localhost
         ProxyPass /authproxy         https://localhost
         ProxyPassReverse /authproxy  https://localhost
		 
		 RewriteEngine on
		 RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)
		 RewriteRule .* - [F]

		 # REST API
		 WSGIScriptAlias /  /usr/local/lib/python<VERSION>/dist-packages/rucio/web/rest/flaskapi/v1/main.py process-group=rucio application-group=rucio

    </VirtualHost>
</IfModule>


