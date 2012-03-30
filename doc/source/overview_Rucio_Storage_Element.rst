---------------------
Rucio Storage Elements
---------------------

.. A Rucio Storage Element (RSE) is a container for physical files. It is the
.. smallest unit of storage space addressable within Rucio. It has an unique
.. identifier and a set of meta attributes describing properties such as supported
.. protocols like file//: or http(s)//:, host/port address, quality of service,
.. storage type (disk, tape, …), available space, used space, (non) pledge, or
.. geographical zone.
.. 
.. Rucio Storage Elements can be grouped in many logical ways, e.g. the UK RSEs,
.. the T1 RSEs, or the ‘good’ RSEs. One can reference groups of RSEs by meta-data
.. attributes or by explicit enumeration of RSEs.

**DRAFT VERSION: WORK IN PROGRESS**


Rucio Storage Elements (RSE) are container for physical files.  They are
designed to provide a way to define each storage and all its supported
protocols separately and includes them in a transparent way for users. Doing so
creates the flexibility to add new storages and protocols to the system without
changing other classes using RSEs. It further allows for separate update
strategies for each storage, as all information needed to interact with a
specific storage is gathered at runtime (Rucio Storage Element Properties
(RSEProperties) and Rucio Storage Element Protocol Type (RSEProtocol)).

********
Overview
********

Architectural Overview
++++++++++++++++++++++

As illustrated below, each complex class (representing a particular
workflow/use case) uses one or more basic (or even complex) classes to perform
the intended operation. One of these basic classes is the RSE class, describing
a generic storage element.  Whenever interaction with a storage is requested by
any other class inside Rucio it instantiates a generic RSE object. The id of
the actual storage must be provided as a parameter to the init-function. As
this class offers a common interface, supported by all storages, no further
knowledge about a specific storage or protocol is required at this time.

.. image:: images/RSE_overview.png

Because some storages use the same protocol,  a Rucio-wide pool of protocol
implementations for the system is also provided. What protocols (cloud be more
than one) are supported by a specific storage is defined in its according
properties. Unfortunately, different version/implementations of one protocol,
which differ in various ways, are supported by different storages. Due to
re-usability reasons we therefore decided to allow various subtypes of each
protocol. If for example a specific storage supports SRM, but not in the
default implementation, it defines in its properties which particular subtype it supports.

What Happens During Instantiation
++++++++++++++++++++++++++++++++


In this section we explain what actually happens when (a) an RSE object is
instantiated and (b) interaction with a specific storage is requested.

.. image:: images/RSE_sequence_instantiation.png

Whenever an interaction with a storage is requested, an RSE object has to be
instantiated. The illustration above gives an overview about what happens at
run-time during its instantiation.

**1. Repository Lookup:** To allow the generic RSE object to interact with a
specific storage, the properties defined for it must be requested from the Storage
Properties Repository.  What this properties are in particular will be
discussed in the according section later in this document.

**2. Interpreting The Properties:**
Based on the information received in Step One, the RSE object is now able to
set its internal properties to allow future interaction with the requested
storage. Some examples for this internal values are the storage specific
prefix, the name of the used protocol, the URI of the storage, to name only a few. Again
a detailed discussion about this properties is given in the according section
later in this document.

**3. Instantiating The Protocol:**
Now that all information about the requested storage is set up, the RSE object
instantiates the specified protocoli class. Because all protocols in the pool
provide similar functionality, they can be used in an arbitrary way. The instance
of the protocol is kept as a private member of the RSE object, as it is of no
further interest for any other class. It therefore exists as long as the
containing RSE object.

**4. Initializing an Authenticated User Session:**
Each protocol class in the pool initializes an authenticated user
session, which is stored inside the protocol object for later usage. Doing so
avoids unnecessary traffic created by user authentication for each storage
request and therefore compliments the overall system performance.

After this four steps, the generic RSE object has become a storage specific one.
What operations are supported by these RSE objects will be discussed in the
according section later in this document. 

In the following we discuss what happens if storage interaction is requested
from the already instantiated RSE object. It should be noted that in the
illustration below all objects are provided/created somewhere before the focus
of the illustration.

.. image:: images/RSE_sequence_usage.png


**1. Interaction Request:** Whenever a complex class wants to interaction with
the specified storage, it uses one of the operations provided by the RSE
object. This operation could be for example GET a file, GET a directory
listing, DELETE a file, … A detailed discussion about the provided operations
is given in the according section later in this document.

**2. Parameter Transformation:** First the RSE object has to adapt the input
parameters in a way to match the referred storage. This includes for example,
transforming the logical file name (LFN) to the physical file name (PFN),
adding storage specific prefixes, and so on. All adaptations are based on the
information received from the properties repository at object instantiation. At
the end of this sequence, the input parameters are matching the interface (by
structure and value) of the according operation provided by the specified
protocol.

**3. Calling the According Protocol Operation:** Because now all parameters are
ready to be used by the protocol, the RSE object can delegate the actual
storage interaction to the protocol object.

**4. Using the Authenticated User Session:** The protocol object reuses the
authenticated user session created during the instantiation to interact
directly with the referred storage system.

**5. The Actual Storage Interaction:** The interaction with the storage systems
is performed as defined in the protocol.

********************************
Rucio Storage Element Object
********************************

Methods
+++++++

GET
===
Get files or directory listings

PUT
===
Rename or update files and directories

POST
====
Create files or directories

DELETE
======
Delete files and directories


*******************************
Rucio Storage Properties Object
*******************************

To enable an RSE object to interact with each storage system specified inside
the repository, a common set of properties is needed. Further are theses
properties needed as a base for automatic decision making when automatic
storage selection will be enabled. All this information is represented by Rucio
Storage Element Properties (RSEPs).

In order to achieve the intended functionality, we decided to split the
information of each storage into two major parts (namely static and dynamic).
Each part must represent a common set of key-value pairs provided by all
storage systems specified inside the repository. 

In the following we will discuss what we understand by the terms 'static
properties', and 'dynamic properties'. At the end the according JSON Schema, as
one way to validate that each storage provides sufficient information when
adding it to the repository, is given.

Static Properties
+++++++++++++++++

Static properties, as we understand them, do not vary on a regular basis.
Therefore this information is kept (static) inside the repository. Having this
information provided here saves bandwidth and storage computing resources every
time a client requests information about a specific storage. Further is
querying and/or filtering storages based on static information possible by
performing only one request, what otherwise would be at least one separate call
for each storage. We argue that this increase in resource efficiency justifies
the more complex maintenance task by updating the information inside the
repository whenever a static value changes.

The following listing gives some examples how static properties may look like.

  'static' : {
    'id' : 'cern.storage.user.ralph.laptop',
    'name' : 'Ralph's Laptop at CERN',
    'location' : {
      'address' : '1-R-024, CERN CH-1211, Genève 23', 
      'country' : 'CH'
    },
    'overall_diskspace' : {'value':'128', 'unit':'GB'}
    'overall_computing_power' : {'value' ; '1.4', 'unit' : 'GHz'},
    'protocols' : [{'s3': []}, {'webdav':['sub1','sub2']}]
    }
  }

The example above will describe a storage represented by one of our laptops
located at CERN, Switzerland. It has 128GB of overall disk space and 1.4 GHz
overall computing power. The supported protocols are S3 (default
implementation) and WebDAV (only subtypes sub1 and sub2).

Dynamic Properties
++++++++++++++++++

In contrast to static properties, dynamic properties vary from request to
request. Examples for such properties are current work load, available disk
space, current connection bandwidth, … Because of their dynamic nature, the
values of this properties are not kept inside the repository. For this
scenario, it saves resources if the values are requested from the storage on
demand instead of automatically update the repository information each time a
certain value changes, like we do with static properties.

To enable the client to query these dynamic properties, each property is
represented by a method which must be defined inside the class of according
protocol. If a storage systems requires different operations to the one defined
inside the default one to provided the requested information, a new subtype
protocol must be defined. This way we create the flexibility for each storage
to implement its own way to provide the requested data. 

  'dynamic' : {
    's3' : {
      'available_disk_space' : {
        'method' : 'get_diskspace()',
        '[some additional protocol specific information]
      }, 
      'current_workload' : {
        'method' : 'get_workload()',
        '[some additional protocol specific information]
      },
    … 
    }
    'webdav_sub1' : {
      'available_disk_space' : {
        'method' : 'get_diskspace()',
        '[some additional protocol specific information]
      }, 
      'current_workload' : {
        'method' : 'get_workload()',
        '[some additional protocol specific information]
      },
    … 
    },
  … 
  }

The example above specifies for each storage system and each supported protocol
how clients are able request the data using the according protocol object.

JSON Schema
+++++++++++

To guarantee the information provided for each storage matches the common set,
a JSON schema [#]_ is defined. Using this schema allows clients to verify if
the responded data is valid, and therefore helps to write less complex code
during implementation. Further supports this schema developers when defining
the RSEP for a storage system by acting as a guideline. Again, by validating
the RSEP against the schema, mistakes and errors can be prevented. Inside the
central repository the validation of the data is performed automatically each
time a information about a storage is created or updated.

.. [#] Link to JSON Schema: http://json-schema.org/

Implementation Details
++++++++++++++++++++++

*****************************
Rucio Storage Protocol Object
*****************************

Methods
+++++++

Authenticate
============
Authenticates the user at the specified storage.


READ
===
Get files or directory listings

WRITE
===
Rename or update files and directories


DELETE
====
Create files or directories


RESOURCE_TYPE
=============
Responds it a resource is a file or a directory


******************************
Rucio Storage Exception Object
******************************

Like Rucio itself, RSE objects use RucioExceptions to escalate errors.
For easier coding it is subclassed as RSEExceptions.

An RSEException consists of three attributes: the ID representing an unique
integer identifier for each exception, the message text which is printed
along side the ID if the exception is transformed to string and a data field
for additional information to the execption.

Exception Codes
+++++++++++++++

In the following a comprehensive list of all exceptions is given.

=====  ====================================            ===================================================================================================================================
 ID     Message Text                                    Description
=====  ====================================            ===================================================================================================================================
 101    Switching Protocols                             The storage indicates the client to use a different protocol to fulfil its request.
 202    Requested Accepted                              Indicates that the request successfully transmitted to storage and that it will be executed later.
 204    No Response                                     The storage has completed the request, but no content is provided to the client.
 300    Multiple Endpoints                              The storage provides this file multiple times (with different protocol) and the client has to select one.
 301    Moved Permanently                               The requested file has been permanently moved to a different location.
 302    Found (but at a different endpoint)             The requested resource resides temporarily under a different URI.
 304    Not modified                                    The requested file can be found in the client cache.
 400    Bad Request                                     The requested was rejected by the server due to malformed syntax.
 402    Payment Required                                 Nothing more to say. :)
 403    Forbidden                                       The client has not necessary privileges to access this resource at this storage.
 404    Resource Not Found                              The requested resource was not found at the specified storage.
 405    Method Not Allowed                              The method specified in the Request-Line is not allowed for the resource identified by the Request-URI.
 409    Conflict                                        The clients request is in conflict with the rules defined for the storage.
 410    Gone                                            The requested resource is no longer available at this storage.
 413    Requested Entity To Large                       The storage is refusing to process a request because the request entity is larger than the storage is willing or able to process. 
 500    Something Embarrassing Happened                  Should not happen.
 503    Service Unavailable                             The requested service temporary not accessible for the client.
 504    Gateway Timeout                                 The storage received a timeout while interacting with other storages.
=====  ====================================            ===================================================================================================================================

Note: Because in Rucio Exception are always related to some unsolicited
behaviour, they are not used to confirm an expected state. 

Methods
+++++++

GET_ID
===
Get files or directory listings

GET_MESSAGE
===
Rename or update files and directories


GET_ADDITIONAL_INFORMATION
====
Create files or directories


TO_STR
====
Create files or directories


***********************
Example Implementations
***********************

File System
+++++++++++

WebDAV
++++++

S3
++





.. ******************
.. Physical File Name
.. ******************
.. 
.. The Physical File Name (PFN) is a fully qualified name identifying a replica of
.. a file. PFNs may take the form of file names, URIs, or any other identifier
.. meaningful to a Rucio Storage Element. The mapping between the LFN and the PFN
.. is a deterministic function (LFN_to_PFN). 
.. 
.. Normally the upload to an RSE and the registration of an additional replica is
.. an atomic operation. For trusted users like the T0 and PanDA production
.. systems, it is possible to register a replica uploaded independently.
