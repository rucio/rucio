Space Reporting in JSON Format
==============================

If a site uses XRootD and WebDAV doors provided by native software (e.g. `XRootD <http://xrootd.org/>`_)
without running a full suite of Grid middleware (such as `dCache <https://www.dcache.org/>`_), space reporting has to be provided externally.

This is facilitated with a JSON file which the site has to update at least every 2 hours (e.g. via cron job).


Generating the file
-------------------
Sample content of this file is provided within this folder of the repository in
`space-usage-sample.json <https://github.com/rucio/rucio/blob/master/tools/space-usage/space-usage-sample.json>`_.

The approach to retrieve the space-usage data is necessarily site-specific, if the underlying file system is a POSIX parallel cluster filesystem (e.g. BeeGFS, Lustre), the best performing way is usually to rely on the quota accounting provided by the file system.

It should be noted that the ``num_files`` field is optional, which may help in the situation that no central accounting is available and the full file tree has to be walked to extract the space usage information.

All units in the `space-usage-sample.json <https://github.com/rucio/rucio/blob/master/tools/space-usage/space-usage-sample.json>`_ file are in *bytes*. A Python script and schema for easy validation are also provided.


Providing the File
------------------
The space usage file has to be provided via HTTPS, usually this can be easily done using an existing WebDAVs door.
For example, the file can be exported from the exported endpoint directory.

An ATLAS specific example including AGIS setup is provided on `ATLAS Computing twiki <https://twiki.cern.ch/twiki/bin/view/AtlasComputing/DDMOperationsGroup#SRM_less_space_reporting>`_.


Testing it works
----------------
You should test your created JSON file against the JSON schema provided in this repository (`space-usage-schema.json <https://github.com/rucio/rucio/blob/master/tools/space-usage/space-usage-schema.json>`_).
A Python script `validate-space-usage-json-file <https://github.com/rucio/rucio/blob/master/tools/space-usage/validate-space-usage-json-file>`_ is provided for convenience.

To test the new space reporting is picked up, you can use the command::

  rucio-admin rse info NAME_OF_SPACETOKEN

Additionally, the monitoring information should show up at `ADC DDM Mon <http://adc-ddm-mon.cern.ch/ddmusr01/>`_.
