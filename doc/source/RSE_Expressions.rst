---------------
RSE Expressions
---------------

A **RSE Expression** allows to select a set of RSEs to create replication rules.
The RSE Expression consists of one or more **terms**. A term can be a single RSE name or a condition over the RSE attributes.
The RSE Expression Parser resolves each term to a set of RSEs. The resulting set of a term will be all those RSEs match the attribute or name.
Terms can be connected by **operators** to form more complex expressions.
For example, users can write RSE expressions to address all Tier 2 RSEs, all the RSEs in certain cloud, all Tier 2 RSEs not in certain clouds, etc.

^^^^^^^^^^^^^^^^^^^^^^
Simple RSE Expressions
^^^^^^^^^^^^^^^^^^^^^^
Rucio allows to test RSE Expressions, using the command **list-rses**. The most simple RSE Expression is the one containing the name of a particular RSE.

1) The following expression only return a set containing a single RSE::

    jbogadog@lxplus0058:~$ rucio list-rses --expression EELA-UNLP_SCRATCHDISK
    EELA-UNLP_SCRATCHDISK

2) Another simple RSE Expression allows to list the set of all the RSEs in a particular site::

    jbogadog@lxplus0058:~$ rucio list-rses --expression site=EELA-UNLP
    EELA-UNLP_PRODDISK
    EELA-UNLP_DATADISK
    EELA-UNLP_SCRATCHDISK

3) Or all the RSEs who's type is SCRATCHDISK::

    jbogadog@lxplus0058:~$ rucio list-rses --expression type=SCRATCHDISK
    UNI-SIEGEN-HEP_SCRATCHDISK
    NCG-INGRID-PT_SCRATCHDISK
    EELA-UNLP_SCRATCHDISK
    ...
    INFN-T1_SCRATCHDISK
    FMPHI-UNIBA_SCRATCHDISK
    INFN-FRASCATI_SCRATCHDISK

4) Or all the Spanish sites::

    jbogadog@lxplus0058:~$ rucio list-rses --expression SPAINSITES
    IFIC-LCG2_LOCALGROUPDISK
    IFAE_PRODDISK
    PIC_SCRATCHDISK
    EELA-UNLP_SCRATCHDISK
    ...
    EELA-UNLP_DATADISK
    UAM-LCG2_SCRATCHDISK
    IFIC-LCG2_DATADISK
    LIP-COIMBRA_LOCALGROUPDISK


Note that if the RSE Expresion returns an empty set, rucio returns an error. This could be because the name of the attribute doesn't exist or because there's no RSE that match the expression. It does not necessarily mean that the syntax of the expression is wrong.

In 2) and 3), the RSE Expression refers to an attribute in the RSE that must be equal to a given value to match the expression.
While in 1) and 4), the expression match a RSE if the attribute is True. It is possible to see the list of attributes for a particular RSE with rucio::

  jbogadog@lxplus0100:~$ rucio list-rse-attributes EELA-UNLP_SCRATCHDISK
    ftstesting: https://fts3-pilot.cern.ch:8446
    ALL: True
    ESTIER2S: True
    physgroup: None
    spacetoken: ATLASSCRATCHDISK
    fts: https://fts3.cern.ch:8446,https://lcgfts3.gridpp.rl.ac.uk:8446,https://fts.usatlas.bnl.gov:8446
    site: EELA-UNLP
    EELA-UNLP_SCRATCHDISK: True
    datapolicyt0disk: False
    cloud: ES
    SPAINSITES: True
    datapolicyt0taskoutput: False
    fts_testing: https://fts3-pilot.cern.ch:8446
    tier: 3
    datapolicyt0tape: False
    type: SCRATCHDISK
    istape: False

Most of the RSEs share the same set of attributes, and is possible to create RSE Expressions based on all of them.

^^^^^^^^^
Operators
^^^^^^^^^

Operators are used to connect terms in order to get more complex RSE Expressions/terms.
The syntactic functionality of the Rucio RSE Expressions Parser allows the basic operations defined in
mathematical set theory, Union, Intersection and Complement.
Using an operator on two sets of RSEs will construct a new set based on the given sets.

The symbols **A** and **B** in this table stand for a term.

========  ==========  ==============  ==========================================
Operator  Meaning     Interpretation  Example
========  ==========  ==============  ==========================================
A|B       UNION       A union B       EELA-UNLP_SCRATCHDISK | EELA-UNLP_PRODDISK
A&B       INTERSECT   A intersect B   tier=1&country=us
A\\B      COMPLEMENT  A complement B  cloud=ES\\type=SCRATCHDISK
========  ==========  ==============  ==========================================


^^^^^^^^^^^^^^^^^^^^^^^^^
Composing RSE Expressions
^^^^^^^^^^^^^^^^^^^^^^^^^

Using the operators described above, it's possible to create expressions to select whatever RSE you need to put your data in.
Use the following list of examples to build your own RSE Expressions.

All Tier 2 sites in DE cloud::

    jbogadog@lxplus0100:~$ rucio list-rses --expression 'tier=2&cloud=DE'
    PRAGUELCG2_PPSLOCALGROUPDISK
    FMPHI-UNIBA_LOCALGROUPDISK
    ...
    UNI-FREIBURG_DATADISK
    DESY-HH_PRODDISK

Note the use of the single quotes. Single quotes are needed to avoid the shell interpret the **&**, the **|** or the **\\** as commands.

All tier 1 but not the ones in country=us::

    jbogadog@lxplus0100:~$ rucio list-rses --expression 'tier=1\country=us'
    INFN-T1_MCTAPE
    BNL-OSG2_DATATAPE
    ...
    BNL-OSG2_DDMTEST
    NIKHEF-ELPROD_PHYS-SUSY

However, take care of the subtle differences. While the first expression exclude United States' sites, the second doesn't::

    jbogadog@lxplus0100:~$ rucio list-rses --expression 'tier=1\country=us'|wc -l
    115
    jbogadog@lxplus0100:~$ rucio list-rses --expression 'tier=1\country=US'|wc -l
    117

The filters are processed from left to right. Is possible to use parenthesis to force the order of operation.
See the following example to get all the SCRATCHDISKs in IT or FR clouds::

    jbogadog@lxplus0100:~$ rucio list-rses --expression 'cloud=IT|cloud=FR&type=SCRATCHDISK'|wc -l
    30
    jbogadog@lxplus0100:~$ rucio list-rses --expression '(cloud=IT|cloud=FR)&type=SCRATCHDISK'|wc -l
    30
    jbogadog@lxplus0100:~$ rucio list-rses --expression 'type=SCRATCHDISK&(cloud=IT|cloud=FR)'|wc -l
    30
    jbogadog@lxplus0100:~$ rucio list-rses --expression 'type=SCRATCHDISK&cloud=IT|cloud=FR'|wc -l
    92

While the first three operations are equivalent, the last return sites in cloud FR but not only the SCRATCHDISKs but the GROUPDISKs and DATADISKs too, among other types.



