-------------
Rucio account
-------------

A Rucio account is the unit of assigning privileges in Rucio. It can
represent individual users (like lgoossen, graemes, vgaronne, ...), a
group of users (like bphys, higgs, susy, ...) or an organised
production activity for the whole ATLAS collaboration (prod,
tzero, ...). A Rucio account is identified by a string.

Rucio actions are always conducted by a Rucio account. Each account
has a namespace identifier called scope that is included in every
name assigned to a collection of data created by that account (see
\S 3.1). By default, Rucio accounts can only create identifiers
in their own scope and not in any other.

A Rucio user is identified by his credentials, like X509 certificates,
username/password, or token. Credentials can map to one or more
accounts (N:M mapping). The Rucio authentication system checks if the
used credentials are authorized to use the supplied Rucio account.
The figure below gives an example of the mapping between credentials
and Rucio accounts:

.. image:: accounts.png
   :height: 500px
   :width: 500px
   :scale: 80 %
   :alt: Figure 1
   :align: center
