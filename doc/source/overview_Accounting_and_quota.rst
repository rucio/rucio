====================
Accounting and quota
====================

Accounting is the measure of how much resource, e.g. storage, an account has used as a consequence of its actions. Quota is a policy limit which the system applies to an account.

Rucio accounts are only accounted for the files they set replication rules on. The accounting is based on the replicas an account requested, not on the actual amount of physical replicas in the system. Thus if two different users set a replication rule for the same file on the same RSE both users are accounted for this file, although there is only one physical copy of it.
