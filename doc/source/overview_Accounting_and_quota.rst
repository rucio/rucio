====================
Accounting and quota
====================

Accounting is the measure of how much resource, e.g. storage, an account has used as a consequence of its actions. Quota is a policy limit which the system applies to an account.

For storage accounting, Rucio accounts will only be accounted for the files they set replication rules on. The accounting is based on the replicas an account requested, not on the actual amount of physical replicas in the system.

