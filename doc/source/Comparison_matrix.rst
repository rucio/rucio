---------------------------------------------
Key concepts: Comparison matrix DQ2 vs. Rucio
---------------------------------------------

============================  ==============================  =============================================================
Features                      DQ2                             Rucio
============================  ==============================  =============================================================
File identifier               GUID/LFN (Basename)             Scope + Label name
Dataset identifier            DUID/DSN                        Scope + Label name
Versioning                    Yes                             No
Namespace                     Global/Flat                     Scoped
Unique PFN                    No                              Yes
Overlapping dataset           Yes                             Yes
Storage Element Groups        No                              Yes
Storage Element Tagging       No                              Yes
Quota support                 Group                           Account (Group/User)
Dataset Replica completeness  Yes                             No
Meta-data name-space/support  System defined, Data placement  System-defined, Physics, Production, analysis, Data placement
Data discovery unit           Pattern                         Meta-data
Data operation unit           Dataset                         Dataset, File
Multiple replica ownership    No                              Yes 
Dynamic placement             No                              Yes
Replication rule support      No                              Yes
Hidden data                   Yes                             Yes
Reuse of dataset name         No                              No (but possibility to resuscitate dataset)
Notifications                 Yes                             Yes
Fine-grained accounting       Partially                       Yes
============================  ==============================  =============================================================





