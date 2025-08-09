-- Keep in mind that XE is limited to 2 GB RAM and 2 CPU threads.
-- Very large PROCESSES values consume SGA memory and can hit that ceiling quickly..
ALTER SYSTEM SET processes      = 200   SCOPE=SPFILE;
ALTER SYSTEM SET sessions       = 335   SCOPE=SPFILE;
ALTER SYSTEM SET transactions   = 369   SCOPE=SPFILE;
ALTER SYSTEM SET disk_asynch_io = FALSE SCOPE=SPFILE;
