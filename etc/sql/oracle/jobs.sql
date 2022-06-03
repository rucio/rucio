-- Definitions of Rucio database scheduler jobs
-- Authors: Rucio team and Gancho Dimitrov

/*
Note:
the Rucio jobs have to run on the Rucio services defined on the DB cluster (in order to take advantage of the already cached data/index blocks on the relevant DB nodes). RUCIO_JOB_CLASS and RUCIO_JOB_CLASS_2 have to be predefined on the database and execute privilege has to be granted to the DB user before creating the Rucio DB scheduler jobs.
*/


--- 1 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('UPDATE_ACCOUNT_COUNTERS');

BEGIN
dbms_scheduler.create_job
(
'UPDATE_ACCOUNT_COUNTERS',
job_type=>'STORED_PROCEDURE',
job_action=> 'ABACUS_ACCOUNT',
number_of_arguments=>0,
start_date=>TO_TIMESTAMP_TZ('10-FEB-2014 08.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=Minutely; INTERVAL=1',
job_class=>'RUCIO_JOB_CLASS',
enabled=> TRUE,
auto_drop=> FALSE
);
END;
/

--- 2 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('UPDATE_RSE_COUNTERS');


BEGIN
dbms_scheduler.create_job
(
'UPDATE_RSE_COUNTERS',
job_type=>'STORED_PROCEDURE',
job_action=>'ABACUS_RSE',
number_of_arguments=>0,
start_date=>TO_TIMESTAMP_TZ('06-APR-2016 09.30.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=Minutely; INTERVAL=1',
job_class=>'RUCIO_JOB_CLASS',
enabled=> TRUE,
auto_drop=> FALSE
);
END;
/


--- 3 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('UPDATE_RSE_USAGE_HISTORY');

BEGIN
dbms_scheduler.create_job('UPDATE_RSE_USAGE_HISTORY',
job_type=>'STORED_PROCEDURE',
job_action=> 'ADD_RSE_USAGE',
number_of_arguments=>0,
start_date=>TO_TIMESTAMP_TZ('06-APR-2016 11.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=Minutely; INTERVAL=30',
job_class=> 'RUCIO_JOB_CLASS',
enabled=>TRUE,
auto_drop=>FALSE
);
END;
/


--- 4 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('RUCIO_DATA_SLIDING_WINDOWS');

BEGIN
dbms_scheduler.create_job(
'RUCIO_DATA_SLIDING_WINDOWS',
job_type=>'PLSQL_BLOCK',
job_action=> 'BEGIN RUCIO_DATA_SLIDING_WINDOW(''REQUESTS_HISTORY'', 180); RUCIO_TABLE_SL_WINDOW(''MESSAGES_HISTORY'',''CREATED_AT'', 30, 1); END;',
start_date=>TO_TIMESTAMP_TZ('03-NOV-2014 09.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=WEEKLY; BYDAY=MON; BYHOUR=10; BYMINUTE=0; BYSECOND=0;',
job_class=>'RUCIO_JOB_CLASS',
enabled=>TRUE,
auto_drop=>FALSE,
comments=>'Every Monday remove partitions that are older than the number of most recent partitions given as argument to the PLSQL procedure'
);
END;
/


--- 5 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('RULES_HIST_SL_WINDOW');


BEGIN
dbms_scheduler.create_job(
'RULES_HIST_SL_WINDOW',
job_type=>'PLSQL_BLOCK',
job_action=> 'BEGIN RUCIO_TABLE_SL_WINDOW(''RULES_HIST_RECENT'',''UPDATED_AT'',5,7); END;',
start_date=>TO_TIMESTAMP_TZ('09-MAR-2015 07.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=WEEKLY; BYDAY=MON; BYHOUR=07; BYMINUTE=0; BYSECOND=0;',
job_class=>'RUCIO_JOB_CLASS',
enabled=>TRUE,
auto_drop=> FALSE,
comments=> 'Every Monday delete partitions that are oleder than last 5 weeks'
);
END;
/



--- 6 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('RUCIO_ACCOUNT_LOGICALBYTES_JOB');


BEGIN
dbms_scheduler.create_job
(
'RUCIO_ACCOUNT_LOGICALBYTES_JOB',
job_type=>'PLSQL_BLOCK',
job_action=> 'BEGIN RUCIO_ACCOUNT_LOGICAL_BYTES; END; ',
number_of_arguments=>0,
start_date => TO_TIMESTAMP_TZ('25-08-2017 05:00:00 EUROPE/ZURICH', 'DD-MM-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=DAILY; BYHOUR=05; BYMINUTE=0; BYSECOND=0;',
job_class=>'RUCIO_JOB_CLASS_2',
enabled=>TRUE,
auto_drop=>FALSE,
comments=> 'Job for regular computation the logical bytes (based on the catalog only, not on the real file replicas on the Grid) based on the information in the DIDS table '
);
END;
/




---- 7 ------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('RUCIO_ACCOUNTING_ALLSCOPES_JOB');


BEGIN
dbms_scheduler.create_job('RUCIO_ACCOUNTING_ALLSCOPES_JOB',
job_type=>'PLSQL_BLOCK',
job_action=> 'BEGIN RUCIO_ACCOUNTING_ALL_SCOPES;  END; ',
number_of_arguments=> 0,
start_date=>TO_TIMESTAMP_TZ('06-SEP-2017 00.00.05 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=DAILY; BYHOUR=00; BYMINUTE=05; BYSECOND=0;',
job_class=>'RUCIO_JOB_CLASS_2',
enabled=> TRUE,
auto_drop=> FALSE,
comments=> 'Job for regular computation the bytes used on the Grid by the replicas of Rucio.'
);

dbms_scheduler.set_attribute('RUCIO_ACCOUNTING_ALLSCOPES_JOB','restartable',TRUE);
END;
/


---- 8 ------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('ESTIMATE_TRANSFER_TIME_JOB');

BEGIN
dbms_scheduler.create_job('ESTIMATE_TRANSFER_TIME_JOB',
job_type=>'PLSQL_BLOCK',
job_action=> 'BEGIN ESTIMATE_TRANSFER_TIME; END; ',
start_date=>TO_TIMESTAMP_TZ('28-SEP-2017 14.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=MINUTELY; INTERVAL=20;',
job_class=>'RUCIO_JOB_CLASS',
enabled=>TRUE,
auto_drop=>FALSE,
comments=> 'Job for regular estimation of files transfer time from source to destination on the Grid.'
);
END;
/


--- 9 -------------------------------------------------------------------------------------------------------------------------------------------------

-- Several DB jobs of the same kind to work simultaneously but for different virtual Scope group

exec dbms_scheduler.drop_job('COLL_REPL_UPDATED_JOB_USER');


BEGIN
dbms_scheduler.create_job
('COLL_REPL_UPDATED_JOB_USER',
job_type=>'PLSQL_BLOCK', job_action=>
'BEGIN COLL_UPDATED_REPLICAS(''user''); END;',
start_date=>TO_TIMESTAMP_TZ('22-MAR-2018 08.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=MINUTELY; INTERVAL=2;',
job_class=>'RUCIO_JOB_CLASS',
enabled=>TRUE,
auto_drop=>FALSE,
comments=>'Every two minutes remove the duplicates from the UPDATED_COL_REP table for a given virtual scope group (''user'') and update the COLLECTION_REPLICAS data'
);
END;
/


--- 10 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('COLL_REPL_UPDATED_JOB_PANDA');


BEGIN
dbms_scheduler.create_job
('COLL_REPL_UPDATED_JOB_PANDA',
job_type=>'PLSQL_BLOCK',
job_action=> 'BEGIN COLL_UPDATED_REPLICAS(''panda''); END;',
start_date=>TO_TIMESTAMP_TZ('22-MAR-2018 08.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=MINUTELY; INTERVAL=2;',
job_class=>'RUCIO_JOB_CLASS',
enabled=>TRUE,
auto_drop=>FALSE,
comments=>'Every two minutes remove the duplicates from the UPDATED_COL_REP table for a given virtual scope group (''panda'') and update the COLLECTION_REPLICAS data'
);
END;
/

--- 11 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('COLL_REPL_UPDATED_JOB_DATA');


BEGIN
dbms_scheduler.create_job
('COLL_REPL_UPDATED_JOB_DATA',
job_type=>'PLSQL_BLOCK',
job_action=>'BEGIN COLL_UPDATED_REPLICAS(''data''); END;',
start_date=>TO_TIMESTAMP_TZ('22-MAR-2018 08.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=MINUTELY; INTERVAL=2;',
job_class=>'RUCIO_JOB_CLASS',
enabled=>TRUE,
auto_drop=>FALSE,
comments=>'Every two minutes remove the duplicates from the UPDATED_COL_REP table for a given virtual scope group (''data'') and update the COLLECTION_REPLICAS data'
);
END;
/


--- 12 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('COLL_REPL_UPDATED_JOB_OTHERS');


BEGIN
dbms_scheduler.create_job
('COLL_REPL_UPDATED_JOB_OTHERS',
job_type=>'PLSQL_BLOCK',
job_action=> 'BEGIN COLL_UPDATED_REPLICAS(''others''); END;',
start_date=>TO_TIMESTAMP_TZ('22-MAR-2018 08.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=MINUTELY; INTERVAL=2;',
job_class=>'RUCIO_JOB_CLASS',
enabled=>TRUE,
auto_drop=>FALSE,
comments=>'Every two minutes remove the duplicates from the UPDATED_COL_REP table for a given virtual scope group (''others'') and update the COLLECTION_REPLICAS data'
);
END;
/


--- 13 -------------------------------------------------------------------------------------------------------------------------------------------------


-- Four simultaneous jobs to handle the MC data (data is distributed in 4 groups using the ORAHASH built-in DB function)

exec dbms_scheduler.drop_job('COLL_REPL_UPDATED_JOB_MC_ID0');

BEGIN
dbms_scheduler.create_job
('COLL_REPL_UPDATED_JOB_MC_ID0',
job_type=>'PLSQL_BLOCK',
job_action=>'BEGIN COLL_UPDATED_REPLICAS_ORAHASH(''mc'', 3, 0); END;',
start_date=>TO_TIMESTAMP_TZ('09-APR-2018 08.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=MINUTELY; INTERVAL=2;',
job_class=>'RUCIO_JOB_CLASS',
enabled=>TRUE,
auto_drop=>FALSE,
comments=>'Every two minutes remove the duplicates from the UPDATED_COL_REP table for a given virtual scope group (''mc'') and bucket result = 0 and update the COLLECTION_REPLICAS data'
);
END;
/


--- 14 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('COLL_REPL_UPDATED_JOB_MC_ID1');


BEGIN
dbms_scheduler.create_job
('COLL_REPL_UPDATED_JOB_MC_ID1',
job_type=>'PLSQL_BLOCK',
 job_action=> 'BEGIN COLL_UPDATED_REPLICAS_ORAHASH(''mc'', 3, 1); END;',
start_date=>TO_TIMESTAMP_TZ('09-APR-2018 08.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=MINUTELY; INTERVAL=2;',
job_class=>'RUCIO_JOB_CLASS',
enabled=>TRUE,
auto_drop=>FALSE,
comments=> 'Every two minutes remove the duplicates from the UPDATED_COL_REP table for a given virtual scope group (''mc'') and bucket result = 1 and update the COLLECTION_REPLICAS data'
);
END;
/


--- 15 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('COLL_REPL_UPDATED_JOB_MC_ID2');


BEGIN
dbms_scheduler.create_job
('COLL_REPL_UPDATED_JOB_MC_ID2',
job_type=>'PLSQL_BLOCK',
job_action=>'BEGIN COLL_UPDATED_REPLICAS_ORAHASH(''mc'', 3, 2); END;',
start_date=>TO_TIMESTAMP_TZ('09-APR-2018 08.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=MINUTELY; INTERVAL=2;',
job_class=>'RUCIO_JOB_CLASS',
enabled=>TRUE,
auto_drop=>FALSE,
comments=>'Every two minutes remove the duplicates from the UPDATED_COL_REP table for a given virtual scope group (''mc'') and bucket result = 2 and update the COLLECTION_REPLICAS data'
);
END;
/


--- 16 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('COLL_REPL_UPDATED_JOB_MC_ID3');


BEGIN
dbms_scheduler.create_job
('COLL_REPL_UPDATED_JOB_MC_ID3',
job_type=>'PLSQL_BLOCK',
job_action=>'BEGIN COLL_UPDATED_REPLICAS_ORAHASH(''mc'', 3, 3); END;',
start_date=>TO_TIMESTAMP_TZ('09-APR-2018 08.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=>'FREQ=MINUTELY; INTERVAL=2;',
job_class=>'RUCIO_JOB_CLASS',
enabled=>TRUE,
auto_drop=>FALSE,
comments=>'Every two minutes remove the duplicates from the UPDATED_COL_REP table for a given virtual scope group (''mc'') and bucket result = 3 and update the COLLECTION_REPLICAS data'
);
END;
/

--- 17 -------------------------------------------------------------------------------------------------------------------------------------------------

exec dbms_scheduler.drop_job('RUCIO_ACCOUNT_USAGE_HIST_JOB');


BEGIN

dbms_scheduler.create_job
(
'RUCIO_ACCOUNT_USAGE_HIST_JOB',
job_type=>'PLSQL_BLOCK',
job_action=> 'BEGIN ADD_ACCOUNT_USAGE_HISTORY;  END; ',
number_of_arguments=> 0,
start_date=>TO_TIMESTAMP_TZ('10-JAN-2019 08.00.00 EUROPE/ZURICH','DD-MON-YYYY HH24:MI:SS TZR'),
repeat_interval=> 'FREQ=DAILY; BYHOUR=08; BYMINUTE=0; BYSECOND=0;',
job_class=>'RUCIO_JOB_CLASS',
enabled=> TRUE,
auto_drop=> FALSE,
comments=> 'Job for regular insertion of the changed (since the previous execution rows) from the ACCOUNT_USAGE into the ACCOUNT_USAGE_HISTORY table.'
);

END;
/
