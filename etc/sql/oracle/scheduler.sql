--/
BEGIN
    dbms_scheduler.create_job(job_name=>'ATLAS_RUCIO.UPDATE_RSE_USAGE', job_class=>'DEFAULT_JOB_CLASS', comments=>NULL, auto_drop=>TRUE, job_type=>'plsql_block', job_action=>
    'BEGIN
FOR i in (SELECT rse_id, sum(bytes) as bytes, sum(files) as files, max(rse_counters.updated_at) as updated_at
FROM  rse_counters, rses
WHERE    rse_counters.rse_id = rses.id
AND deleted = ''0''
GROUP BY rse_counters.rse_id)
LOOP

MERGE INTO RSE_USAGE
USING DUAL
ON (RSE_USAGE.rse_id = i.rse_id and source = ''rucio'')
WHEN MATCHED THEN UPDATE SET used=i.bytes, updated_at=i.updated_at
WHEN NOT MATCHED THEN INSERT (rse_id, source, used, updated_at, created_at) VALUES (i.rse_id, ''rucio'', i.bytes, i.updated_at, i.updated_at);

BEGIN
INSERT INTO RSE_USAGE_HISTORY (RSE_ID, SOURCE, USED, UPDATED_AT, CREATED_AT) VALUES (i.rse_id, ''rucio'', i.bytes, i.updated_at, i.updated_at);
exception
when others then null;
END;

COMMIT;
END LOOP;
END;', number_of_arguments=>0, start_date=>NULL, repeat_interval=>'Freq=Minutely;Interval=30', end_date=>NULL);
END;
--/


--/
BEGIN
    dbms_scheduler.create_job(job_name=>'ATLAS_RUCIO.UPDATE_RSE_USAGE', job_class=>'DEFAULT_JOB_CLASS', comments=>NULL, auto_drop=>TRUE, job_type=>'plsql_block', job_action=>
'BEGIN
FOR usage IN (SELECT /*+ INDEX(R REPLICAS_STATE_IDX ) */ rse_id, SUM(bytes) AS bytes , COUNT(*) AS files
              FROM atlas_rucio.replicas r WHERE (CASE WHEN state != ''A'' THEN rse_id END) IS NOT NULL
              AND (state=''U'' or state=''C'') AND tombstone IS NULL GROUP BY rse_id)
LOOP
        MERGE INTO atlas_rucio.rse_usage USING DUAL ON (RSE_USAGE.rse_id = usage.rse_id and source = ''unavailable'')
        WHEN MATCHED THEN UPDATE SET used=usage.bytes, files=usage.files, updated_at=sysdate
        WHEN NOT MATCHED THEN INSERT (rse_id, source, used, files, updated_at, created_at) VALUES (usage.rse_id, ''unavailable'', usage.bytes, usage.files, sysdate, sysdate);
        COMMIT;
END LOOP;
END;', number_of_arguments=>0, start_date=>NULL, repeat_interval=>'Freq=Minutely;Interval=30', end_date=>NULL);
END;
--/
