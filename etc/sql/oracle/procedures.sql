-- Dependency: the LOGGING_TABPARTITIONS table must be exist beforehand

-- 23th Oct 2013, Gancho Dimitrov
-- a PLSQL procedure for adding new LIST partition to any relevant Rucio table
-- use of DBMS_ASSERT for validation of the input. Sanitise the input by replacing the dots and dashes into the SCOPE names by underscore for the partition names to be Oracle friendly.


--/
create or replace PROCEDURE ADD_NEW_PARTITION( m_tabname VARCHAR2, m_partition_name VARCHAR2)
AS
	-- PRAGMA AUTONOMOUS_TRANSACTION;
	-- define exception handling for the "ORA-00054: resource busy and acquire with NOWAIT specified" error
	resource_busy EXCEPTION;
	PRAGMA exception_init (resource_busy,-54);
	stmt VARCHAR2(1000);
	v_error_message VARCHAR2(1000);
BEGIN
	-- version 1.2 with the use of the DBMS_ASSERT package for validation of the input value
	-- the partition names are capitalised as by default
	-- dots and dashes are replaced into the SCOPE names by underscore for the partition names to be Oracle friendly
	-- Oracle has specific meaning/treatment for these symbols and INTERVAL stats gathering does not work
	LOOP
		   BEGIN

			-- the DBMS_ASSERT.SIMPLE_SQL_NAME is needed to verify that the input string is a simple SQL name.
			-- The name must begin with an alphabetic character. It may contain alphanumeric characters as well as the characters _, $, and # as of the second position

            stmt := 'ALTER TABLE '|| DBMS_ASSERT.QUALIFIED_SQL_NAME ( m_tabname ) ||' ADD PARTITION ' || DBMS_ASSERT.SIMPLE_SQL_NAME(REPLACE(REPLACE(UPPER(m_partition_name),'.', '_'), '-', '_' )) || ' VALUES  ('|| DBMS_ASSERT.ENQUOTE_LITERAL(m_partition_name) ||')';

            DBMS_UTILITY.exec_ddl_statement(stmt);

			-- a logging record
			INSERT INTO  LOGGING_TABPARTITIONS(table_name, partition_name, partition_value , action_type, action_date, executed_sql_stmt, message )
			VALUES (m_tabname, REPLACE(REPLACE(UPPER(m_partition_name),'.', '_'), '-', '_' ), m_partition_name ,'CREATE', systimestamp, stmt, 'success');
		     	EXIT;
		   EXCEPTION
    			WHEN resource_busy
				THEN DBMS_LOCK.sleep(1);
				CONTINUE;
			WHEN OTHERS
				THEN v_error_message := SUBSTR(SQLERRM,1,1000);
				INSERT INTO  LOGGING_TABPARTITIONS(table_name, partition_name, partition_value, action_type, action_date, executed_sql_stmt, message )
				VALUES (m_tabname, REPLACE(REPLACE(UPPER(m_partition_name),'.', '_'), '-', '_' ), m_partition_name ,'CREATE', systimestamp, stmt, v_error_message );
				EXIT;
		   END;
	END LOOP;
COMMIT;
END;
/





-- 23th Mar 2015, Vincent Garone
-- a PLSQL procedure to write datasets which had replicas deleted into the updated_collection_replicas table

--/
CREATE OR REPLACE PROCEDURE "ATLAS_RUCIO"."REAPER_FINISHER" AS
    type array_raw is table of RAW(16) index by binary_integer;
    type array_scope is table of VARCHAR2(30) index by binary_integer;
    type array_name  is table of VARCHAR2(255) index by binary_integer;

    rse_ids array_raw;
    scopes  array_scope;
    names   array_name;

BEGIN
        DELETE FROM ATLAS_RUCIO.REPLICAS_HISTORY
        RETURNING RSE_ID, SCOPE, NAME BULK COLLECT INTO RSE_IDS, SCOPES, NAMES;

        FORALL i IN rse_ids.first .. rse_ids.last
                MERGE INTO ATLAS_RUCIO.UPDATED_COL_REP T
                USING (SELECT /*+ INDEX(C CONTENTS_CHILD_SCOPE_NAME_IDX) */ c.scope as s, c.name as n, rse_ids(i) as rse_id
                       FROM atlas_rucio.contents c
                       WHERE c.child_scope = scopes(i) and c.child_name = names(i)) e
                ON  (T.name = e.n and T."scope" = e.s and t.rse_id = e.rse_id)
                WHEN NOT MATCHED THEN
                INSERT (ID, "scope", NAME, DID_TYPE, RSE_ID, UPDATED_AT, CREATED_AT)
                VALUES (sys_guid, e.s, e.n, 'D', e.rse_id, sys_extract_utc(systimestamp), sys_extract_utc(systimestamp));
        COMMIT;
END;
/



-- 24th Mar 2015, Martin Barisits
-- a PL/SQL Proecdure to populate the collection_replicas table from the updated_col_rep table

--/
CREATE OR REPLACE PROCEDURE "ATLAS_RUCIO"."COLLECTION_REPLICAS_UPDATES" AS
    type array_raw is table of RAW(16) index by binary_integer;
    type array_scope is table of VARCHAR2(30) index by binary_integer;
    type array_name  is table of VARCHAR2(255) index by binary_integer;

    ids     array_raw;
    rse_ids array_raw;
    scopes  array_scope;
    names   array_name;

    ds_length                 NUMBER(19);
    ds_bytes                  NUMBER(19);
    available_replicas        NUMBER(19);
    old_available_replicas    NUMBER(19);
    ds_available_bytes        NUMBER(19);
    ds_replica_state          VARCHAR2(1);
    row_exists                NUMBER;
    
    CURSOR get_upd_col_rep IS SELECT id, scope, name, rse_id FROM ATLAS_RUCIO.updated_col_rep; 
BEGIN
    -- Delete duplicates
    DELETE FROM ATLAS_RUCIO.UPDATED_COL_REP A WHERE A.rowid > ANY (SELECT B.rowid FROM ATLAS_RUCIO.UPDATED_COL_REP B WHERE A.scope = B.scope AND A.name=B.name AND A.did_type=B.did_type AND (A.rse_id=B.rse_id OR (A.rse_id IS NULL and B.rse_id IS NULL)));
    -- Delete Update requests which do not have Collection_replicas
    DELETE FROM ATLAS_RUCIO.UPDATED_COL_REP A WHERE A.rse_id IS NOT NULL AND NOT EXISTS(SELECT * FROM ATLAS_RUCIO.COLLECTION_REPLICAS B WHERE B.scope = A.scope AND B.name = A.name  AND B.rse_id = A.rse_id);
    DELETE FROM ATLAS_RUCIO.UPDATED_COL_REP A WHERE A.rse_id IS NULL AND NOT EXISTS(SELECT * FROM ATLAS_RUCIO.COLLECTION_REPLICAS B WHERE B.scope = A.scope AND B.name = A.name);
    COMMIT;

    OPEN get_upd_col_rep;
    LOOP
        FETCH get_upd_col_rep BULK COLLECT INTO ids, scopes, names, rse_ids LIMIT 5000;
        FOR i IN 1 .. rse_ids.count
        LOOP
            DELETE FROM ATLAS_RUCIO.updated_col_rep WHERE id = ids(i);
            IF rse_ids(i) IS NOT NULL THEN
                -- Check one specific DATASET_REPLICA
                BEGIN
                    SELECT length, bytes, available_replicas_cnt INTO ds_length, ds_bytes, old_available_replicas FROM ATLAS_RUCIO.collection_replicas WHERE scope=scopes(i) and name=names(i) and rse_id=rse_ids(i);
                EXCEPTION
                    WHEN NO_DATA_FOUND THEN CONTINUE;
                END;

                SELECT count(*), sum(r.bytes) INTO available_replicas, ds_available_bytes FROM ATLAS_RUCIO.replicas r, ATLAS_RUCIO.contents c WHERE r.scope = c.child_scope and r.name = c.child_name and c.scope = scopes(i) and c.name = names(i) and r.state='A' and r.rse_id=rse_ids(i);
                IF available_replicas >= ds_length THEN
                    ds_replica_state := 'A';
                ELSE
                    ds_replica_state := 'U';
                END IF;

                IF old_available_replicas > 0 AND available_replicas = 0 THEN
                    DELETE FROM ATLAS_RUCIO.COLLECTION_REPLICAS WHERE scope = scopes(i) and name = names(i) and rse_id = rse_ids(i);
                ELSE               
                    UPDATE ATLAS_RUCIO.COLLECTION_REPLICAS 
                    SET state=ds_replica_state, available_replicas_cnt=available_replicas, length=ds_length, bytes=ds_bytes, available_bytes=ds_available_bytes, updated_at=sys_extract_utc(systimestamp)
                    WHERE scope = scopes(i) and name = names(i) and rse_id = rse_ids(i);
                END IF;
            ELSE
                -- Check all DATASET_REPLICAS of this DS
                SELECT count(*), SUM(bytes) INTO ds_length, ds_bytes FROM ATLAS_RUCIO.contents WHERE scope=scopes(i) and name=names(i);
                UPDATE ATLAS_RUCIO.COLLECTION_REPLICAS SET length=nvl(ds_length,0), bytes=nvl(ds_bytes,0) WHERE scope = scopes(i) and name = names(i);
                FOR rse IN (SELECT rse_id, count(*) as available_replicas, sum(r.bytes) as ds_available_bytes FROM ATLAS_RUCIO.replicas r, ATLAS_RUCIO.contents c WHERE r.scope = c.child_scope and r.name = c.child_name and c.scope = scopes(i) and c.name = names(i) and r.state='A' GROUP BY rse_id)
                LOOP
                    IF rse.available_replicas >= ds_length THEN
                        ds_replica_state := 'A';
                    ELSE
                        ds_replica_state := 'U';
                    END IF;
                    UPDATE ATLAS_RUCIO.COLLECTION_REPLICAS
                    SET state=ds_replica_state, available_replicas_cnt=rse.available_replicas, available_bytes=rse.ds_available_bytes, updated_at=sys_extract_utc(systimestamp)
                    WHERE scope = scopes(i) and name = names(i) and rse_id = rse.rse_id;
                END LOOP;
            END IF;
            COMMIT;
        END LOOP;
        EXIT WHEN get_upd_col_rep%NOTFOUND;
    END LOOP;
    CLOSE get_upd_col_rep;
    COMMIT;
END;
/


-- Mar  5 avr 2016 14:52:42 CEST, Vincent Garonne
-- a PL/SQL Proecdure to populate the rse_usage table from the UPDATED_RSE_COUNTERS table

--/
CREATE OR REPLACE PROCEDURE "ATLAS_RUCIO"."ABACUS_RSE" AS
    type array_raw is table of RAW(16) index by binary_integer;
    type array_number is table of NUMBER(19) index by binary_integer;
    r array_raw;
    f array_number;
    b array_number;
BEGIN
        DELETE FROM ATLAS_RUCIO.UPDATED_RSE_COUNTERS
        RETURNING rse_id, files, bytes BULK COLLECT INTO r,f,b;

        FORALL i in r.FIRST .. r.LAST
                MERGE INTO ATLAS_RUCIO.RSE_usage D
                USING (select r(i) as rse_id from dual) T
                ON (D.rse_id = T.rse_id and source='rucio')
                WHEN MATCHED THEN UPDATE SET files = files + f(i), used = used + b(i)
                WHEN NOT MATCHED THEN INSERT (rse_id, files, used, source, updated_at, created_at)
                VALUES (r(i), f(i), b(i), 'rucio', sys_extract_utc(systimestamp), sys_extract_utc(systimestamp));

        FORALL i in r.FIRST .. r.LAST
                MERGE INTO ATLAS_RUCIO.rse_usage_history D
                USING (select r(i) as rse_id from dual) T
                ON (D.rse_id = T.rse_id and source='rucio')
                WHEN MATCHED THEN UPDATE SET files = files + f(i), used = used+ b(i)
                WHEN NOT MATCHED THEN INSERT (rse_id, files, used, source, updated_at, created_at)
                VALUES (r(i), f(i), b(i), 'rucio', sys_extract_utc(systimestamp), sys_extract_utc(systimestamp));

        MERGE INTO ATLAS_RUCIO.RSE_USAGE_HISTORY H
        USING (SELECT hextoraw('00000000000000000000000000000000') as rse_id, 'rucio', sum(used) as bytes, sum(files) as files, sys_extract_utc(systimestamp) as updated_at
             FROM   ATLAS_RUCIO.rse_usage c, ATLAS_RUCIO.rses r
             WHERE  c.rse_id = r.id AND c.source = 'rucio' AND r.deleted = '0') U
        ON (h.rse_id = u.rse_id and h.source = 'rucio' and h.UPDATED_AT = u.UPDATED_AT)
        WHEN NOT MATCHED THEN INSERT(rse_id, source, used, files, updated_at, created_at)
        VALUES (u.rse_id, 'rucio', u.bytes, u.files, u.updated_at, u.updated_at);

         FOR usage IN (SELECT /*+ INDEX(R REPLICAS_STATE_IDX ) */ rse_id, SUM(bytes) AS bytes , COUNT(*) AS files
                FROM atlas_rucio.replicas r WHERE (CASE WHEN state != 'A' THEN rse_id END) IS NOT NULL
                AND (state='U' or state='C') AND tombstone IS NULL GROUP BY rse_id)
         LOOP
              MERGE INTO atlas_rucio.rse_usage USING DUAL ON (RSE_USAGE.rse_id = usage.rse_id and source = 'unavailable')
              WHEN MATCHED THEN UPDATE SET used=usage.bytes, files=usage.files, updated_at=sysdate
              WHEN NOT MATCHED THEN INSERT (rse_id, source, used, files, updated_at, created_at) VALUES (usage.rse_id, 'unavailable', usage.bytes, usage.files, sysdate, sysdate);
         END LOOP;

        COMMIT;
END;
/

-- 2017-03-23, Martin Barisits
-- a PL/SQL Proecdure to populate the account_usage table from the UPDATED_ACCOUNT_COUNTERS table

--/
CREATE OR REPLACE PROCEDURE "ATLAS_RUCIO"."ABACUS_ACCOUNT" AS
   type array_raw is table of RAW(16) index by binary_integer;
   type array_number is table of NUMBER(19) index by binary_integer;
   type array_varchar2 is table of VARCHAR2(25 CHAR) index by binary_integer;

   r array_raw;
   f array_number;
   b array_number;
   a array_varchar2;
BEGIN
       DELETE FROM ATLAS_RUCIO.UPDATED_ACCOUNT_COUNTERS
       RETURNING rse_id, files, bytes, account BULK COLLECT INTO r,f,b,a;

       FORALL i in r.FIRST .. r.LAST
               MERGE INTO ATLAS_RUCIO.account_usage D
               USING (select r(i) as rse_id, a(i) as account from dual) T
               ON (D.rse_id = T.rse_id and D.account = T.account )
               WHEN MATCHED THEN UPDATE SET files = files + f(i), bytes = bytes + b(i), updated_at = CAST(SYS_EXTRACT_UTC(LOCALTIMESTAMP) AS DATE) 
               WHEN NOT MATCHED THEN INSERT (rse_id, account, files, bytes, updated_at, created_at)
               VALUES (r(i), a(i), f(i), b(i), CAST(SYS_EXTRACT_UTC(LOCALTIMESTAMP) AS DATE), CAST(SYS_EXTRACT_UTC(LOCALTIMESTAMP) AS DATE) );


       COMMIT;
END;
/
