-- Rucio DB functions and procedure definitions for Oracle RDBMS  
-- Authors: Rucio team and Gancho Dimitrov 



-- ==============================================================================
-- ==============================  Functions  ===================================
-- ==============================================================================

CREATE OR REPLACE FUNCTION RSE2ID(RSE_NAME IN VARCHAR2)
RETURN RAW
DETERMINISTIC
IS
    rse_id RAW(16);
BEGIN
    SELECT id
    INTO rse_id
    FROM rses
    WHERE rse = RSE_NAME;

    RETURN rse_id;
END;
/

--------------------------------------------------------------------------------------------------------------------------------


CREATE OR REPLACE FUNCTION ID2RSE(RSE_ID IN RAW)
RETURN VARCHAR2
DETERMINISTIC
IS
    rse_name VARCHAR2(256);
BEGIN
    SELECT rse
    INTO rse_name
    FROM rses
    WHERE id = RSE_ID;

    RETURN rse_name;
END;
/

--------------------------------------------------------------------------------------------------------------------------------

GRANT EXECUTE on DBMS_CRYPTO to ATLAS_RUCIO; 


CREATE OR REPLACE FUNCTION LFN2PATH(scope varchar2, name varchar2) 
RETURN VARCHAR2 DETERMINISTIC IS
      md5  varchar2(1024) := lower(rawtohex(dbms_crypto.hash(to_clob(name), 2))) ;
      path varchar2(1024);
BEGIN

   IF scope like 'user.%' THEN
	path := 'user/' || regexp_substr(scope, '[^.]+', 1, 2) || '/' ;
   ELSIF scope like 'group.%' THEN
	path := 'group/' || regexp_substr(scope, '[^.]+', 1, 2) || '/' ;
   ELSE
	path := scope || '/';
   END IF;
   RETURN path || SUBSTR(md5, 1, 2) || '/' || SUBSTR(md5, 3, 2) || '/' || name;

END;
/


-- =========================================================================================
-- ==============================  Procedures  =============================================
-- =========================================================================================


-- PLSQL procedure for adding new LIST partition to any relevant Rucio table (the LOGGING_TABPARTITIONS table must exist beforehand) 
-- Use of DBMS_ASSERT for validation of the input. Sanitise the input by replacing the dots and dashes into the SCOPE names by underscore for the partition names to be Oracle friendly.

CREATE OR REPLACE PROCEDURE ADD_NEW_PARTITION( m_tabname VARCHAR2, m_partition_name VARCHAR2) 
AS
	-- PRAGMA AUTONOMOUS_TRANSACTION;
	-- define exception handling for the ORA-00054: resource busy and acquire with NOWAIT specified error
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
				-- THEN DBMS_LOCK.sleep(1);
				THEN DBMS_SESSION.sleep(1); -- from 12c onwards 
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




-------------------------------------------------------------------------------------------------------------------------------------------------



CREATE OR REPLACE PROCEDURE ABACUS_ACCOUNT AS
   type array_raw is table of RAW(16) index by binary_integer;
   type array_number is table of NUMBER(19) index by binary_integer;
   type array_varchar2 is table of VARCHAR2(25 CHAR) index by binary_integer;

   r array_raw;
   f array_number;
   b array_number;
   a array_varchar2;
BEGIN
       DELETE FROM UPDATED_ACCOUNT_COUNTERS
       RETURNING rse_id, files, bytes, account BULK COLLECT INTO r,f,b,a;

       FORALL i in r.FIRST .. r.LAST
               MERGE INTO account_usage D
               USING (select r(i) as rse_id, a(i) as account from dual) T
               ON (D.rse_id = T.rse_id and D.account = T.account )
               WHEN MATCHED THEN UPDATE SET files = files + f(i), bytes = bytes + b(i), updated_at = CAST(SYS_EXTRACT_UTC(LOCALTIMESTAMP) AS DATE)
               WHEN NOT MATCHED THEN INSERT (rse_id, account, files, bytes, updated_at, created_at)
               VALUES (r(i), a(i), f(i), b(i), CAST(SYS_EXTRACT_UTC(LOCALTIMESTAMP) AS DATE), CAST(SYS_EXTRACT_UTC(LOCALTIMESTAMP) AS DATE) );

       COMMIT;
END;
/

-------------------------------------------------------------------------------------------------------------------------------------------------


CREATE OR REPLACE PROCEDURE ABACUS_RSE AS 
    type array_raw is table of RAW(16) index by binary_integer;
    type array_number is table of NUMBER(19) index by binary_integer;
    r array_raw;
    f array_number;
    b array_number;
BEGIN
        DELETE FROM UPDATED_RSE_COUNTERS
        RETURNING rse_id, files, bytes BULK COLLECT INTO r,f,b;

        FORALL i in r.FIRST .. r.LAST
                MERGE INTO RSE_usage D
                USING (select r(i) as rse_id, sys_extract_utc(systimestamp) as now from dual) T
                ON (D.rse_id = T.rse_id and D.source = 'rucio')
                WHEN MATCHED THEN UPDATE SET files = files + f(i), used = used + b(i), updated_at = T.now           
                WHEN NOT MATCHED THEN INSERT (rse_id, files, used, source, updated_at, created_at)
                VALUES (r(i), f(i), b(i), 'rucio', T.now, T.now);                                
        COMMIT;
END;
/



-------------------------------------------------------------------------------------------------------------------------------------------------


CREATE OR REPLACE PROCEDURE ADD_RSE_USAGE AS
BEGIN
      FOR i in (SELECT rse_usage.rse_id, 
                         rse_usage.used as bytes, 
                         rse_usage.free,                          
                         rse_usage.files, 
                         rse_usage.updated_at, 
                         rse_usage.source
                  FROM   rse_usage, rses
                  WHERE  rse_usage.rse_id = rses.id AND deleted = '0')
        LOOP
              MERGE INTO RSE_USAGE_HISTORY H
              USING (SELECT i.rse_id as rse_id, i.bytes as bytes, i.files as files, i.free as free, i.updated_at as updated_at, i.source as source from DUAL) U
              ON (h.rse_id = u.rse_id and h.source = U.source and h.updated_at = u.updated_at)
              WHEN NOT MATCHED THEN INSERT(rse_id, source, used, files, free, updated_at, created_at)
              VALUES (u.rse_id, U.source, u.bytes, u.files, u.free, u.updated_at, u.updated_at);
        END LOOP;
              
        MERGE INTO RSE_USAGE_HISTORY H
        USING (SELECT hextoraw('00000000000000000000000000000000') as rse_id, 'rucio', sum(used) as bytes, sum(files) as files, sys_extract_utc(systimestamp) as updated_at
             FROM   rse_usage c, rses r
             WHERE  c.rse_id = r.id AND c.source = 'rucio' AND r.deleted = '0') U
        ON (h.rse_id = u.rse_id and h.source = 'rucio' and h.UPDATED_AT = u.UPDATED_AT)
        WHEN NOT MATCHED THEN INSERT(rse_id, source, used, files, updated_at, created_at)
        VALUES (u.rse_id, 'rucio', u.bytes, u.files, u.updated_at, u.updated_at);

         FOR usage IN (SELECT /*+ INDEX(R REPLICAS_STATE_IDX ) */ rse_id, SUM(bytes) AS bytes , COUNT(*) AS files
                FROM replicas r WHERE (CASE WHEN state != 'A' THEN rse_id END) IS NOT NULL
                AND (state='U' or state='C') AND tombstone IS NULL GROUP BY rse_id)
         LOOP
              MERGE INTO rse_usage USING DUAL ON (RSE_USAGE.rse_id = usage.rse_id and source = 'unavailable')
              WHEN MATCHED THEN UPDATE SET used=usage.bytes, files=usage.files, updated_at=sysdate
              WHEN NOT MATCHED THEN INSERT (rse_id, source, used, files, updated_at, created_at) VALUES (usage.rse_id, 'unavailable', usage.bytes, usage.files, sysdate, sysdate);
         END LOOP;
                                
        COMMIT;
END;
/



-------------------------------------------------------------------------------------------------------------------------------------------------

-- PLSQL procedure for sustaining DAYS_OFFSET days sliding window on chosen table which has automatic INTERVAL partitioning NUMTODSINTERVAL(1,'DAY')


CREATE OR REPLACE PROCEDURE RUCIO_DATA_SLIDING_WINDOW (mytab_name VARCHAR2, DAYS_OFFSET NUMBER default 90) AUTHID DEFINER
AS
-- Procedure for sustaining DAYS_OFFSET days sliding window on chosen table which has automatic INTERVAL partitioning NUMTODSINTERVAL(1,'DAY')

-- Define exception handling for the ORA-00054: resource busy and acquire with NOWAIT specified error
resource_busy EXCEPTION;
PRAGMA exception_init (resource_busy,-54);

stmt VARCHAR2(4000);
TYPE part_names IS TABLE OF VARCHAR2(30) INDEX BY BINARY_INTEGER;
coll_parts part_names;
messg VARCHAR2(10);
fullq_name VARCHAR2(100);

BEGIN

-- ver 1.2, last update 30th Oct 2014

-- Note: Oracle does NOT allow dropping of the last remaining non-interval partition (ORA-14758)! That is why is better to have INTERVAL = 'YES' condition in the WHERE clause
-- get the older than the last DAYS_OFFSET partitions (days)

-- the DBMS_ASSERT.SQL_OBJECT_NAME function checks that the input string represents an existing object
-- The ORA-44002: invalid object name exception is raised when the input string does not match an existing object name
SELECT DBMS_ASSERT.SQL_OBJECT_NAME( sys_context('USERENV', 'CURRENT_SCHEMA') || '.' || UPPER(mytab_name) ) into fullq_name FROM DUAL;


SELECT partition_name BULK COLLECT INTO coll_parts
FROM USER_TAB_PARTITIONS
WHERE table_name = UPPER(mytab_name)
AND INTERVAL = 'YES' AND partition_position <= (SELECT MAX(partition_position) - DAYS_OFFSET FROM USER_TAB_PARTITIONS
WHERE table_name = UPPER(mytab_name) );

-- do NOT drop partitions that are within DAYS_OFFSET from now. In that case exit the procedure
IF (coll_parts.COUNT <= 0) THEN
	stmt:= 'USER DEFINED INFO: There are NOT partitions with data older than ' || to_char(DAYS_OFFSET) || ' days for drop!';
	-- this RAISE call is commented out as the procedure will be called from within a scheduler job monthly and would be not good to be shown error on the shifters page
	-- RAISE_APPLICATION_ERROR(-20101, stmt );
	return;
END IF;

-- Verification and partition drop part --

FOR j IN 1 .. coll_parts.COUNT LOOP

	-- for each older than the last DAYS_OFFSET partitions check whether the MAX(modificationdate) is smaller than DAYS_OFFSET days
	stmt := 'SELECT (CASE WHEN MAX(created_at) < (SYSDATE - ' || DAYS_OFFSET || ') THEN ''OK'' ELSE ''NOT OK'' END ) FROM ' ||UPPER(mytab_name)||' PARTITION ( ' || coll_parts(j) || ')' ;
	-- DBMS_OUTPUT.put_line(stmt);

	EXECUTE IMMEDIATE stmt INTO messg;

	IF (messg = 'OK') THEN
		stmt := 'ALTER TABLE '|| UPPER(mytab_name)||' DROP PARTITION ' || coll_parts(j) ;

		-- loop until gets exclusive lock on the table
		LOOP
		   BEGIN
			EXECUTE IMMEDIATE stmt;
		     	EXIT;
		   EXCEPTION
    			WHEN resource_busy 
			-- THEN DBMS_LOCK.sleep(1);
			THEN DBMS_SESSION.sleep(1); -- from 12c onwards 

		   END;
		END LOOP;
	END IF;

END LOOP;

END;
/



-------------------------------------------------------------------------------------------------------------------------------------------------


CREATE OR REPLACE PROCEDURE RUCIO_TABLE_SL_WINDOW (mytab_name VARCHAR2, mytab_column VARCHAR2, part_offset NUMBER DEFAULT 3, part_range NUMBER DEFAULT 1) AUTHID DEFINER
AS
-- Procedure for sustaining partition offset sliding window on a given table which has automatic INTERVAL partitioning NUMTODSINTERVAL(part_range)
-- the DROP partition clause is with  UPDATE GLOBAL INDEXES option
-- mytab_name: name of the table on which will be enforced a sliding window policy
-- mytab_column: a DATE or a TIMESTAMP column on which is based the RANGE (+ interval) partitioning
-- part_offset: the number of most recent partitions which have to stay in the table
-- part_range: the period in days/months/years defined for a partition

-- define exception handling for the ORA-00054: resource busy and acquire with NOWAIT specified error
resource_busy EXCEPTION;
PRAGMA exception_init (resource_busy,-54);

stmt VARCHAR2(4000);
TYPE part_names IS TABLE OF VARCHAR2(30) INDEX BY BINARY_INTEGER;
coll_parts part_names;
messg VARCHAR2(10);
fullq_name VARCHAR2(100);

BEGIN

-- ver 1.0, last update 16th January 2015

-- Note: Oracle does NOT allow dropping of the last remaining non-interval partition (ORA-14758)! That is why is better to have INTERVAL = 'YES' condition in the WHERE clause
-- get the older than the last DAYS_OFFSET partitions (days)

-- the DBMS_ASSERT.SQL_OBJECT_NAME function checks that the input string represents an existing object
-- The ORA-44002: invalid object name exception is raised when the input string does not match an existing object name
SELECT DBMS_ASSERT.SQL_OBJECT_NAME( sys_context('USERENV', 'CURRENT_SCHEMA') || '.' || UPPER(mytab_name) ) into fullq_name FROM DUAL;

SELECT partition_name BULK COLLECT INTO coll_parts
FROM USER_TAB_PARTITIONS
WHERE table_name = UPPER(mytab_name)
AND INTERVAL = 'YES' AND partition_position <= (SELECT MAX(partition_position) - part_offset FROM USER_TAB_PARTITIONS
WHERE table_name = UPPER(mytab_name) );

-- do NOT drop partitions that are within DAYS_OFFSET from now. In that case exit the procedure
IF (coll_parts.COUNT <= 0) THEN
	stmt:= 'USER DEFINED INFO: There are NOT partitions with data older than ' || to_char(part_offset*part_range) || ' days for drop!';
	-- this RAISE call is commented out as the procedure will be called from within a scheduler job monthly and would be not good to be shown error on the shifters page
	-- RAISE_APPLICATION_ERROR(-20101, stmt );
	return;
END IF;

-- Verification and partition drop part --
FOR j IN 1 .. coll_parts.COUNT LOOP

	-- for each older than the last DAYS_OFFSET partitions check whether the MAX(modificationdate) is smaller than DAYS_OFFSET days
	stmt := 'SELECT (CASE WHEN MAX('||mytab_column||') < (SYSDATE - ' || part_offset*part_range || ') THEN ''OK'' ELSE ''NOT OK'' END ) FROM ' ||UPPER(mytab_name)||' PARTITION ( ' || coll_parts(j) || ')' ;
	-- DBMS_OUTPUT.put_line(stmt);

	EXECUTE IMMEDIATE stmt INTO messg;

	IF (messg = 'OK') THEN
		stmt := 'ALTER TABLE '|| UPPER(mytab_name)||' DROP PARTITION ' || coll_parts(j) || ' UPDATE GLOBAL INDEXES';

		-- loop until gets exclusive lock on the table
		LOOP
		   BEGIN
			EXECUTE IMMEDIATE stmt;
		     	EXIT;
		   EXCEPTION
    			WHEN resource_busy 
			-- THEN DBMS_LOCK.sleep(1);
			THEN DBMS_SESSION.sleep(1); -- from Oracle 12c onwards 
		   END;
		END LOOP;
	END IF;

END LOOP;

END;
/


-------------------------------------------------------------------------------------------------------------------------------------------------


CREATE OR REPLACE PROCEDURE RUCIO_ACCOUNT_LOGICAL_BYTES 
AS
BEGIN

  -- 4th Sept 2017, ver 1.3, reads from the DIDS table with parallelism 2
  -- Procedure for computing the logical bytes (based on the catalog only, not on the real file replicas on the Grid) based on the information in the DIDS table

  -- Special condition in the FOR query to get only the SCOPEs that have not been computed within the same day. This is for case when the job fails for some reason and is re-started again
    FOR i IN ( SELECT scope FROM scopes WHERE scope not like 'mock%' AND scope NOT IN (SELECT DISTINCT curr_scope FROM RUCIO_ACCOUNTING_LOGICAL_BYTES where CURRTIME > TRUNC(sysdate) ) ORDER BY scope ) LOOP

      INSERT INTO RUCIO_ACCOUNTING_LOGICAL_BYTES
	(
	CURR_SCOPE,
	COMMON_SCOPE,
	STREAM_NAME,
	DATATYPE,
	HIDDEN,
	ACCOUNT,
	PROVENANCE,
	CAMPAIGN,
	PHYS_GROUP,
	PROD_STEP,
	GROUP_CNT,
	BYTES
	)
      SELECT /*+ FULL(d) PARALLEL(d 2) NO_INDEX_RS(d DIDS_PK) NO_INDEX_FFS(d DIDS_PK) */
            d.SCOPE,
            CASE
              WHEN d.scope LIKE 'user%'
              THEN 'user'
              WHEN d.scope LIKE 'group%'
              THEN 'group'
              WHEN project IS NULL
              THEN NVL(d.scope, 'other')
              ELSE NVL(d.project, 'other')
             END AS common_scope,
            NVL(d.stream_name, 'other'),
            NVL(d.datatype, 'other'),
            NVL(d.hidden, 0),
            NVL(d.account, 'other'),
            NVL(d.provenance, 'other'),
            NVL(d.campaign, 'other'),
            NVL(d.phys_group, 'other'),
            NVL(d.prod_step, 'other'),
            COUNT(1),
            SUM(d.bytes)
          FROM DIDS d
          WHERE d.DID_TYPE = 'F' AND d.availability!='L' AND d.SCOPE = i.scope
          GROUP BY
	    d.SCOPE,
            CASE
              WHEN d.scope LIKE 'user%'
              THEN 'user'
              WHEN d.scope LIKE 'group%'
              THEN 'group'
              WHEN project IS NULL
              THEN NVL(d.scope, 'other')
              ELSE NVL(d.project, 'other')
            END,
            d.stream_name,
            d.datatype,
            d.hidden,
            d.account,
            d.provenance,
            d.campaign,
            d.phys_group,
            d.prod_step
          ;

        COMMIT;

    END LOOP;

    EXCEPTION
      WHEN NO_DATA_FOUND THEN
          NULL;
      WHEN OTHERS THEN
          RAISE;
END;
/


-------------------------------------------------------------------------------------------------------------------------------------------------


CREATE OR REPLACE PROCEDURE RUCIO_ACCOUNTING_ALL_SCOPES 
AS
  curr_time DATE;
  to_delete CHAR(1);
  num_null_currtime NUMBER(10);
BEGIN

EXECUTE IMMEDIATE 'ALTER SESSION SET workarea_size_policy=MANUAL';
EXECUTE IMMEDIATE 'ALTER SESSION SET sort_area_size=2100000000';
EXECUTE IMMEDIATE 'ALTER SESSION SET hash_area_size=2100000000';

-- 9th Nov 2021, version 1.7, include new rep_type column. rep_type defined as following :
-- rep_type = 3 if no rule (similar to secondary). Cached data
-- rep_type = 2 if locked rule. Custodial data
-- rep_type = 1 if non locked rule with no expiration data. Permanent data
-- rep_type = 0 if non locked rule with expiration date. Temporary data
-- 28th May 2018, version 1.6, added check for the number or rows when the CURRTIME is null
-- 10th Oct 2017, version 1.5, The CURRTIME is populated only at the end of the work because of the Monit Flume JDBC sorce  
-- Direct select - insert instead of passing data via collection.
-- Added 3 more metrics (columns to the RUCIO_ACCOUNTING_TAB and HIST tables) on which is based the computation TIER, SPACETOKEN, GRP_DATATYPE


-- In order to keep the history of the computations
-- Check whether there is already data from the same date. If there are, then to_delete = 'N'

 to_delete :='Y';
 num_null_currtime := 0;
 
 SELECT  UNIQUE (case when ( TRUNC(currtime) = TRUNC(sysdate) ) then 'N'  else 'Y' end) INTO to_delete FROM RUCIO_ACCOUNTING_TAB;
 -- 28th May 2018: necessary for situations when the FOR loop did not finish for all scopes and partial information has left into the RUCIO_ACCOUNTING_TAB table 
 select count(*) INTO num_null_currtime from RUCIO_ACCOUNTING_TAB where currtime is null;

 
 IF to_delete = 'Y' THEN
    
    IF num_null_currtime = 0 THEN 
    	INSERT /*+ append */ INTO RUCIO_ACCOUNTING_HIST_TAB
        SELECT * FROM RUCIO_ACCOUNTING_TAB;
    END IF;
    
 	DELETE FROM RUCIO_ACCOUNTING_TAB;
	COMMIT;
 END IF;


-- Because the job that calls this proc is RESTARTABLE in case of error, the query in the FOR clause is as the following :
FOR i IN ( SELECT scope FROM scopes WHERE scope NOT LIKE 'mock%' AND scope NOT IN (SELECT distinct curr_scope FROM RUCIO_ACCOUNTING_TAB) ORDER BY scope ) LOOP

     --   curr_time := sysdate; -- single current time for each computed scope

	INSERT INTO RUCIO_ACCOUNTING_TAB
    ( RSE,
    SCOPE,
    STREAM_NAME,
    DATATYPE,
    TOMBSTONE,
    HIDDEN,
    ACCOUNT,
    PROVENANCE,
    CAMPAIGN,
    PHYS_GROUP,
    PROD_STEP,
    GROUP_CNT,
    BYTES,
    CURR_SCOPE,
    TIER,
    SPACETOKEN,
    GRP_DATATYPE,
    SITE,
    REP_TYPE)
        WITH l AS
         (SELECT /*+ use_hash(a,b) full(a) full(b) */ a.scope,
                                                      a.name,
                                                      a.rse_id,
                                                      MAX(a.bytes) AS fbytes,
                                                      MAX(CASE
                                                              WHEN b.locked=1 THEN 2
                                                              WHEN b.expires_at IS NULL THEN 1
                                                              WHEN NOT b.expires_at IS NULL THEN 0
                                                          END) AS rep_type
          FROM LOCKS a,
               RULES b
          WHERE a.rule_id=b.id
            AND a.scope = i.scope
            AND b.scope = i.scope
          GROUP BY a.scope,
                   a.name,
                   a.rse_id)

        SELECT /*+ LEADING(R D RS L) USE_HASH(RS) USE_HASH(R) USE_HASH(L) USE_HASH(D) INDEX_FFS(RS ("RSES"."ID")) FULL(R) FULL(D) USE_HASH_AGGREGATION */
	-- curr_time,
        rs.rse,
        CASE WHEN d.scope LIKE 'user%' THEN 'user'
           WHEN d.scope LIKE 'group%' THEN 'group'
           WHEN project IS NULL THEN NVL(d.scope, 'other')
           ELSE NVL(d.project, 'other') END as scope,
        NVL(d.stream_name, 'other'),
        NVL(d.datatype, 'other'),
        CASE WHEN tombstone IS NOT NULL AND tombstone < sysdate AND NVL(lock_cnt, 0) = 0 THEN 'secondary'
           WHEN (tombstone IS NULL OR tombstone>sysdate) AND rs.rse_type='TAPE' THEN 'custodial'
           WHEN (tombstone IS NULL OR tombstone>sysdate) THEN 'primary'
           ELSE 'other' END tombstone,
        NVL(d.hidden, 0),
        NVL(d.account, 'other'),
        NVL(d.provenance, 'other'),
        NVL(d.campaign, 'other'),
        NVL(d.phys_group, 'other'),
        NVL(d.prod_step, 'other'),
        COUNT(1),
        SUM(r.bytes),
        d.scope,
	NULL, /* temporary NULL for the TIER column. After the loop it will be computed */
--      rmap.value as tier,
        regexp_substr(rs.rse, '[^_]+$', 1, 1) as spacetoken,
        regexp_replace(d.datatype, '_[^_]+$', '', 1, 1) as grp_datatype ,
	NULL, /* temporary NULL for the SITE column. After the loop it will be computed */
        NVL(l.rep_type, 3)
        FROM DIDS d,
           REPLICAS r LEFT OUTER JOIN l on r.scope=l.scope and r.name=l.name and r.rse_id=l.rse_id,
           RSES rs
--         ADG_ONLY_RSES_ATTR_MAP rmap
        WHERE
        d.DID_TYPE = 'F'
	AND d.scope = i.scope
        AND r.scope = i.scope
        AND d.name = r.name
        AND r.state = 'A'
        AND rs.id = r.rse_id
        AND rs.deleted != 1
--      AND rmap.rse_id=r.rse_id
--      AND rmap.key='tier'
        GROUP BY sysdate, rs.rse,
            CASE WHEN d.scope LIKE 'user%' THEN 'user'
                WHEN d.scope LIKE 'group%' THEN 'group'
                WHEN project IS NULL THEN NVL(d.scope, 'other')
            ELSE NVL(d.project, 'other') END,
            d.stream_name, d.datatype,
            CASE WHEN tombstone IS NOT NULL AND tombstone < sysdate AND NVL(lock_cnt, 0) = 0 THEN 'secondary'
               WHEN (tombstone IS NULL OR tombstone>sysdate) AND rs.rse_type='TAPE' THEN 'custodial'
               WHEN (tombstone IS NULL OR tombstone>sysdate) THEN 'primary'
               ELSE 'other' END,
            d.hidden,
            d.account,
            d.provenance,
            d.campaign,
            d.phys_group,
            d.prod_step,
            l.rep_type,
            d.scope ;
--            rmap.value,
--            regexp_substr(rs.rse, '[^_]+$', 1, 1),
--            regexp_replace(d.datatype, '_[^_]+$', '', 1, 1);

         COMMIT;

    END LOOP;

   
    curr_time := sysdate; -- single current time for each computed scope

    /* 10th Oct 2017: 
    The IT Monit Flume JDBCsource queries every hour and gets any new records from the table (based on the currtime column). 
    That is why this column has to be populated at the end. If the currtime is updated in the LOOP, the TIER and SITE values are missed by Flume. 
    */

	-- Update the TIER and SITE columns with the real Tier and Site value from the RSE_ATTR_MAP table
	UPDATE RUCIO_ACCOUNTING_TAB tab
	set 
    CURRTIME = curr_time, 
    TIER = (select m.value from RSE_ATTR_MAP m, RSES r where m.rse_id=r.id AND r.rse = tab.rse AND m.key='tier'),
	SITE = (select m.value from RSE_ATTR_MAP m, RSES r where m.rse_id=r.id AND r.rse = tab.rse AND m.key='site');
	COMMIT;

    EXCEPTION
      WHEN NO_DATA_FOUND THEN
          NULL;
      WHEN OTHERS THEN
          RAISE;

END;
/




-------------------------------------------------------------------------------------------------------------------------------------------------



CREATE OR REPLACE PROCEDURE ESTIMATE_TRANSFER_TIME 
AS
BEGIN

   /* 28th Sept 2017, Ver 1.0 , procedure estimating the files transfer time from source to destination on the Grid */
   /* Note: the UPDATEs of about 500K-600K are done within standalone transactions in order to avoid rows lock for long time (minutes) */

   FOR req IN
   (
      SELECT
           scope,
           name,
           source_rse_id,
           dest_rse_id,
               CASE
                   WHEN NVL(transfer_speed, 0)!=0
                   THEN sys_extract_utc(systimestamp) + numtodsinterval((SUM(bytes) OVER (partition BY src_site, dest_site ORDER BY src_site, dest_site, created_at rows BETWEEN unbounded preceding AND CURRENT row))/transfer_speed/1000000, 'second')
                   ELSE NULL
               END AS estimated_at
         FROM
           (
               SELECT
			/* the ORDERED hint is important as this instructs the CBO to perform the HASH join in the order the tables appear in the FROM clause */
			/*+ ORDERED FULL(a) INDEX_FFS(b DISTANCES_PK) INDEX_FFS(src RSE_ATTR_MAP_PK) INDEX_FFS(dest RSE_ATTR_MAP_PK)*/
                   scope,
                   name,
                   bytes,
                   a.created_at,
                   finished,
                   a.source_rse_id,
                   src.value AS src_site,
                   a.dest_rse_id,
                   dest.value AS dest_site,
                   transfer_speed
               FROM
                   distances b,
                   requests a,
                   rse_attr_map src,
                   rse_attr_map dest
               WHERE
                   state='S'
               AND a.source_rse_id=b.src_rse_id
               AND a.dest_rse_id=b.dest_rse_id
               AND a.source_rse_id=src.rse_id
               AND src.key='site'
               AND a.dest_rse_id=dest.rse_id
               AND dest.key='site'
	)
	-- ORDER BY scope, name
)
   LOOP
       UPDATE
           requests
       SET
           estimated_at=req.estimated_at
       WHERE
           scope=req.scope
       AND name=req.name
       AND source_rse_id=req.source_rse_id
       AND dest_rse_id=req.dest_rse_id
       AND estimated_at IS NULL;

	COMMIT;

END LOOP;

END;
/




-------------------------------------------------------------------------------------------------------------------------------------------------


CREATE OR REPLACE PROCEDURE COLL_UPDATED_REPLICAS (virt_scope_gr VARCHAR2)
AS
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


	CURSOR get_upd_col_rep
	IS
	SELECT id, scope, name, rse_id
	FROM updated_col_rep
	WHERE virt_scope_group = virt_scope_gr
	ORDER BY scope, name;

BEGIN

	/* 22nd March 2018 , ver 1.0 */
	-- Within the requested virt_scope_gr delete the unnecessary rows
	-- Delete requests which do not have Collection_replicas
	DELETE FROM UPDATED_COL_REP A
	WHERE
	virt_scope_group = virt_scope_gr
	AND
	(
	A.rse_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM COLLECTION_REPLICAS B WHERE B.scope = A.scope AND B.name = A.name  AND B.rse_id = A.rse_id)
	)
	OR
	(
	A.rse_id IS NULL AND NOT EXISTS(SELECT 1 FROM COLLECTION_REPLICAS B WHERE B.scope = A.scope AND B.name = A.name)
	);

     -- Delete duplicates
    DELETE FROM UPDATED_COL_REP A
	WHERE
	virt_scope_group = virt_scope_gr
	AND
	A.rowid > ANY (SELECT B.rowid FROM updated_col_rep B WHERE A.scope = B.scope AND A.name=B.name AND A.did_type=B.did_type AND (A.rse_id=B.rse_id OR (A.rse_id IS NULL and B.rse_id IS NULL)));

	COMMIT;

    -- Execute the query
    OPEN get_upd_col_rep;
    LOOP
        FETCH get_upd_col_rep BULK COLLECT INTO ids, scopes, names, rse_ids LIMIT 50000;
        FOR i IN 1 .. rse_ids.count
        LOOP
            DELETE FROM updated_col_rep WHERE id = ids(i);
            IF rse_ids(i) IS NOT NULL THEN
                -- Check one specific DATASET_REPLICA
                BEGIN
                    SELECT length, bytes, available_replicas_cnt INTO ds_length, ds_bytes, old_available_replicas FROM collection_replicas WHERE scope=scopes(i) and name=names(i) and rse_id=rse_ids(i);
                EXCEPTION
                    WHEN NO_DATA_FOUND THEN CONTINUE;
                END;

                SELECT count(*), sum(r.bytes) INTO available_replicas, ds_available_bytes FROM replicas r, contents c WHERE r.scope = c.child_scope and r.name = c.child_name and c.scope = scopes(i) and c.name = names(i) and r.state='A' and r.rse_id=rse_ids(i);
                IF available_replicas >= ds_length THEN
                    ds_replica_state := 'A';
                ELSE
                    ds_replica_state := 'U';
                END IF;
                IF old_available_replicas > 0 AND available_replicas = 0 THEN
                    DELETE FROM COLLECTION_REPLICAS WHERE scope = scopes(i) and name = names(i) and rse_id = rse_ids(i);
                ELSE
                    UPDATE COLLECTION_REPLICAS
                    SET state=ds_replica_state, available_replicas_cnt=available_replicas, length=ds_length, bytes=ds_bytes, available_bytes=ds_available_bytes, updated_at=sys_extract_utc(systimestamp)
                    WHERE scope = scopes(i) and name = names(i) and rse_id = rse_ids(i);
                END IF;
            ELSE
                -- Check all DATASET_REPLICAS of this DS
                SELECT count(*), SUM(bytes) INTO ds_length, ds_bytes FROM contents WHERE scope=scopes(i) and name=names(i);
                UPDATE COLLECTION_REPLICAS SET length=nvl(ds_length,0), bytes=nvl(ds_bytes,0) WHERE scope = scopes(i) and name = names(i);
                FOR rse IN (SELECT rse_id, count(*) as available_replicas, sum(r.bytes) as ds_available_bytes FROM replicas r, contents c WHERE r.scope = c.child_scope and r.name = c.child_name and c.scope = scopes(i) and c.name = names(i) and r.state='A' GROUP BY rse_id)
                LOOP
                    IF rse.available_replicas >= ds_length THEN
                        ds_replica_state := 'A';
                    ELSE
                        ds_replica_state := 'U';
                    END IF;
                    UPDATE COLLECTION_REPLICAS
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



-------------------------------------------------------------------------------------------------------------------------------------------------


CREATE OR REPLACE PROCEDURE COLL_UPDATED_REPLICAS_ORAHASH (virt_scope_gr VARCHAR2, num_splitters NUMBER DEFAULT 0, portion_id NUMBER DEFAULT 0)
AS
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

	-- Get the rows of the asked virtual scope and data portion based to the num_splitters and the result from ORA_HASH(name, num_splitters ) = portion_id
	-- ORA_HASH computes a hash value for a given expression. It is useful for operations such as analyzing a subset of data and generating a random sample.
	CURSOR get_upd_col_rep
	IS
	SELECT id, scope, name, rse_id
	FROM updated_col_rep
	WHERE virt_scope_group = virt_scope_gr
	AND ORA_HASH(name, num_splitters ) = portion_id
	ORDER BY scope, name;

BEGIN

	/* 4nd April 2018, ver 1.0 */

	/* Within the requested virt_scope_gr and data portion based to the num_splitters and the result from ORA_HASH(name, num_splitters ) = portion_id, delete the unnecessary rows */
	-- Delete requests which do not have Collection_replicas
	DELETE FROM UPDATED_COL_REP A
	WHERE
	virt_scope_group = virt_scope_gr
	AND ORA_HASH(name, num_splitters) = portion_id
	AND
	(
	A.rse_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM COLLECTION_REPLICAS B WHERE B.scope = A.scope AND B.name = A.name  AND B.rse_id = A.rse_id)
	)
	OR
	(
	A.rse_id IS NULL AND NOT EXISTS(SELECT 1 FROM COLLECTION_REPLICAS B WHERE B.scope = A.scope AND B.name = A.name)
	);
	COMMIT;

     -- Delete duplicates
    DELETE FROM UPDATED_COL_REP A
	WHERE
	virt_scope_group = virt_scope_gr
	AND ORA_HASH(name, num_splitters) = portion_id
	AND
	A.rowid > ANY (SELECT B.rowid FROM updated_col_rep B WHERE A.scope = B.scope AND A.name=B.name AND A.did_type=B.did_type AND (A.rse_id=B.rse_id OR (A.rse_id IS NULL and B.rse_id IS NULL)));

	COMMIT;

    -- Execute the query
    OPEN get_upd_col_rep;
    LOOP
        FETCH get_upd_col_rep BULK COLLECT INTO ids, scopes, names, rse_ids LIMIT 70000;
        FOR i IN 1 .. rse_ids.count
        LOOP
            DELETE FROM updated_col_rep WHERE id = ids(i);
            IF rse_ids(i) IS NOT NULL THEN
                -- Check one specific DATASET_REPLICA
                BEGIN
                    SELECT length, bytes, available_replicas_cnt INTO ds_length, ds_bytes, old_available_replicas FROM collection_replicas WHERE scope=scopes(i) and name=names(i) and rse_id=rse_ids(i);
                EXCEPTION
                    WHEN NO_DATA_FOUND THEN CONTINUE;
                END;

                SELECT count(*), sum(r.bytes) INTO available_replicas, ds_available_bytes FROM replicas r, contents c WHERE r.scope = c.child_scope and r.name = c.child_name and c.scope = scopes(i) and c.name = names(i) and r.state='A' and r.rse_id=rse_ids(i);
                IF available_replicas >= ds_length THEN
                    ds_replica_state := 'A';
                ELSE
                    ds_replica_state := 'U';
                END IF;
                IF old_available_replicas > 0 AND available_replicas = 0 THEN
                    DELETE FROM COLLECTION_REPLICAS WHERE scope = scopes(i) and name = names(i) and rse_id = rse_ids(i);
                ELSE
                    UPDATE COLLECTION_REPLICAS
                    SET state=ds_replica_state, available_replicas_cnt=available_replicas, length=ds_length, bytes=ds_bytes, available_bytes=ds_available_bytes, updated_at=sys_extract_utc(systimestamp)
                    WHERE scope = scopes(i) and name = names(i) and rse_id = rse_ids(i);
                END IF;
            ELSE
                -- Check all DATASET_REPLICAS of this DS
                SELECT count(*), SUM(bytes) INTO ds_length, ds_bytes FROM contents WHERE scope=scopes(i) and name=names(i);
                UPDATE COLLECTION_REPLICAS SET length=nvl(ds_length,0), bytes=nvl(ds_bytes,0) WHERE scope = scopes(i) and name = names(i);
                FOR rse IN (SELECT rse_id, count(*) as available_replicas, sum(r.bytes) as ds_available_bytes FROM replicas r, contents c WHERE r.scope = c.child_scope and r.name = c.child_name and c.scope = scopes(i) and c.name = names(i) and r.state='A' GROUP BY rse_id)
                LOOP
                    IF rse.available_replicas >= ds_length THEN
                        ds_replica_state := 'A';
                    ELSE
                        ds_replica_state := 'U';
                    END IF;
                    UPDATE COLLECTION_REPLICAS
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



-------------------------------------------------------------------------------------------------------------------------------------------------


CREATE OR REPLACE PROCEDURE ADD_ACCOUNT_USAGE_HISTORY 
AS
BEGIN

	/* 9th Jan 2019: A PLSQL procedure for insertion of the changed (since the previous execution) rows from the ACCOUNT_USAGE into the ACCOUNT_USAGE_HISTORY table */

	MERGE INTO ACCOUNT_USAGE_HISTORY h 
	USING 
	( SELECT   account_usage.account,
                         account_usage.rse_id, 
                         account_usage.bytes,                          
                         account_usage.files, 
                         account_usage.updated_at
                  FROM   account_usage, rses
                  WHERE  account_usage.rse_id = rses.id AND deleted = '0') u 
	ON (h.rse_id = u.rse_id and h.account = u.account and h.updated_at = u.updated_at)
	WHEN NOT MATCHED THEN INSERT(account, rse_id, bytes, files,  updated_at, created_at)
	VALUES (u.account, u.rse_id, u.bytes, u.files, u.updated_at, CAST(SYS_EXTRACT_UTC(LOCALTIMESTAMP) AS DATE) );
        
COMMIT;

END;
/
