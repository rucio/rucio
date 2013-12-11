-- 23th Oct 2013, Gancho Dimitrov
-- a PLSQL procedure for adding new LIST partition to any relevant Rucio table
-- use of DBMS_ASSERT for validation of the input

-- Dependency: the LOGGING_TABPARTITIONS table must be exist beforehand

--/
create or replace PROCEDURE ADD_NEW_PARTITION(m_tabname VARCHAR2, m_partition_name VARCHAR2)
AS
	PRAGMA AUTONOMOUS_TRANSACTION;
	-- define exception handling for the "ORA-00054: resource busy and acquire with NOWAIT specified" error
	resource_busy EXCEPTION;
	PRAGMA exception_init (resource_busy,-54);
	stmt VARCHAR2(1000);
	v_error_message VARCHAR2(1000);
	full_qualified_name VARCHAR2(60);
BEGIN
   LOOP
        BEGIN
                stmt := 'ALTER TABLE '|| m_tabname ||' ADD PARTITION ' || DBMS_ASSERT.ENQUOTE_NAME(m_partition_name, capitalize=> TRUE) || ' VALUES  ('|| DBMS_ASSERT.ENQUOTE_LITERAL(m_partition_name) ||')';

                DBMS_UTILITY.exec_ddl_statement(stmt);

                -- a logging record
		INSERT INTO LOGGING_TABPARTITIONS(table_name, partition_name, action_type, action_date, executed_sql_stmt, message )
		VALUES (m_tabname, m_partition_name,'CREATE', systimestamp, stmt, 'success');
                EXIT;
	EXCEPTION
                WHEN resource_busy
                        THEN DBMS_LOCK.sleep(1);
                        CONTINUE;
	       WHEN OTHERS
	               THEN v_error_message := SUBSTR(SQLERRM,1,1000);
			     INSERT INTO LOGGING_TABPARTITIONS(table_name, partition_name, action_type, action_date, executed_sql_stmt, message )
			     VALUES (m_tabname, m_partition_name ,'CREATE', systimestamp, stmt, v_error_message );
			     EXIT;
        END;

    END LOOP;
    COMMIT;
END;
/
