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
