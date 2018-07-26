-- 23th October 2013 , Gancho Dimitrov
-- Version of the Rucio database schema with tables being categorised in 4 categories, changed physical implementation and distributed on several tablespaces.

/* explanations

Table categories:
1. Small tables that host attribute data
2. Large partitioned fact tables
3. Tables with highly transient data (high insert and delete activity). Index rebuild would or shrink operations be needed.
4. Historical data - once written the content does not change. OLTP compression is activated for them to safe space.

Tablespace names created on the INTR database

ATLAS_RUCIO_ATTRIBUTE_DATA01
ATLAS_RUCIO_FACT_DATA01
ATLAS_RUCIO_TRANSIENT_DATA01
ATLAS_RUCIO_HIST_DATA01


-- ============================================== section ATTRIBUTES data ========================================================================
-- to reside in tablespace ATLAS_RUCIO_ATTRIBUTE_DATA01

ACCOUNTS
ACCOUNT_MAP
ACCOUNT_ATTR_MAP
SCOPES
RSES
RSE_ATTR_MAP
IDENTITIES
DID_KEYS
DID_KEY_MAP
SUBSCRIPTIONS


-- ============================================== section FACT data ==============================================================================
-- to reside in tablespace ATLAS_RUCIO_FACT_DATA01

DIDS
REPLICAS
RULES
LOCKS
DATASET_LOCKS
ACCOUNT_LIMITS
RSE_COUNTERS
RSE_LIMITS
RSE_PROTOCOLS
COLLECTION_REPLICAS


-- ============================================== section TRANSIENT data  ==========================================================================
-- to reside in tablespace ATLAS_RUCIO_TRANSIENT_DATA01

CONTENTS
REQUESTS
CALLBACKS
TOKENS
ACCOUNT_USAGE
RSE_USAGE
-- MOCK_FTS_TRANSFERS (obsolete)
UPDATED_DIDS
UPDATED_RSE_COUNTERS
UPDATED_ACCOUNT_COUNTERS
REPLICAS_HISTORY
UPDATED_COL_REP


-- ============================================== section HISTORICAL data =========================================================================
-- to reside in tablespace ATLAS_RUCIO_HIST_DATA01

DELETED_DIDS
REQUESTS_HISTORY
SUBSCRIPTIONS_HISTORY
RSE_USAGE_HISTORY
ACCOUNT_USAGE_HISTORY
LOGGING_TABPARTITIONS
RULES_HIST_RECENT
RULES_HISTORY

as total 31 tables (+ one obsolete)

--===================================================================================================
-- for dropping the existing tables
-- SELECT 'DROP TABLE ATLAS_RUCIO_RND.' || object_name || ';'
-- FROM dba_objects WHERE owner = 'ATLAS_RUCIO_RND'AND object_type = 'TABLE'
-- ORDER BY created desc;

*/







--==============================================================================================================================================================================
--===================================================== DB tables creation section =============================================================================================
--==============================================================================================================================================================================



-- ============================================== section ATTRIBUTES data ========================================================================
-- to reside in tablespace ATLAS_RUCIO_ATTRIBUTE_DATA01
--================================================================================================================================================

-- ========================================= ACCOUNTS (IOT type) =========================================
-- Desc: Table to store the list of accounts
-- Estimated volume: ~2000
-- Access pattern: By account

CREATE TABLE accounts (
    account VARCHAR2(25 CHAR),
    account_type VARCHAR2(7 CHAR),
    status VARCHAR2(9 CHAR),
    email VARCHAR2(255 CHAR),
    suspended_at DATE,
    deleted_at DATE,
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "ACCOUNTS_PK" PRIMARY KEY (account),
    CONSTRAINT "ACCOUNTS_TYPE_NN" CHECK ("ACCOUNT_TYPE" IS NOT NULL),
    CONSTRAINT "ACCOUNTS_STATUS_NN" CHECK ("STATUS" IS NOT NULL),
    CONSTRAINT "ACCOUNTS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "ACCOUNTS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "ACCOUNTS_TYPE_CHK" CHECK (account_type IN ('GROUP', 'USER', 'SERVICE')),
    CONSTRAINT "ACCOUNTS_STATUS_CHK" CHECK (status IN ('ACTIVE', 'DELETED', 'SUSPENDED')),
    CONSTRAINT "ACCOUNTS_NAME_LOWERCASE_CHK" CHECK (account=LOWER(account))
) ORGANIZATION INDEX TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;



-- ========================================= IDENTITIES =========================================
-- Description: Table to store the identities of the users
-- Estimated volume: ~2000 users * gss + x509 credentials : ~4000 rows
-- Access pattern: By identity, type
-- Because of the BLOB column, it is not appropriate to be an IOT structure

CREATE TABLE identities (
    identity VARCHAR2(2048 CHAR),
    identity_type VARCHAR2(8 CHAR),
    username VARCHAR2(255 CHAR),
    password VARCHAR2(255 CHAR),
    email VARCHAR2(255 CHAR),
    updated_at DATE,
    created_at DATE,
    deleted NUMBER(1),
    deleted_at DATE,
    salt BLOB,
    CONSTRAINT "IDENTITIES_PK" PRIMARY KEY (identity, identity_type),
    CONSTRAINT "IDENTITIES_TYPE_NN" CHECK ("IDENTITY_TYPE" IS NOT NULL),
    CONSTRAINT "IDENTITIES_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "IDENTITIES_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "IDENTITIES_DELETED_NN" CHECK (DELETED IS NOT NULL),
    CONSTRAINT "IDENTITIES_EMAIL_NN" CHECK (EMAIL IS NOT NULL),
    CONSTRAINT "IDENTITIES_TYPE_CHK" CHECK (identity_type IN ('X509', 'GSS', 'USERPASS', 'SSH')),
    CONSTRAINT "IDENTITIES_DELETED_CHK" CHECK (deleted IN (0, 1))
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;




-- ========================================= ACCOUNT_MAP (IOT type) =========================================
-- Desc: table to store the mapping account-identity
-- Estimated volume: ~2000 accounts * 4000 identities
-- Access pattern: by identity, type

CREATE TABLE account_map (
    identity VARCHAR2(2048 CHAR),
    identity_type VARCHAR2(8 CHAR),
    account VARCHAR2(25 CHAR),
    is_default NUMBER(1),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "ACCOUNT_MAP_PK" PRIMARY KEY (identity, identity_type, account),
    CONSTRAINT "ACCOUNT_MAP_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
    CONSTRAINT "ACCOUNT_MAP_ID_TYPE_FK" FOREIGN KEY(identity, identity_type) REFERENCES identities (identity, identity_type),
    CONSTRAINT "ACCOUNT_MAP_IS_DEFAULT_NN" CHECK (is_default IS NOT NULL),
    CONSTRAINT "ACCOUNT_MAP_IS_TYPE_NN" CHECK ("IDENTITY_TYPE" IS NOT NULL),
    CONSTRAINT "ACCOUNT_MAP_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "ACCOUNT_MAP_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "ACCOUNT_MAP_IS_TYPE_CHK" CHECK (identity_type IN ('X509', 'GSS', 'USERPASS', 'SSH')),
    CONSTRAINT "ACCOUNT_MAP_DEFAULT_CHK" CHECK (is_default IN (0, 1))
) ORGANIZATION INDEX COMPRESS 1 TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;


-- ========================================= ACCOUNT_ATTR_MAP (IOT type) =========================================
-- Description: Table to mapping between account attributes and account
-- Estimated volume: ~4000 * 2 account attributes
-- Access pattern: by account. By key or by "key/value"

CREATE TABLE atlas_rucio.account_attr_map (
	account VARCHAR2(25 CHAR) NOT NULL,
	key VARCHAR2(255 CHAR) NOT NULL,
	value VARCHAR2(255 CHAR),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "ACCOUNT_ATTR_MAP_PK" PRIMARY KEY (account, key),
	CONSTRAINT "ACCOUNT_ATTR_MAP_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
	CONSTRAINT "ACCOUNT_ATTR_MAP_CREATED_NN" CHECK (CREATED_AT IS NOT NULL),
	CONSTRAINT "ACCOUNT_ATTR_MAP_UPDATED_NN" CHECK (UPDATED_AT IS NOT NULL)
) ORGANIZATION INDEX TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;

CREATE INDEX atlas_rucio."ACCOUNT_ATTR_MAP_KEY_VALUE_IDX" ON atlas_rucio.account_attr_map (key, value) COMPRESS 2 TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;

-- ========================================= SCOPES (IOT type) =========================================
-- Description: Table to store the scopes
-- Estimated volume: ~4000
-- Access pattern: by scope

CREATE TABLE scopes (
    scope VARCHAR2(25 CHAR),
    account VARCHAR2(25 CHAR),
    is_default NUMBER(1),
    status CHAR(1 CHAR),
    closed_at DATE,
    deleted_at DATE,
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "SCOPES_PK" PRIMARY KEY (scope),
    CONSTRAINT "SCOPES_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
    CONSTRAINT "SCOPES_IS_DEFAULT_NN" CHECK (is_default IS NOT NULL),
    CONSTRAINT "SCOPES_STATUS_NN" CHECK (STATUS IS NOT NULL),
    CONSTRAINT "SCOPES_ACCOUNT_NN" CHECK ("ACCOUNT" IS NOT NULL),
    CONSTRAINT "SCOPES_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "SCOPES_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "SCOPES_DEFAULT_CHK" CHECK (is_default IN (0, 1)),
    CONSTRAINT "SCOPES_STATUS_CHK" CHECK (status IN ('C', 'D', 'O'))
) ORGANIZATION INDEX TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;

CREATE UNIQUE INDEX SCOPES_SCOPE_UQ ON SCOPES(UPPER(scope)) tablespace ATLAS_RUCIO_ATTRIBUTE_DATA01;

-- ========================================= RSES (IOT structure) =========================================
-- Description: Table to store the list of RSEs
-- Estimated volume: ~700 which can be reduced to ~200
-- Access pattern: By rse/id

CREATE TABLE rses (
    id RAW(16),
    rse VARCHAR2(255 CHAR),
    rse_type VARCHAR2(4 CHAR),
    deterministic NUMBER(1),
    volatile NUMBER(1),
    staging_area NUMBER(1),
    city VARCHAR2(255 CHAR),
    region_code VARCHAR2(2 CHAR),
    country_name VARCHAR2(255 CHAR),
    continent VARCHAR2(2 CHAR),
    time_zone VARCHAR2(255 CHAR),
    ISP VARCHAR2(255 CHAR),
    ASN VARCHAR2(255 CHAR),
    longitude FLOAT,
    latitude FLOAT,
    availability NUMBER(3,0) DEFAULT 7,
    updated_at DATE,
    created_at DATE,
    deleted NUMBER(1),
    deleted_at DATE,
    CONSTRAINT "RSES_PK" PRIMARY KEY (id),
    CONSTRAINT "RSES_RSE_UQ" UNIQUE (rse),
    CONSTRAINT "RSES_RSE_NN" CHECK ("RSE" IS NOT NULL),
    CONSTRAINT "RSES_TYPE_NN" CHECK ("RSE_TYPE" IS NOT NULL),
    CONSTRAINT "RSES_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "RSES_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "RSES_DELETED_NN" CHECK (DELETED IS NOT NULL),
    CONSTRAINT "RSES_TYPE_CHK" CHECK (rse_type IN ('DISK', 'TAPE')),
    CONSTRAINT "RSE_DETERMINISTIC_CHK" CHECK (deterministic IN (0, 1)),
    CONSTRAINT "RSE_VOLATILE_CHK" CHECK (volatile IN (0, 1)),
    CONSTRAINT "RSE_STAGING_AREA_CHK" CHECK (staging_area IN (0,1)),
    CONSTRAINT "RSES_DELETED_CHK" CHECK (deleted IN (0, 1))
) ORGANIZATION INDEX TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;




-- ========================================= RSE_ATTR_MAP (IOT structure) =========================================
-- Description: Table to mapping between rse attributes and rse
-- Estimated volume: ~700 * 10 rse attributes (t1, t0, etc.)
-- Access pattern: by rse_id. By key or by "key/value"

CREATE TABLE rse_attr_map (
    rse_id RAW(16),
    key VARCHAR2(255 CHAR),
    value VARCHAR2(255 CHAR),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "RSE_ATTR_MAP_PK" PRIMARY KEY (rse_id, key),
    CONSTRAINT "RSE_ATTR_MAP_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
    CONSTRAINT "RSE_ATTR_MAP_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "RSE_ATTR_MAP_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) ORGANIZATION INDEX TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;

CREATE INDEX RSE_ATTR_MAP_KEY_VALUE_IDX ON rse_attr_map (key, value) COMPRESS 2 TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;


-- ========================================= DID_KEYS =========================================
-- Description: Table to store the list of values for a key
-- Estimated volume: ~1000 (campaign ~20, datatype ~400, group,  ~20, prod_step ~30, project ~200, provenance ~10)
-- Access pattern: by key

CREATE TABLE did_keys (
    key VARCHAR2(255 CHAR),
    key_type VARCHAR2(10 CHAR),
    value_type VARCHAR2(255 CHAR),
    value_regexp VARCHAR2(255 CHAR),
    is_enum NUMBER(1),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "DID_KEYS_PK" PRIMARY KEY (key),
    CONSTRAINT "DID_KEYS_TYPE_NN" CHECK (key_type IS NOT NULL),
    CONSTRAINT "DID_KEYS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "DID_KEYS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "DID_KEYS_TYPE_CHK" CHECK (key_type IN ('ALL', 'DERIVED', 'COLLECTION', 'FILE'))
) ORGANIZATION INDEX TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;




-- ========================================= DID_KEY_MAP =========================================
-- Description: Table to store the list of values for a key
-- Estimated volume: ~1000 (campaign ~20, datatype ~400, group,  ~20, prod_step ~30, project ~200, provenance ~10)
-- Access pattern: by key. by key value.

CREATE TABLE did_key_map (
    key VARCHAR2(255 CHAR),
    value VARCHAR2(255 CHAR),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "DID_KEY_MAP_PK" PRIMARY KEY (key, value),
    CONSTRAINT "DID_MAP_KEYS_FK" FOREIGN KEY(key) REFERENCES did_keys (key),
    CONSTRAINT "DID_KEY_MAP_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "DID_KEY_MAP_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) ORGANIZATION INDEX TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;



-- ========================================= SUBSCRIPTIONS (not IOT table as otherwise an overflow segment has to be defined) =========================================
-- Description: Table to store subscriptions
-- Estimated volume: ~1000
-- Access pattern: by state. by name


CREATE TABLE subscriptions (
    id RAW(16),
    name VARCHAR2(64 CHAR),
    account VARCHAR2(25 CHAR),
    state CHAR(1 CHAR),
    policyid NUMBER(3),
    last_processed DATE,
    lifetime DATE,
    retroactive NUMBER(1),
    filter VARCHAR2(2048 CHAR),
    replication_rules VARCHAR2(1024 CHAR),
    comments VARCHAR2(4000 CHAR),
    expired_at DATE,
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "SUBSCRIPTIONS_PK" PRIMARY KEY (id),
    CONSTRAINT "SUBSCRIPTIONS_NAME_ACCOUNT_UQ" UNIQUE (name, account),
    CONSTRAINT "SUBSCRIPTIONS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
    CONSTRAINT "SUBSCRIPTIONS_ACCOUNT_NN" CHECK ("ACCOUNT" IS NOT NULL),
    CONSTRAINT "SUBSCRIPTIONS_RETROACTIVE_NN" CHECK ("RETROACTIVE" IS NOT NULL),
    CONSTRAINT "SUBSCRIPTIONS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "SUBSCRIPTIONS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "SUBSCRIPTIONS_STATE_CHK" CHECK (state IN ('I', 'A', 'B', 'U', 'N')),
    CONSTRAINT "SUBSCRIPTIONS_RETROACTIVE_CHK" CHECK (retroactive IN (0, 1))
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01 ;

CREATE INDEX SUBSCRIPTIONS_STATE_IDX ON subscriptions (STATE) COMPRESS 1 TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01 ;
CREATE INDEX SUBSCRIPTIONS_NAME_IDX ON subscriptions (NAME) TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01 ;


-- ============================================== section FACT data ==============================================================================
-- to reside in tablespace ATLAS_RUCIO_FACT_DATA01
-- ===============================================================================================================================================



-- ========================================= DIDS (list partitioned and list sub-partitioned) =========================================
-- Description: Table to store data identifiers
-- Estimated volume: 0.5 Billion
-- uniqueness constraint on scope,name over all types and deleted data
-- Access pattern:
--                 - by scope, name (type)
--                 - by scope, pattern, type (wildcard queries)
--                 - by expired_at to get the expired datasets
--                 - by new to get the new datasets




CREATE TABLE dids (
    scope VARCHAR2(25 CHAR),
    name VARCHAR2(255 CHAR),
    account VARCHAR2(25 CHAR),
    did_type CHAR(1 CHAR),
    is_open NUMBER(1),
    monotonic NUMBER(1) DEFAULT '0',
    hidden NUMBER(1) DEFAULT '0',
    obsolete NUMBER(1) DEFAULT '0',
    complete NUMBER(1),
    is_new NUMBER(1) DEFAULT '1',
    availability CHAR(1 CHAR),
    suppressed NUMBER(1) DEFAULT '0',
    bytes NUMBER(19),
    length NUMBER(19),
    md5 VARCHAR2(32 CHAR),
    adler32 VARCHAR2(8 CHAR),
    expired_at DATE,
    deleted_at DATE,
    events NUMBER(19),
    guid RAW(16),
    project VARCHAR2(50 CHAR),
    datatype VARCHAR2(50 CHAR),
    run_number NUMBER(10,0),
    stream_name VARCHAR2(70 CHAR),
    prod_step VARCHAR2(50 CHAR),
    version VARCHAR2(50 CHAR),
    task_id NUMBER(11),
    panda_id NUMBER(11),
    purge_replicas NUMBER(1) DEFAULT 1,
    campaign VARCHAR2(50 CHAR),
    updated_at DATE,
    created_at DATE,
    lumiblocknr NUMBER(10,0),
    provenance VARCHAR2(2 CHAR),
    phys_group VARCHAR2(25 CHAR),
    transient NUMBER(1,0),
    accessed_at DATE,
    closed_at DATE,
    eol_at DATE,
    is_archive NUMBER(1),
    constituent  NUMBER(1),
    access_cnt NUMBER(11),
    CONSTRAINT "DIDS_PK" PRIMARY KEY (scope, name) USING INDEX COMPRESS 1,
    CONSTRAINT "DIDS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
    CONSTRAINT "DIDS_SCOPE_FK" FOREIGN KEY(scope) REFERENCES scopes (scope),
    CONSTRAINT "DIDS_PHYS_GROUP_FK" FOREIGN KEY(phys_group) REFERENCES accounts (account),
    CONSTRAINT "DIDS_MONOTONIC_NN" CHECK ("MONOTONIC" IS NOT NULL),
    CONSTRAINT "DIDS_OBSOLETE_NN" CHECK ("OBSOLETE" IS NOT NULL),
    CONSTRAINT "DIDS_SUPP_NN" CHECK ("SUPPRESSED" IS NOT NULL),
    CONSTRAINT "DIDS_ACCOUNT_NN" CHECK ("ACCOUNT" IS NOT NULL),
    CONSTRAINT "DIDS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "DIDS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "DIDS_TYPE_CHK" CHECK (did_type IN ('C', 'D', 'F')),
    CONSTRAINT "DIDS_IS_OPEN_CHK" CHECK (is_open IN (0, 1)),
    CONSTRAINT "DIDS_MONOTONIC_CHK" CHECK (monotonic IN (0, 1)),
    CONSTRAINT "DIDS_HIDDEN_CHK" CHECK (hidden IN (0, 1)),
    CONSTRAINT "DIDS_OBSOLETE_CHK" CHECK (obsolete IN (0, 1)),
    CONSTRAINT "DIDS_COMPLETE_CHK" CHECK (complete IN (0, 1)),
    CONSTRAINT "DIDS_PURGE_REPLICAS_CHK" CHECK (purge_replicas IN (0, 1)),
    CONSTRAINT "DIDS_IS_NEW_CHK" CHECK (is_new IN (0, 1)),
    CONSTRAINT "DIDS_AVAILABILITY_CHK" CHECK (availability IN ('A', 'D', 'L')),
    CONSTRAINT "FILES_SUPP_CHK" CHECK (suppressed IN (0, 1)),
    CONSTRAINT "DIDS_TRANSIENT_CHK" CHECK (transient IN (0, 1)),
    CONSTRAINT "DIDS_ARCHIVE_CHK" CHECK (IS_ARCHIVE IN (0, 1)),
    CONSTRAINT "DIDS_CONSTITUENT_CHK" CHECK (CONSTITUENT IN (0, 1)),
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_FACT_DATA01
PARTITION BY LIST(SCOPE)
SUBPARTITION BY LIST(DID_TYPE)
SUBPARTITION TEMPLATE
    (
    SUBPARTITION C VALUES('C'),
    SUBPARTITION D VALUES('D'),
    SUBPARTITION F VALUES('F')
    )
(
PARTITION INITIAL_PARTITION VALUES ('INITIAL_PARTITION')
);

-- indices
CREATE INDEX DIDS_IS_NEW_IDX ON dids (is_new) COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01 ;
CREATE INDEX DIDS_EXPIRED_AT_IDX ON dids (expired_at) TABLESPACE ATLAS_RUCIO_FACT_DATA01 ;
CREATE UNIQUE INDEX DIDS_GUID_IDX ON DIDS(guid) TABLESPACE ATLAS_RUCIO_FACT_DATA01;
-- commented out as it is not clear whether it is needed
-- CREATE INDEX DIDS_run_number_IDX ON DIDS(run_number, name) LOCAL compress 1;




-- ========================================= REPLICAS =========================================
-- Description: Table to store file replicas
-- Estimated volume: ~ Billions
-- Access pattern:
--                 - by scope, name
--                 - by rse_id for data dumps - to be issued on the ADG
--                 - by tombstone not null


CREATE TABLE replicas (
    scope VARCHAR2(25 CHAR),
    name VARCHAR2(255 CHAR),
    rse_id RAW(16),
    bytes NUMBER(19),
    md5 VARCHAR2(32 CHAR),
    adler32 VARCHAR2(8 CHAR),
    state CHAR(1 CHAR),
    lock_cnt NUMBER(5),
    accessed_at DATE,
    tombstone DATE,
    path VARCHAR2(1024 CHAR),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "REPLICAS_PK" PRIMARY KEY (scope, name, rse_id) USING INDEX LOCAL COMPRESS 1,
    CONSTRAINT "REPLICAS_LFN_FK" FOREIGN KEY(scope, name) REFERENCES dids (scope, name),
    CONSTRAINT "REPLICAS_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
    CONSTRAINT "REPLICAS_STATE_NN" CHECK ("STATE" IS NOT NULL),
    CONSTRAINT "REPLICAS_BYTES_NN" CHECK (bytes IS NOT NULL),
    CONSTRAINT "REPLICAS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "REPLICAS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "REPLICAS_LOCK_CNT_NN" CHECK (lock_cnt IS NOT NULL),
    CONSTRAINT "REPLICAS_STATE_CHK" CHECK (state IN ('A', 'C', 'B', 'U', 'D', 'S'))
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_FACT_DATA01
PARTITION BY LIST (SCOPE)
(
    PARTITION INITIAL_PARTITION VALUES ('Initial_partition')
);

CREATE INDEX REPLICAS_TOMBSTONE_IDX ON replicas (case when TOMBSTONE is not NULL then RSE_ID END, TOMBSTONE) COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01;

CREATE INDEX REPLICAS_LOCK_CNT_IDX ON replicas (case when TOMBSTONE is NULL and lock_cnt=0 then RSE_ID END) COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01;

CREATE INDEX REPLICAS_STATE_IDX ON replicas (case when STATE != 'A' then RSE_ID END) COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01;

CREATE INDEX REPLICAS_PATH_IDX ON replicas (path) TABLESPACE ATLAS_RUCIO_FACT_DATA01;

-- ========================================= REPLICAS_HISTORY =========================================
-- Description: Table to store recent file deletion replicas
-- Estimated volume: 20Hz
-- Access pattern:
--      get everything
--      update rucio
--      delete

CREATE TABLE REPLICAS_HISTORY (
    SCOPE VARCHAR2(25 CHAR),
    NAME VARCHAR2(255 CHAR),
    RSE_ID RAW(16),
    BYTES NUMBER(19),
    UPDATED_AT DATE,
    CREATED_AT DATE,
    CONSTRAINT "REPLICAS_HIST_PK" PRIMARY KEY (SCOPE, NAME, RSE_ID),
    --CONSTRAINT "REPLICAS_HIST_LFN_FK" FOREIGN KEY(SCOPE, NAME) REFERENCES DIDS (SCOPE, NAME),
    CONSTRAINT "REPLICAS_HIST_RSE_ID_FK" FOREIGN KEY(RSE_ID) REFERENCES RSES (ID),
    CONSTRAINT "REPLICAS_HIST_BYTES_NN" CHECK (BYTES IS NOT NULL),
    CONSTRAINT "REPLICAS_HIST_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "REPLICAS_HIST_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;


COMMENT ON TABLE REPLICAS_HISTORY IS 'Recent history of deleted replicas';


-- ========================================= COLLECTION_REPLICAS =========================================
-- Description: Table to store dataset/container replicas
-- Estimated volume: Hundreds of Million
-- Access pattern:
--                 - by scope, name
--                 - by rse_id


CREATE TABLE collection_replicas (
    scope VARCHAR2(25 CHAR),
    name VARCHAR2(255 CHAR),
    did_type CHAR(1 CHAR),
    rse_id RAW(16),
    bytes NUMBER(19),
    length NUMBER(19),
    available_bytes NUMBER(19),
    available_replicas_cnt NUMBER(19),
    state CHAR(1 CHAR),
    accessed_at DATE,
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "COLLECTION_REPLICAS_PK" PRIMARY KEY (scope, name, rse_id),
    CONSTRAINT "COLLECTION_REPLICAS_LFN_FK" FOREIGN KEY(scope, name) REFERENCES dids (scope, name),
    CONSTRAINT "COLLECTION_REPLICAS_TYPE_CHK" CHECK (did_type IN ('C', 'D', 'F')),
    CONSTRAINT "COLLECTION_REPLICAS_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
    CONSTRAINT "COLLECTION_REPLICAS_STATE_NN" CHECK ("STATE" IS NOT NULL),
    CONSTRAINT "COLLECTION_REPLICAS_BYTES_NN" CHECK (bytes IS NOT NULL),
    CONSTRAINT "COLLECTION_REPLICAS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "COLLECTION_REPLICAS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "COLLECTION_REPLICAS_STATE_CHK" CHECK (state IN ('A', 'C', 'B', 'U', 'D', 'S'))
) ORGANIZATION INDEX COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01;

CREATE INDEX COLLECTION_REPLICAS_RSE_ID_IDX ON collection_replicas (rse_id) TABLESPACE ATLAS_RUCIO_FACT_DATA01;


-- ========================================= UPDATED_COLLECTION_REPLICAS =========================================
-- Description: Table to store updates on dataset/container replicas
-- Estimated volume: Small, used as a queue table
-- Access pattern:
--                 - by scope, name, rse_id
--                 - by id


CREATE TABLE updated_col_rep (
    id RAW(16),
    scope VARCHAR2(25 CHAR),
    name VARCHAR2(255 CHAR),
    did_type CHAR(1 CHAR),
    rse_id RAW(16),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "UPDATED_COL_REP_PK" PRIMARY KEY (id),
    CONSTRAINT "UPDATED_COL_REP_TYPE_CHK" CHECK (did_type IN ('C', 'D', 'F')),
    CONSTRAINT "UPDATED_COL_REP_SCOPE_NN" CHECK ("scope" IS NOT NULL),
    CONSTRAINT "UPDATED_COL_REP_NAME_NN" CHECK (name IS NOT NULL),
    CONSTRAINT "UPDATED_COL_REP_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "UPDATED_COL_REP_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) ORGANIZATION INDEX TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;


CREATE INDEX UPDATED_COL_REP_SNR_IDX ON updated_col_rep ("scope", name, rse_id) COMPRESS 1 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;
CREATE INDEX ATLAS_RUCIO.UPDATED_COL_REP_SCOPE_NAME_IDX on ATLAS_RUCIO.UPDATED_COL_REP(scope, name) COMPRESS 2 tablespace ATLAS_RUCIO_TRANSIENT_DATA01;


-- ========================================= RULES ==============================================
-- Description: Table to store rules
-- Estimated volume:  ~25 millions (versus 1 billion)
-- Access pattern: -- By scope, name
--                 -- By rule_id
                   -- By subscription_id


CREATE TABLE rules (
    id RAW(16),
    subscription_id RAW(16),
    account VARCHAR2(25 CHAR),
    scope VARCHAR2(25 CHAR),
    name VARCHAR2(255 CHAR),
    did_type CHAR(1 CHAR),
    state CHAR(1 CHAR),
    rse_expression VARCHAR2(3000 CHAR),
    copies NUMBER(4) DEFAULT 1,
    expires_at DATE,
    weight VARCHAR2(255 CHAR),
    locked NUMBER(1) DEFAULT 0,
    grouping CHAR(1 CHAR),
    error VARCHAR2(255 CHAR),
    updated_at DATE,
    created_at DATE,
    source_replica_expression VARCHAR2(255 CHAR),
    activity VARCHAR2(50 CHAR),
    locks_ok_cnt NUMBER(10) DEFAULT 0,
    locks_replicating_cnt NUMBER(10) DEFAULT 0,
    locks_stuck_cnt NUMBER(10) DEFAULT 0,
    notification CHAR(1 CHAR),
    stuck_at DATE,
    purge_replicas NUMBER(1) DEFAULT 0,
    ignore_availability NUMBER(1) DEFAULT 0,
    ignore_account_limit NUMBER(1) DEFAULT 0,
    comments VARCHAR2(255 CHAR),
    child_rule_id RAW(16),
    priority NUMBER(1),
    eol_at DATE,
    split_container NUMBER(1) DEFAULT 0,
    meta VARCHAR2(4000 CHAR),
    CONSTRAINT "RULES_PK" PRIMARY KEY (id),   -- id, scope, name
    CONSTRAINT "RULES_SCOPE_NAME_FK" FOREIGN KEY(scope, name) REFERENCES dids (scope, name),
    CONSTRAINT "RULES_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
    CONSTRAINT "RULES_SUBS_ID_FK" FOREIGN KEY(subscription_id) REFERENCES subscriptions (id),
    CONSTRAINT "RULES_CHILD_RULE_ID_FK" FOREIGN KEY(child_rule_id) REFERENCES rules(id),
    CONSTRAINT "RULES_STATE_NN" CHECK ("STATE" IS NOT NULL),
    CONSTRAINT "RULES_SCOPE_NN" CHECK ("SCOPE" IS NOT NULL),
    CONSTRAINT "RULES_NAME_NN" CHECK ("NAME" IS NOT NULL),
    CONSTRAINT "RULES_GROUPING_NN" CHECK ("GROUPING" IS NOT NULL),
    CONSTRAINT "RULES_COPIES_NN" CHECK ("COPIES" IS NOT NULL),
    CONSTRAINT "RULES_LOCKED_NN" CHECK ("LOCKED" IS NOT NULL),
    CONSTRAINT "RULES_PURGE_REPLICAS_NN" CHECK ("PURGE_REPLICAS" IS NOT NULL),
    CONSTRAINT "RULES_ACCOUNT_NN" CHECK ("ACCOUNT" IS NOT NULL),
    CONSTRAINT "RULES_LOCKS_OK_CNT_NN" CHECK ("LOCKS_OK_CNT" IS NOT NULL),
    CONSTRAINT "RULES_LOCKS_REPLICATING_CNT_NN" CHECK ("LOCKS_REPLICATING_CNT" IS NOT NULL),
    CONSTRAINT "RULES_LOCKS_STUCK_CNT_NN" CHECK ("LOCKS_STUCK_CNT" IS NOT NULL),
    CONSTRAINT "RULES_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "RULES_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "RULES_DID_TYPE_CHK" CHECK (did_type IN ('C', 'D', 'F')),
    CONSTRAINT "RULES_STATE_CHK" CHECK (state IN ('S', 'R', 'U', 'O', 'W', 'I')),
    CONSTRAINT "RULES_LOCKED_CHK" CHECK (locked IN (0, 1)),
    CONSTRAINT "RULES_PURGE_REPLICAS_CHK" CHECK (purge_replicas IN (0, 1)),
    CONSTRAINT "RULES_IGNORE_AVAILABILITY_CHK" CHECK (ignore_availability IN (0, 1)),
    CONSTRAINT "RULES_IGNORE_ACCOUNT_LIMIT_CHK" CHECK (ignore_account_limit IN (0, 1)),
    CONSTRAINT "RULES_GROUPING_CHK" CHECK (grouping IN ('A', 'D', 'N')),
    CONSTRAINT "RULES_NOTIFICATION_CHK" CHECK (state IN('Y', 'N', 'C')),
    CONSTRAINT "RULES_SPLIT_CONTAINER_CHK" CHECK (split_container IN (0, 1))
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_FACT_DATA01;



CREATE INDEX RULES_SCOPE_NAME_IDX ON rules (scope, name) COMPRESS 2 TABLESPACE ATLAS_RUCIO_FACT_DATA01;
CREATE INDEX RULES_EXPIRES_AT_IDX ON rules (expires_at, name) COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01;
-- function based index for the "S" value of the STATE column
CREATE INDEX RULES_STUCKSTATE_IDX ON rules (CASE when state='S' THEN state ELSE null END) COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01;
CREATE UNIQUE INDEX "RULES_SC_NA_AC_RS_CO_UQ_IDX" ON "RULES" ("SCOPE", "NAME", "ACCOUNT", "RSE_EXPRESSION", "COPIES") COMPRESS 2 TABLESPACE ATLAS_RUCIO_FACT_DATA01;
CREATE INDEX RULES_INJECTSTATE_IDX ON rules (CASE when state='I' THEN state ELSE null END) COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01;
CREATE INDEX RULES_APPROVALSTATE_IDX ON rules (CASE when state='W' THEN state ELSE null END) COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01;
CREATE INDEX RULES_CHILD_RULE_ID_IDX on ATLAS_RUCIO.rules(child_rule_id) tablespace ATLAS_RUCIO_FACT_DATA01;


-- ========================================= LOCKS (List partitioned table) =========================================
-- Description: Table to store locks
-- Estimated volume: 1.7 billion
-- Access pattern: By scope, name
--                 By scope, name, rule_id (By rule_id AND state, rule_id)


CREATE TABLE locks (
    scope VARCHAR2(25 CHAR),
    name VARCHAR2(255 CHAR),
    rule_id RAW(16),
    rse_id RAW(16),
    account VARCHAR2(25 CHAR),
    bytes NUMBER(19),
    state CHAR(1 CHAR),
    repair_cnt NUMBER(19),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "LOCKS_PK" PRIMARY KEY (scope, name, rule_id, rse_id) USING INDEX LOCAL COMPRESS 1,
    -- CONSTRAINT "LOCKS_REPLICAS_FK" FOREIGN KEY(rse_id, scope, name) REFERENCES replicas (rse_id, scope, name),
    CONSTRAINT "LOCKS_RULE_ID_FK" FOREIGN KEY(rule_id) REFERENCES rules (id),
    CONSTRAINT "LOCKS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
    CONSTRAINT "LOCKS_STATE_NN" CHECK ("STATE" IS NOT NULL),
    CONSTRAINT "LOCKS_ACCOUNT_NN" CHECK ("ACCOUNT" IS NOT NULL),
    CONSTRAINT "LOCKS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "LOCKS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "LOCKS_STATE_CHK" CHECK (state IN ('S', 'R', 'O'))
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_FACT_DATA01
PARTITION BY LIST (SCOPE)
(
    PARTITION INITIAL_PARTITION VALUES ('Initial_partition')
);

CREATE INDEX "LOCKS_RULE_ID_IDX" ON locks(rule_id)  COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01 ;





-- ========================================= DATASET_LOCKS =========================================
-- Description: Table to store locks
-- Estimated volume: 1 million (???)
-- Access pattern: By scope, name
--                 By rse_id
--                 By rule_id


CREATE TABLE dataset_locks (
    scope VARCHAR2(25 CHAR),
    name VARCHAR2(255 CHAR),
    rule_id RAW(16),
    rse_id RAW(16),
    account VARCHAR2(25 CHAR),
    state CHAR(1 CHAR),
    updated_at DATE,
    created_at DATE,
    length NUMBER(19),
    bytes NUMBER(19),
    accessed_at DATE,
    CONSTRAINT "DATASET_LOCKS_PK" PRIMARY KEY (scope, name, rule_id, rse_id) USING INDEX COMPRESS 1,
    CONSTRAINT "DATASET_LOCKS_DID_FK" FOREIGN KEY(scope, name) REFERENCES dids (scope, name),
    CONSTRAINT "DATASET_LOCKS_RULE_ID_FK" FOREIGN KEY(rule_id) REFERENCES rules (id),
    CONSTRAINT "DATASET_LOCKS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
    CONSTRAINT "DATASET_LOCKS_STATE_NN" CHECK ("STATE" IS NOT NULL),
    CONSTRAINT "DATASET_LOCKS_ACCOUNT_NN" CHECK ("ACCOUNT" IS NOT NULL),
    CONSTRAINT "DATASET_LOCKS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "DATASET_LOCKS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "DATASET_LOCKS_STATE_CHK" CHECK (state IN ('S', 'R', 'O'))
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_FACT_DATA01;

CREATE INDEX "DATASET_LOCKS_RULE_ID_IDX" ON dataset_locks(rule_id) COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01 ;
CREATE INDEX "DATASET_LOCKS_RSE_ID_IDX" ON dataset_locks(rse_id) COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01 ;




-- ========================================= UPDATED_ACCOUNT_COUNTERS =========================================

CREATE TABLE UPDATED_ACCOUNT_COUNTERS
(
    ID RAW(16) NOT NULL,
    account VARCHAR2(25 CHAR),
    rse_id RAW(16),
    files NUMBER(19),
    bytes NUMBER(19),
    UPDATED_AT DATE,
    CREATED_AT DATE,
    CONSTRAINT "UPDATED_ACCNT_CNTRS_PK" PRIMARY KEY (ID),
    CONSTRAINT "UPDATED_ACCNT_CNTRS_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
    CONSTRAINT "UPDATED_ACCNT_CNTRS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
    CONSTRAINT "UPDATED_ACCNT_CNTRS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "UPDATED_ACCNT_CNTRS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) ORGANIZATION INDEX TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;


CREATE INDEX "UPDATED_ACCNT_CNTRS_RSE_IDX" ON updated_account_counters (account, rse_id) COMPRESS 1 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;


-- ========================================= ACCOUNT_LIMITS (physical structure IOT) =========================================
-- Description: Table to store the limits for an account.
-- Estimated volume: ~2000 accounts * 700 RSE * 1 limits (MaxBytes)
-- Access pattern: by account

CREATE TABLE account_limits (
 account VARCHAR2(25 CHAR),
 rse_id RAW(16),
 bytes NUMBER(19),
 updated_at DATE,
 created_at DATE,
 CONSTRAINT ACCOUNT_LIMITS_PK PRIMARY KEY (account, rse_id),
 CONSTRAINT ACCOUNT_LIMITS_created_nn CHECK (created_at is not null),
 CONSTRAINT ACCOUNT_LIMITS_updated_nn CHECK (updated_at is not null),
 CONSTRAINT ACCOUNT_LIMITS_ACCOUNT_FK FOREIGN KEY(account) REFERENCES accounts (account),
 CONSTRAINT ACCOUNT_LIMITS_RSE_ID_FK FOREIGN KEY(rse_id) REFERENCES rses(id)
) ORGANIZATION INDEX tablespace ATLAS_RUCIO_ATTRIBUTE_DATA01;



-- ========================================= UPDATED_RSE_COUNTERS =========================================

CREATE TABLE UPDATED_RSE_COUNTERS
(
	ID RAW(16) NOT NULL,
        rse_id RAW(16),
        files NUMBER(19),
        bytes NUMBER(19),
	UPDATED_AT DATE,
	CREATED_AT DATE,
	CONSTRAINT "UPDATED_RSE_CNTRS_PK" PRIMARY KEY (ID),
        CONSTRAINT "UPDATED_RSE_CNTRS_RSE_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
	CONSTRAINT "UPDATED_RSE_CNTRS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "UPDATED_RSE_CNTRS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) ORGANIZATION INDEX TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;

CREATE INDEX "UPDATED_RSE_CNTRS_RSE_IDX" ON updated_rse_counters (rse_id) TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;



-- ========================================= RSE_LIMITS (physical structure IOT) =========================================
-- Description: Table to store the limits of a a RSE
-- Estimated volume: ~700 RSEs *  ~2 limits (MinFreeSpace, MaxBeingDeletedFiles)
-- Access pattern: by rse_id, name

CREATE TABLE rse_limits (
    rse_id RAW(16),
    name VARCHAR2(255 CHAR),
    value NUMBER(19),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "RSE_LIMITS_PK" PRIMARY KEY (rse_id, name),
    CONSTRAINT "RSE_LIMIT_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
    CONSTRAINT "RSE_LIMITS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "RSE_LIMITS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) ORGANIZATION INDEX COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01;



-- ========================================= RSE_TRANSFER_LIMITS (physical structure IOT) =========================================
-- Description: Table to store the transfer limits of a RSE
-- Estimated volume: ~700 RSEs *  ~10 activities
-- Access pattern: by rse_id, activity

CREATE TABLE rse_transfer_limits (
  rse_id RAW(16),
  activity VARCHAR2(50 CHAR),
  rse_expression VARCHAR2(3000 CHAR),
  max_transfers NUMBER(19),
  transfers NUMBER(19),
  waitings NUMBER(19),
  updated_at DATE,
  created_at DATE,
  CONSTRAINT "RSE_TRANSFER_LIMITS_PK" PRIMARY KEY (rse_id, activity),
  CONSTRAINT "RSE_TRANSFER_LIMITS_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
  CONSTRAINT "RSE_TRANSFER_LIMITS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
  CONSTRAINT "RSE_TRANSFER_LIMITS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) ORGANIZATION INDEX COMPRESS 1 TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01 ;



-- ========================================= RSE_PROTOCOLS (physical structure IOT) =========================================
-- Description: Table to store the list of protocols per RSE
-- Estimated volume: ~700 RSEs *  ~3 protocols = ~ ~2100
-- Access pattern: by rse_id. by rse_id, scheme


CREATE TABLE rse_protocols (
    rse_id RAW(16),
    scheme VARCHAR2(255 CHAR),
    hostname VARCHAR2(255 CHAR),
    port NUMBER(6),
    prefix VARCHAR2(1024 CHAR),
    impl VARCHAR2(255 CHAR) NOT NULL,
    read_LAN NUMBER(1),
    write_LAN NUMBER(1),
    delete_LAN NUMBER(1),
    read_WAN NUMBER(1),
    write_WAN NUMBER(1),
    delete_WAN NUMBER(1),
    third_party_copy NUMBER(1),
    extended_attributes VARCHAR2(1024 CHAR),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "RSE_PROTOCOLS_PK" PRIMARY KEY (rse_id, scheme, hostname, port),
    CONSTRAINT "RSE_PROTOCOL_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
    CONSTRAINT "RSE_PROTOCOLS_IMPL_NN" CHECK ("IMPL" IS NOT NULL),
    CONSTRAINT "RSE_PROTOCOLS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "RSE_PROTOCOLS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
)  ORGANIZATION INDEX COMPRESS 2 TABLESPACE ATLAS_RUCIO_FACT_DATA01;




-- ============================================== section TRANSIENT data  ==========================================================================
-- to reside in tablespace ATLAS_RUCIO_TRANSIENT_DATA01
-- =================================================================================================================================================


-- ========================================= CONTENTS (list partitioned IOT table) =========================================
-- Description: Table to store did contents
-- Estimated volume: 0.6 Billion
-- Access pattern: by "scope, name", by "child_scope, child_name"


CREATE TABLE contents (
        scope VARCHAR2(25 CHAR),
        name VARCHAR2(255 CHAR),
        child_scope VARCHAR2(25 CHAR),
        child_name VARCHAR2(255 CHAR),
        did_type CHAR(1 CHAR),
        child_type CHAR(1 CHAR),
        length NUMBER(22), -- or children ?
        bytes NUMBER(22),
        adler32 VARCHAR2(8 CHAR),
        md5 VARCHAR2(32 CHAR),
        guid RAW(16),
        events NUMBER(19),
        rule_evaluation NUMBER(1),
        updated_at DATE,
        created_at DATE,
        CONSTRAINT "CONTENTS_PK" PRIMARY KEY (scope, name, child_scope, child_name),
        CONSTRAINT "CONTENTS_ID_FK" FOREIGN KEY(scope, name) REFERENCES dids (scope, name),
        CONSTRAINT "CONTENTS_CHILD_ID_FK" FOREIGN KEY(child_scope, child_name) REFERENCES dids (scope, name),
        CONSTRAINT "CONTENTS_DID_TYPE_NN" CHECK ("DID_TYPE" IS NOT NULL),
        CONSTRAINT "CONTENTS_CHILD_TYPE_NN" CHECK ("CHILD_TYPE" IS NOT NULL),
        CONSTRAINT "CONTENTS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
        CONSTRAINT "CONTENTS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
        CONSTRAINT "CONTENTS_TYPE_CHK" CHECK (did_type IN ('C', 'D', 'F')),
        CONSTRAINT "CONTENTS_CHILD_IS_TYPE_CHK" CHECK (child_type IN ('C', 'D', 'F')),
        CONSTRAINT "CONTENTS_RULE_EVAL_CHK" CHECK (rule_evaluation IN (0, 1))
)
ORGANIZATION INDEX COMPRESS 2 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01
PARTITION BY LIST (SCOPE)
(
    PARTITION INITIAL_PARTITION VALUES ('Initial_partition')
);


-- this index is equivalent to ("CHILD_SCOPE", "CHILD_NAME", "SCOPE", "NAME") as the columns of the PKs are added as logical address
CREATE INDEX CONTENTS_CHILD_SCOPE_NAME_IDX ON CONTENTS (CHILD_SCOPE, CHILD_NAME) COMPRESS 1 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;


-- ========================================= CONTENTS_HISTORY =========================================
-- Description: Table to store the history of contents

CREATE TABLE ATLAS_RUCIO.CONTENTS_HISTORY (
    scope VARCHAR2(25 CHAR) constraint CONTENTS_HIST_SCOPE_NN NOT NULL,
    name VARCHAR2(255 CHAR) constraint CONTENTS_NAME_NN NOT NULL,
    child_scope VARCHAR2(25 CHAR) constraint CONTENTS_HIST_CHILD_SCOPE_NN NOT NULL,
    child_name VARCHAR2(255 CHAR) constraint CONTENTS_HIST_CHILD_NAME_NN NOT NULL,
    did_type CHAR(1 CHAR),
    child_type CHAR(1 CHAR),
    length NUMBER(22),
    bytes NUMBER(22),
    adler32 VARCHAR2(8 CHAR),
    md5 VARCHAR2(32 CHAR),
    guid RAW(16),
    events NUMBER(19),
    rule_evaluation NUMBER(1),
    updated_at DATE,
    created_at DATE,
    deleted_at DATE,
    did_created_at DATE,
    CONSTRAINT "CONTENTS_HIST_DID_TYPE_NN" CHECK ("DID_TYPE" IS NOT NULL),
    CONSTRAINT "CONTENTS_HIST_CHILD_TYPE_NN" CHECK ("CHILD_TYPE" IS NOT NULL),
    CONSTRAINT "CONTENTS_HIST_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "CONTENTS_HIST_DID_CREATED_NN" CHECK ("DID_CREATED_AT" IS NOT NULL),
    CONSTRAINT "CONTENTS_HIST_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
    CONSTRAINT "CONTENTS_HIST_TYPE_CHK" CHECK (did_type IN ('C', 'D', 'F')),
    CONSTRAINT "CONTENTS_HIST_CHILD_ISTYPE_CHK" CHECK (child_type IN ('C', 'D', 'F')),
    CONSTRAINT "CONTENTS_HIST_RULE_EVAL_CHK" CHECK (rule_evaluation IN (0, 1))
) PCTFREE 0 COMPRESS FOR OLTP TABLESPACE ATLAS_RUCIO_HIST_DATA02
PARTITION BY RANGE(did_created_at) INTERVAL ( NUMTOYMINTERVAL(1,'MONTH') )
( PARTITION "DATA_BEFORE_01052015" VALUES LESS THAN (TO_DATE('01-05-2015', 'DD-MM-YYYY')) )
ENABLE ROW MOVEMENT ;

CREATE INDEX ATLAS_RUCIO.CONTENTS_HISTORY_INDX on ATLAS_RUCIO.CONTENTS_HISTORY(scope, name) COMPRESS 2 LOCAL TABLESPACE ATLAS_RUCIO_HIST_DATA02;

-- ========================================= REQUESTS =========================================
-- Description: Table to store transfer requests
-- Estimated volume: 2 millions
-- When you add a new column here, don't forget to add it to requests_history table too
-- Also, add the corresponding variables in core/requests.py archive_request method to correct propagation.s

CREATE TABLE REQUESTS
   ("ID" RAW(16),
    "STATE" CHAR(1 CHAR),
    "REQUEST_TYPE" CHAR(1 CHAR),
    "SCOPE" VARCHAR2(25 CHAR),
    "NAME" VARCHAR2(255 CHAR),
    "DID_TYPE" CHAR(1 CHAR) DEFAULT 'F',
    "DEST_RSE_ID" RAW(16),
    "SOURCE_RSE_ID" RAW(16),
    "EXTERNAL_ID" VARCHAR2(64 CHAR),
    "EXTERNAL_HOST" VARCHAR2(256 CHAR),
    "RETRY_COUNT" NUMBER(3,0) DEFAULT '0',
    "ATTRIBUTES" VARCHAR2(4000 CHAR),
    "ERR_MSG" VARCHAR2(4000 CHAR),
    "PREVIOUS_ATTEMPT_ID" RAW(16),
    "RULE_ID" RAW(16),
    "BYTES" NUMBER(19),
    "MD5" VARCHAR2(32 CHAR),
    "ADLER32" VARCHAR2(8 CHAR),
    "DEST_URL" VARCHAR2(2048 CHAR),
    "ACTIVITY" VARCHAR2(50 CHAR),
    "UPDATED_AT" DATE,
    "CREATED_AT" DATE,
    "SUBMITTED_AT" DATE,
    "STARTED_AT" DATE,
    "TRANSFERRED_AT" DATE,
    "ESTIMATED_AT" DATE,
    "REQUESTED_AT" DATE,
    "ESTIMATED_STARTED_AT" DATE,
    "ESTIMATED_TRANSFERRED_AT" DATE,
    "ACCOUNT" VARCHAR2(25 CHAR),
    "SUBMITTER_ID" NUMBER(10),
    "PRIORITY" NUMBER(1),
     CONSTRAINT "REQUESTS_PK" PRIMARY KEY (ID),
     CONSTRAINT "REQUESTS_RSES_FK" FOREIGN KEY ("DEST_RSE_ID") REFERENCES "RSES" ("ID") ,
     CONSTRAINT "REQUESTS_DID_FK" FOREIGN KEY ("SCOPE", "NAME") REFERENCES "DIDS" ("SCOPE", "NAME"),
     CONSTRAINT "REQUESTS_ACCOUNT_FK" FOREIGN KEY("account") REFERENCES accounts ("account"),
--     CONSTRAINT "REQUESTS_RULE_ID_FK" FOREIGN KEY ("RULE_ID") REFERENCES "RULES" ("ID"),
     CONSTRAINT "REQUESTS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
     CONSTRAINT "REQUESTS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL) ,
     CONSTRAINT "REQUESTS_RSE_ID_NN" CHECK (dest_rse_id IS NOT NULL) ,
     CONSTRAINT "REQUESTS_TYPE_CHK" CHECK (request_type IN ('U', 'D', 'T','I','0')) ,
     CONSTRAINT "REQUESTS_STATE_CHK" CHECK (state IN ('Q', 'G', 'S', 'D', 'F', 'L', 'N', 'O', 'A', 'U', 'W', 'M')),
     CONSTRAINT "REQUESTS_DIDTYPE_CHK" CHECK (did_type IN ('C', 'F', 'D'))
       ) PCTFREE 0 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01 ;

-- commented out because PK is added instead
-- CREATE UNIQUE INDEX "REQUESTS_ID_IDX" ON "REQUESTS" ("ID") TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;

--superseded
--CREATE INDEX "REQUESTS_SCOPE_NAME_RSE_IDX" ON "REQUESTS" ("SCOPE", "NAME", "DEST_RSE_ID") COMPRESS 2 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;
CREATE UNIQUE INDEX "REQUESTS_SC_NA_RS_TY_UQ_IDX" ON "REQUESTS" ("SCOPE", "NAME", "DEST_RSE_ID", "REQUEST_TYPE") COMPRESS 2 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;

CREATE INDEX "REQUESTS_TYP_STA_UPD_IDX_OLD" ON "REQUESTS" ("REQUEST_TYPE", "STATE", "UPDATED_AT") COMPRESS 2 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;
CREATE INDEX "REQUESTS_TYP_STA_UPD_IDX" ON "REQUESTS" ("REQUEST_TYPE", "STATE", "ACTIVITY") COMPRESS 3 tablespace ATLAS_RUCIO_TRANSIENT_DATA01;

CREATE INDEX "REQUESTS_RULEID_IDX" ON "REQUESTS" ("RULE_ID") COMPRESS 1 ONLINE tablespace ATLAS_RUCIO_TRANSIENT_DATA01;

CREATE INDEX "REQUESTS_EXTERNALID_UQ" ON "REQUESTS" ("EXTERNAL_ID") ONLINE tablespace ATLAS_RUCIO_TRANSIENT_DATA01;

ALTER session set DDL_LOCK_TIMEOUT=300;


-- ========================================= SOURCES =========================================
-- Description: Table to store sources for transfers
-- Estimated volume: 2 millions * avg(sources) ~ 1.4
-- Access patterns:
--  by request_id (to get all sources for a transfer)
--  by scope,name, rse_id (to know if a file is used as a source)
--  by rse_id, dest_rse_id (to do some statistics of transfer activity between sites) by request_id

CREATE TABLE ATLAS_RUCIO.SOURCES (
	REQUEST_ID RAW(16) NOT NULL,
	SCOPE VARCHAR2(25 CHAR) NOT NULL,
	NAME VARCHAR2(255 CHAR) NOT NULL,
	RSE_ID RAW(16) NOT NULL,
	DEST_RSE_ID RAW(16) NOT NULL,
	URL VARCHAR2(2048 CHAR),
	bytes NUMBER(19),
	RANKING INTEGER,
        IS_USING NUMBER(1),
	UPDATED_AT DATE,
	CREATED_AT DATE,
	CONSTRAINT "SOURCES_PK" PRIMARY KEY (REQUEST_ID, SCOPE, NAME, RSE_ID) USING INDEX COMPRESS 1,
	CONSTRAINT "SOURCES_REQ_ID_FK" FOREIGN KEY(REQUEST_ID) REFERENCES ATLAS_RUCIO.REQUESTS (ID),
	CONSTRAINT "SOURCES_REPLICAS_FK" FOREIGN KEY(SCOPE, NAME, RSE_ID) REFERENCES ATLAS_RUCIO.REPLICAS (SCOPE, NAME, RSE_ID),
	CONSTRAINT "SOURCES_RSES_FK" FOREIGN KEY(RSE_ID) REFERENCES ATLAS_RUCIO.RSES (ID),
	CONSTRAINT "SOURCES_DEST_RSES_FK" FOREIGN KEY(DEST_RSE_ID) REFERENCES ATLAS_RUCIO.RSES (ID),
	CONSTRAINT "SOURCES_BYTES_NN" CHECK (BYTES IS NOT NULL),
	CONSTRAINT "SOURCES_CREATED_NN" CHECK (CREATED_AT IS NOT NULL),
	CONSTRAINT "SOURCES_UPDATED_NN" CHECK (UPDATED_AT IS NOT NULL)
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;

CREATE INDEX ATLAS_RUCIO."SOURCES_SRC_DST_IDX" ON ATLAS_RUCIO.SOURCES (rse_id, dest_rse_id) COMPRESS 2 ONLINE tablespace ATLAS_RUCIO_TRANSIENT_DATA01;

CREATE INDEX ATLAS_RUCIO."SOURCES_SC_NM_DST_IDX" ON ATLAS_RUCIO.SOURCES (scope, rse_id, name) COMPRESS 2 ONLINE tablespace ATLAS_RUCIO_TRANSIENT_DATA01;

CREATE INDEX ATLAS_RUCIO."SOURCES_DEST_RSEID_IDX" ON ATLAS_RUCIO.SOURCES (dest_rse_id) COMPRESS 1 ONLINE tablespace ATLAS_RUCIO_TRANSIENT_DATA01;


-- ========================================= SOURCES_HISTORY ================================

CREATE TABLE ATLAS_RUCIO.SOURCES_HISTORY (
     REQUEST_ID RAW(16) NOT NULL,
     SCOPE VARCHAR2(25 CHAR) NOT NULL,
     NAME VARCHAR2(255 CHAR) NOT NULL,
     RSE_ID RAW(16) NOT NULL,
     DEST_RSE_ID RAW(16) NOT NULL,
     URL VARCHAR2(2048 CHAR),
     bytes NUMBER(19),
     RANKING NUMBER(7,0),
    IS_USING NUMBER(1),
     UPDATED_AT DATE,
     CREATED_AT DATE
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_HIST_DATA01
     COMPRESS FOR OLTP
PARTITION BY RANGE(CREATED_AT)
INTERVAL ( NUMTODSINTERVAL(1,'DAY') )
(
PARTITION "DATA_BEFORE_01112015" VALUES LESS THAN (TO_DATE('01-11-2015', 'DD-MM-YYYY'))
);

CREATE INDEX "SOURCES_HIST_REQID_IDX" ON "SOURCES_HISTORY" (REQUEST_ID) LOCAL TABLESPACE ATLAS_RUCIO_HIST_DATA01;


-- ========================================= DISTANCE =========================================
-- Description: Table to store distance between rses
-- Estimated volume: 400k
-- Access patterns:
--  by src_rse_id, dest_rse_id (to get distance between rses)
--  by dest_rse_id (to get all source rses distance)

CREATE TABLE ATLAS_RUCIO.DISTANCES (
        SRC_RSE_ID RAW(16) NOT NULL,
        DEST_RSE_ID RAW(16) NOT NULL,
        RANKING INTEGER,
        AGIS_DISTANCE INTEGER,
        GEOIP_DISTANCE INTEGER,
        ACTIVE INTEGER,
        SUBMITTED INTEGER,
        FINISHED INTEGER,
        FAILED INTEGER,
        TRANSFER_SPEED INTEGER,
        PACKET_LOSS = INTEGER,
        LATENCY = INTEGER,
        MBPS_FILE = INTEGER,
        MBPS_LINK = INTEGER,
        QUEUED_TOTAL = INTEGER,
        DONE_1H = INTEGER,
        DONE_6H = INTEGER,
        UPDATED_AT DATE,
        CREATED_AT DATE,
        CONSTRAINT "DISTANCES_PK" PRIMARY KEY (SRC_RSE_ID, DEST_RSE_ID) USING INDEX COMPRESS 1,
        CONSTRAINT "DISTANCES_SRC_RSES_FK" FOREIGN KEY(SRC_RSE_ID) REFERENCES ATLAS_RUCIO.RSES (ID),
        CONSTRAINT "DISTANCES_DEST_RSES_FK" FOREIGN KEY(DEST_RSE_ID) REFERENCES ATLAS_RUCIO.RSES (ID),
        CONSTRAINT "DISTANCES_CREATED_NN" CHECK (CREATED_AT IS NOT NULL),
        CONSTRAINT "DISTANCES_UPDATED_NN" CHECK (UPDATED_AT IS NOT NULL)
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;

CREATE INDEX ATLAS_RUCIO."DISTANCES_DEST_RSEID_IDX" ON ATLAS_RUCIO.DISTANCES (dest_rse_id) COMPRESS 1 ONLINE tablespace ATLAS_RUCIO_TRANSIENT_DATA01;


-- ========================================= MESSAGES =========================================
-- Previously called: CALLBACKS
-- Description: Table to store messages before sending them to a broker
-- Estimated volume: 20,000 rows per 10. min.
-- Access pattern: list the last messages by created date for the last n minutes
-- this table could be of IOT type but then an overflow segment would need to be defined because of the column definition lengths, the row
-- length can go over 4K
-- Is it really necessary EVENT_TYPE to be with max size of 1024?

CREATE TABLE messages (
    id RAW(16),
    updated_at TIMESTAMP(6),
    created_at TIMESTAMP(6),
    event_type VARCHAR2(1024 CHAR),
    payload VARCHAR2(4000 CHAR),
    CONSTRAINT "MESSAGES_PK" PRIMARY KEY (id),
    CONSTRAINT "MESSAGES_EVENT_TYPE_NN" CHECK ("EVENT_TYPE" IS NOT NULL),
    CONSTRAINT "MESSAGES_PAYLOAD_NN" CHECK ("PAYLOAD" IS NOT NULL),
    CONSTRAINT "MESSAGES_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "MESSAGES_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
)  PCTFREE 0 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;




-- ========================================= TOKENS (physical structure IOT) =========================================
-- Description: Table to store auth tokens
-- Estimated volume: ~100,000
-- Access pattern: by token (frequently). Cleanup of expired token done by account (rarely)
--           DELETE FROM atlas_rucio.tokens WHERE atlas_rucio.tokens.expired_at < :expired_at_1 AND atlas_rucio.tokens.account = :account_1
--           SELECT atlas_rucio.tokens.account AS atlas_rucio_tokens_account, atlas_rucio.tokens.expired_at AS atlas_rucio_tokens_expired_at
--           FROM atlas_rucio.tokens
--           WHERE atlas_rucio.tokens.token = :token_1 AND atlas_rucio.tokens.expired_at > :expired_at_1

CREATE TABLE tokens (
    account VARCHAR2(25 CHAR),
    expired_at DATE,
    token VARCHAR2(352 CHAR),
    identity VARCHAR2(2048 CHAR),
    ip VARCHAR2(39 CHAR),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "TOKENS_PK" PRIMARY KEY (token),
    CONSTRAINT "TOKENS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
    CONSTRAINT "TOKENS_EXPIRED_AT_NN" CHECK ("EXPIRED_AT" IS NOT NULL),
    CONSTRAINT "TOKENS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "TOKENS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
)  TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;

CREATE INDEX "TOKENS_ACCOUNT_EXPIRED_AT_IDX" ON "TOKENS"(ACCOUNT, expired_at) COMPRESS 1 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01 ;


-- ========================================= ACCOUNT_USAGE (physical structure IOT) =========================================
-- Description: Table to store incrementally the disk usage by account, rse
-- Estimated volume: ~700 RSEs *  ~2000 accounts
-- Access pattern: by account, by account/rse_id


CREATE TABLE account_usage (
    account VARCHAR2(25 CHAR),
    rse_id RAW(16),
    files NUMBER(19),
    bytes NUMBER(19),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "ACCOUNT_USAGE_PK" PRIMARY KEY (account, rse_id),
    CONSTRAINT "ACCOUNT_USAGE_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
    CONSTRAINT "ACCOUNT_USAGE_RSES_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
    CONSTRAINT "ACCOUNT_USAGE_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "ACCOUNT_USAGE_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) ORGANIZATION INDEX COMPRESS 1 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01 ;



-- ========================================= RSE_USAGE (physical structure IOT) =========================================
-- Description: Table to store the disk usage of a RSE
-- Estimated volume: ~700 RSEs *  ~2 measures (rucio, srm): ~1.400
-- Access pattern: by rse_id, source

CREATE TABLE rse_usage (
    rse_id RAW(16),
    source VARCHAR2(255 CHAR),
    used NUMBER(19),
    free NUMBER(19),
    files NUMBER(19),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "RSE_USAGE_PK" PRIMARY KEY (rse_id, source),
    CONSTRAINT "RSE_USAGE_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
    CONSTRAINT "RSE_USAGE_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
    CONSTRAINT "RSE_USAGE_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) ORGANIZATION INDEX COMPRESS 1 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01 ;





-- ========================================= UPDATED_DIDS =========================================

CREATE TABLE UPDATED_DIDS
(
	ID RAW(16) NOT NULL,
	SCOPE VARCHAR2(25 CHAR),
	NAME VARCHAR2(255 CHAR),
	RULE_EVALUATION_ACTION VARCHAR2(1 CHAR),
	UPDATED_AT DATE,
	CREATED_AT DATE,
	CONSTRAINT UPDATED_DIDS_PK PRIMARY KEY (ID),
	CONSTRAINT UPDATED_DIDS_SCOPE_NN CHECK ("SCOPE" IS NOT NULL),
	CONSTRAINT UPDATED_DIDS_NAME_NN CHECK ("NAME" IS NOT NULL),
	CONSTRAINT UPDATED_DIDS_CREATED_NN CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT UPDATED_DIDS_UPDATED_NN CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT UPDATED_DIDS_RULE_EVAL_ACT_CHK CHECK (rule_evaluation_action IN ('A', 'B', 'D'))
) ORGANIZATION INDEX TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;

CREATE INDEX "UPDATED_DIDS_SCOPERULENAME_IDX" ON "UPDATED_DIDS"(SCOPE, RULE_EVALUATION_ACTION, NAME) COMPRESS 2 TABLESPACE  ATLAS_RUCIO_TRANSIENT_DATA01;




-- ============================================== section HISTORICAL data =========================================================================
-- to reside in tablespace ATLAS_RUCIO_HIST_DATA01
-- =================================================================================================================================================


-- ========================================= DELETED_DIDS =========================================

CREATE TABLE DELETED_DIDS
   ("SCOPE" VARCHAR2(25 CHAR) NOT NULL ENABLE,
    "NAME" VARCHAR2(255 CHAR) NOT NULL ENABLE,
    "ACCOUNT" VARCHAR2(25 CHAR),
    "DID_TYPE" CHAR(1 CHAR) NOT NULL ENABLE,
    "IS_OPEN" NUMBER(1,0),
    "MONOTONIC" NUMBER(1,0) DEFAULT 0,
    "HIDDEN" NUMBER(1,0) DEFAULT 0,
    "OBSOLETE" NUMBER(1,0) DEFAULT 0,
    "COMPLETE" NUMBER(1,0),
    "IS_NEW" NUMBER(1,0) DEFAULT 1,
    "AVAILABILITY" CHAR(1 CHAR),
    "SUPPRESSED" NUMBER(1,0) DEFAULT 0,
    "BYTES" NUMBER(19,0),
    "LENGTH" NUMBER(19,0),
    "MD5" VARCHAR2(32 CHAR),
    "ADLER32" VARCHAR2(8 CHAR),
    "RULE_EVALUATION_REQUIRED" DATE,
    "RULE_EVALUATION_ACTION" CHAR(1 CHAR),
    "EXPIRED_AT" DATE,
    "DELETED_AT" DATE,
    "UPDATED_AT" DATE,
    "CREATED_AT" DATE,
    "EVENTS" NUMBER(22,0),
    "GUID" RAW(16),
    "PROJECT" VARCHAR2(50 CHAR),
    "DATATYPE" VARCHAR2(50 CHAR),
    "RUN_NUMBER" NUMBER(10,0),
    "STREAM_NAME" VARCHAR2(70 CHAR),
    "PROD_STEP" VARCHAR2(50 CHAR),
    "VERSION" VARCHAR2(50 CHAR),
    task_id NUMBER(11),
    panda_id NUMBER(11),
    purge_replicas NUMBER(1),
    "CAMPAIGN" VARCHAR2(50 CHAR),
    lumiblocknr NUMBER(10,0),
    provenance VARCHAR2(2 CHAR),
    phys_group VARCHAR2(25 CHAR),
    transient NUMBER(1,0),
    accessed_at DATE,
    closed_at DATE,
    eol_at DATE,
    is_archive NUMBER(1),
    constituent  NUMBER(1),
    access_cnt NUMBER(11),
    CONSTRAINT "DELETED_DIDS_PK" PRIMARY KEY ("SCOPE", "NAME") USING INDEX LOCAL COMPRESS 1
   ) PCTFREE 0 TABLESPACE ATLAS_RUCIO_HIST_DATA01
	 COMPRESS FOR OLTP
  PARTITION BY LIST ("SCOPE")
 (
    PARTITION "INITIAL_PARTITION"  VALUES ('INITIAL_PARTITION')
 );


-- ========================================= REQUESTS_HISTORY (range partitioned, data sliding window of 180 days) =========================================

-- Description: History table for requests, range partitioned by CREATED_AT + automatic interval partitioning and OLTP compression
-- Expected growth rate is about 3 million rows per day (and the idea is to move stuff that's older than a few months off to hadoop afterwards)
-- Typical queries on "scope, name, dest_rse_id", "state', "external_id", "id', "id, previous_attempt_id"
-- added NOT NULL constraint on the column on which we partition and on the SCOPE
-- The columns are re-ordered so that the ones that are not indexed are in the beginning of the row - this helps when filtering on them on full partition scan

CREATE TABLE requests_history
  (
    "CREATED_AT" DATE CONSTRAINT CREATED_AT_NN NOT NULL,
    "UPDATED_AT" DATE,
    "STATE" CHAR(1 CHAR),
    "REQUEST_TYPE" CHAR(1 CHAR),
    "IS_TYPE" CHAR(1 CHAR),
    "EXTERNAL_ID" VARCHAR2(64 CHAR),
    "EXTERNAL_HOST" VARCHAR2(256 CHAR),
    "SCOPE" VARCHAR2(25 CHAR) CONSTRAINT SCOPE_NN NOT NULL,
    "NAME" VARCHAR2(255 CHAR),
    "DEST_RSE_ID" RAW(16),
    "SOURCE_RSE_ID" RAW(16),
    "ID" RAW(16),
    "PREVIOUS_ATTEMPT_ID" RAW(16),
    "RETRY_COUNT" NUMBER(3,0),
    "ATTRIBUTES" VARCHAR2(4000 CHAR),
    "ERR_MSG" VARCHAR2(4000 CHAR),
    "RULE_ID" RAW(16),
    "BYTES" NUMBER(19),
    "ACTIVITY" VARCHAR2(50 CHAR),
    "MD5" VARCHAR2(32 CHAR),
    "ADLER32" VARCHAR2(8 CHAR),
    "DEST_URL" VARCHAR2(2048 CHAR),
    "ESTIMATED_AT" DATE,
    "REQUESTED_AT" DATE,
    "SUBMITTED_AT" DATE,
    "STARTED_AT" DATE,
    "ESTIMATED_STARTED_AT" DATE,
    "TRANSFERRED_AT" DATE,
    "ESTIMATED_TRANSFERRED_AT" DATE,
    "ACCOUNT" VARCHAR2(25 CHAR),
    "SUBMITTER_ID" NUMBER(10),
    "PRIORITY" NUMBER(1)
  ) PCTFREE 0 TABLESPACE ATLAS_RUCIO_HIST_DATA01
	COMPRESS FOR OLTP
PARTITION BY RANGE(CREATED_AT)
INTERVAL ( NUMTODSINTERVAL(1,'DAY') )
(
PARTITION "DATA_BEFORE_01102013" VALUES LESS THAN (TO_DATE('01-10-2013', 'DD-MM-YYYY'))
);

CREATE INDEX "REQ_HIST_ID_IDX" ON "REQUESTS_HISTORY" (ID) LOCAL TABLESPACE ATLAS_RUCIO_HIST_DATA01;
CREATE INDEX "REQ_HIST_EXTID_IDX" ON "REQUESTS_HISTORY" (EXTERNAL_ID) COMPRESS 1 LOCAL TABLESPACE ATLAS_RUCIO_HIST_DATA01;
CREATE INDEX "REQ_HIST_SCOPE_NAME_RSE_IDX" ON "REQUESTS_HISTORY" ("SCOPE", "NAME", "DEST_RSE_ID") COMPRESS 1 LOCAL TABLESPACE ATLAS_RUCIO_HIST_DATA01;


-- ========================================= SUBSCRIPTIONS_HISTORY (range automatic partitioning with certain interval) =========================================

-- Description: Table to store the history of subscriptions
-- to partition on UPDATED_AT column or on CREATED_AT column

CREATE TABLE subscriptions_history (
    id RAW(16),
    name VARCHAR2(64 CHAR),
    filter VARCHAR2(2048 CHAR),
    replication_rules VARCHAR2(1024 CHAR),
    policyid NUMBER(2),
    state CHAR(1 CHAR),
    last_processed DATE,
    account VARCHAR2(25 CHAR),
    lifetime DATE,
    retroactive NUMBER(1),
    expired_at DATE,
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "SUBSCRIPTIONS_HISTORY_PK" PRIMARY KEY (id, updated_at) USING INDEX LOCAL ,
    CHECK (state IN ('I', 'A', 'B', 'U', 'N')),
    CONSTRAINT "SUBS_HISTORY_RETROACTIVE_CHK" CHECK (retroactive IN (0, 1))
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_HIST_DATA01
	COMPRESS FOR OLTP
 PARTITION BY RANGE (updated_at) INTERVAL (NUMTOYMINTERVAL(1,'MONTH'))
(
PARTITION "DATA_BEFORE_01092013" VALUES LESS THAN (TO_DATE('01-09-2013', 'DD-MM-YYYY'))
);


-- ========================================= RSE_USAGE_HISTORY (List partitioned IOT table?  ) =========================================
-- Description: Table to store the usage history per RSE (time series)
-- Estimated volume: ~700 RSEs * with two records per 30 min. (e.g. rucio/srm)
-- Access pattern: By rse_id, source

-- QUESTION: Is partitioning necessary here? It might be better to offload the data dictionary and NOT partition this table

CREATE TABLE rse_usage_history (
    rse_id RAW(16),
    source VARCHAR2(255 CHAR),
    used NUMBER(19),
    free NUMBER(19),
    files NUMBER(19),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "RSE_USAGE_HISTORY_PK" PRIMARY KEY (rse_id, source, updated_at)
) ORGANIZATION INDEX COMPRESS 2 TABLESPACE ATLAS_RUCIO_HIST_DATA01  ;

-- PARTITION BY LIST (RSE_ID) ( PARTITION INITIAL_PARTITION VALUES ('00000000000000000000000000000000') );




-- ========================================= ACCOUNT_USAGE_HISTORY (List partitioned IOT table ?) =========================================
-- Description: Table to store the usage history per account, RSE
-- Estimated volume: ~700 RSEs * 2000 accounts: one record every 30 min.
-- Access pattern: By account, by "account/rse_id"

-- QUESTION: Is partitioning necessary here? It might be better to offload the data dictionary and NOT partition this table


CREATE TABLE account_usage_history (
    account VARCHAR2(25 CHAR),
    rse_id RAW(16),
    files NUMBER(19),
    bytes NUMBER(19),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "ACCOUNT_USAGE_HISTORY_PK" PRIMARY KEY (account, rse_id, updated_at)
) ORGANIZATION INDEX COMPRESS 1 TABLESPACE ATLAS_RUCIO_HIST_DATA01 ;


-- PARTITION BY LIST (account) ( PARTITION INITIAL_PARTITION VALUES ('INITIAL_PARTITION') );



-- ========================================= LOGGING_TABPARTITIONS =========================================
-- Description: table in which logging information of the partition creation activity is stored

CREATE TABLE LOGGING_TABPARTITIONS
(   TABLE_NAME VARCHAR2(30) CONSTRAINT TABPART_TABLE_NN NOT NULL,
    PARTITION_NAME VARCHAR2(30) CONSTRAINT TABPART_PART_NN NOT NULL,
    PARTITION_VALUE VARCHAR2(30) CONSTRAINT TABPART_VALUE_NN NOT NULL,
    ACTION_TYPE VARCHAR2(10),
    ACTION_DATE TIMESTAMP(0),
    PART_MARKED_FOR_REMOVAL CHAR(1) CONSTRAINT PART_MARKED_FOR_REMOVAL_YN_CHK CHECK (PART_MARKED_FOR_REMOVAL in ( 'Y', 'N' )),
    MARKED_FOR_REMOVAL_ON DATE,
    REMOVED_ON DATE,
    EXECUTED_SQL_STMT VARCHAR2(1000),
    MESSAGE VARCHAR2(1000)
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_HIST_DATA01;




-- ========================================= CONFIGS =========================================
-- Description: Table to store the shared configuration of Rucio
-- Estimated volume: ~100 key-value pairs
-- Access pattern: List by section (rarely), List by option (rarely), List by Section+Option (often), Insert (rarely)

CREATE TABLE configs (
  section VARCHAR2(128 CHAR),
  opt VARCHAR2(128 CHAR),
  value VARCHAR2(4000 CHAR),
  updated_at DATE,
  created_at DATE,
  CONSTRAINT configs_pk PRIMARY KEY (section, opt),
  CONSTRAINT configs_created_nn CHECK (created_at is not null),
  CONSTRAINT configs_updated_nn CHECK (updated_at is not null)
) PCTFREE 0 tablespace   ATLAS_RUCIO_ATTRIBUTE_DATA01;


-- ========================================= CONFIGS_HISTORY =========================================
-- Description: Table to store the history of modifications to the shared configuration of Rucio
-- Estimated volume: ~1000
-- Access pattern: Insert (rarely), Select (rarely)

CREATE TABLE configs_history (
  section VARCHAR2(128 CHAR),
  opt VARCHAR2(128 CHAR),
  value VARCHAR2(4000 CHAR),
  updated_at DATE,
  created_at DATE,
  CONSTRAINT configs_history_pk PRIMARY KEY (section, opt, updated_at) USING INDEX COMPRESS 1
) PCTFREE 0 COMPRESS FOR OLTP tablespace ATLAS_RUCIO_HIST_DATA01;


-- ========================================= RULES_HIST_RECENT ==============================================
-- Description: Table of recent rule changes
-- Estimated volume:  ~10mio
-- Access pattern: -- By rule_id
-- Range partitioned on "updated_at" with interval of 7 days. Locally partitioned index on ID column.


CREATE TABLE rules_hist_recent (
    history_id RAW(16),
    id RAW(16),
    subscription_id RAW(16),
    account VARCHAR2(25 CHAR),
    scope VARCHAR2(25 CHAR),
    name VARCHAR2(255 CHAR),
    did_type CHAR(1 CHAR),
    state CHAR(1 CHAR),
    rse_expression VARCHAR2(3000 CHAR),
    copies NUMBER(4) DEFAULT 1,
    expires_at DATE,
    weight VARCHAR2(255 CHAR),
    locked NUMBER(1) DEFAULT 0,
    grouping CHAR(1 CHAR),
    error VARCHAR2(255 CHAR),
    updated_at DATE,
    created_at DATE,
    source_replica_expression VARCHAR2(255 CHAR),
    activity VARCHAR2(50 CHAR),
    locks_ok_cnt NUMBER(10) DEFAULT 0,
    locks_replicating_cnt NUMBER(10) DEFAULT 0,
    locks_stuck_cnt NUMBER(10) DEFAULT 0,
    notification CHAR(1 CHAR),
    stuck_at DATE,
    purge_replicas NUMBER(1) DEFAULT 0,
    ignore_availability NUMBER(1) DEFAULT 0,
    ignore_account_limit NUMBER(1) DEFAULT 0,
    comments VARCHAR2(255 CHAR),
    child_rule_id RAW(16),
    priority NUMBER(1)
    eol_at DATE,
    split_container NUMBER(1) DEFAULT 0,
    meta VARCHAR2(4000 CHAR),
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_HIST_DATA01
PARTITION BY RANGE(updated_at)
INTERVAL ( NUMTODSINTERVAL(7,'DAY') )
(
PARTITION DATA_BEFORE_01012015 VALUES LESS THAN (TO_DATE('01-01-2015', 'DD-MM-YYYY'))
) ENABLE ROW MOVEMENT ;


CREATE INDEX ATLAS_RUCIO.RULES_HIST_RECENT_ID_IDX ON ATLAS_RUCIO.rules_hist_recent(id) LOCAL COMPRESS 1 TABLESPACE ATLAS_RUCIO_HIST_DATA01;
CREATE INDEX ATLAS_RUCIO.RULES_HIST_RECENT_SC_NA_IDX ON ATLAS_RUCIO.rules_hist_recent(scope, name) LOCAL COMPRESS 1 TABLESPACE ATLAS_RUCIO_HIST_DATA01;


COMMENT ON TABLE ATLAS_RUCIO.rules_hist_recent IS 'Recent history table (1 month) for rules';
COMMENT ON COLUMN ATLAS_RUCIO.rules_hist_recent.history_id IS 'Fake id necessary for sqlalchemy';


-- ========================================= RULES_HISTORY ==============================================
-- Description: Table of longterm rules (deleted)
-- Estimated volume:  ?
-- Access pattern: -- Usually by scope, name - but very rare so full table scan is fine
-- Range partitioned on "updated_at" with interval of a month. OLTP compression on the data blocks.


CREATE TABLE rules_history (
    history_id RAW(16),
    id RAW(16),
    subscription_id RAW(16),
    account VARCHAR2(25 CHAR),
    scope VARCHAR2(25 CHAR),
    name VARCHAR2(255 CHAR),
    did_type CHAR(1 CHAR),
    state CHAR(1 CHAR),
    rse_expression VARCHAR2(3000 CHAR),
    copies NUMBER(4) DEFAULT 1,
    expires_at DATE,
    weight VARCHAR2(255 CHAR),
    locked NUMBER(1) DEFAULT 0,
    grouping CHAR(1 CHAR),
    error VARCHAR2(255 CHAR),
    updated_at DATE,
    created_at DATE,
    source_replica_expression VARCHAR2(255 CHAR),
    activity VARCHAR2(50 CHAR),
    locks_ok_cnt NUMBER(10) DEFAULT 0,
    locks_replicating_cnt NUMBER(10) DEFAULT 0,
    locks_stuck_cnt NUMBER(10) DEFAULT 0,
    notification CHAR(1 CHAR),
    stuck_at DATE,
    purge_replicas NUMBER(1) DEFAULT 0,
    ignore_availability NUMBER(1) DEFAULT 0,
    ignore_account_limit NUMBER(1) DEFAULT 0,
    comments VARCHAR2(255 CHAR),
    child_rule_id RAW(16),
    priority NUMBER(1)
    eol_at DATE,
    split_container NUMBER(1) DEFAULT 0,
    meta VARCHAR2(4000 CHAR),
) PCTFREE 0 COMPRESS FOR OLTP TABLESPACE ATLAS_RUCIO_HIST_DATA01
PARTITION BY RANGE(updated_at)
INTERVAL ( NUMTOYMINTERVAL(1,'MONTH') )
( PARTITION "DATA_BEFORE_01012015" VALUES LESS THAN (TO_DATE('01-01-2015', 'DD-MM-YYYY')) )
 ENABLE ROW MOVEMENT ;

CREATE INDEX ATLAS_RUCIO.RULES_HISTORY_SCOPENAME_IDX ON ATLAS_RUCIO.RULES_HISTORY(scope,name) LOCAL COMPRESS 2 TABLESPACE ATLAS_RUCIO_HIST_DATA01;

COMMENT ON TABLE ATLAS_RUCIO.rules_history IS 'Full history table for rules';
COMMENT ON COLUMN ATLAS_RUCIO.rules_history.history_id IS 'Fake id necessary for sqlalchemy';


-- ========================================= BAD_REPLICAS ==============================================
-- Description: Table that stores the bad files
-- Estimated volume:  A few millions per year
-- Access pattern: -- By state, rse_id


CREATE TABLE BAD_REPLICAS(
   SCOPE VARCHAR2(25),
   NAME VARCHAR2(255),
   RSE_ID RAW(16),
   REASON VARCHAR2(255),
   STATE CHAR(1),
   ACCOUNT VARCHAR2(25),
   BYTES NUMBER(19),
   UPDATED_AT DATE,
   CREATED_AT DATE,
   CONSTRAINT BAD_REPLICAS_PK PRIMARY KEY (SCOPE, NAME, RSE_ID, CREATED_AT) USING INDEX LOCAL COMPRESS 2,
   CONSTRAINT BAD_REPLICAS_ACCOUNT_FK FOREIGN KEY(ACCOUNT) REFERENCES ACCOUNTS (ACCOUNT),
   CONSTRAINT BAD_REPLICAS_SCOPE_NN CHECK (SCOPE IS NOT NULL),
   CONSTRAINT BAD_REPLICAS_NAME_NN CHECK (NAME IS NOT NULL),
   CONSTRAINT BAD_REPLICAS_RSE_ID_NN CHECK (RSE_ID IS NOT NULL),
   CONSTRAINT BAD_REPLICAS_CREATED_NN CHECK (CREATED_AT IS NOT NULL),
   CONSTRAINT BAD_REPLICAS_UPDATED_AT CHECK (UPDATED_AT IS NOT NULL),
   CONSTRAINT BAD_REPLICAS_STATE_CHK CHECK (STATE IN ('R', 'L', 'S', 'B', 'D'))
)
PCTFREE 0 COMPRESS FOR OLTP TABLESPACE ATLAS_RUCIO_HIST_DATA01
PARTITION BY RANGE(CREATED_AT)
INTERVAL (NUMTOYMINTERVAL(1,'MONTH'))
(
PARTITION "DATA_BEFORE_02192015" VALUES LESS THAN (TO_DATE('19-02-2015', 'DD-MM-YYYY'))
) ENABLE ROW MOVEMENT ;


CREATE INDEX BAD_REPLICAS_STATE_IDX ON BAD_REPLICAS(RSE_ID, STATE) COMPRESS 1 TABLESPACE ATLAS_RUCIO_HIST_DATA01;

CREATE INDEX BAD_REPLICAS_ACCOUNT_IDX ON BAD_REPLICAS(ACCOUNT) COMPRESS 1 TABLESPACE ATLAS_RUCIO_HIST_DATA01;

COMMENT ON TABLE BAD_REPLICAS IS 'FULL HISTORY FOR BAD REPLICAS';


-- ========================================= HEARTBEATS =========================================
-- Description: Table to store the status and heartbeat of the running daemons and services
-- Estimated volume: ~1000
-- Access pattern: Insert/Select/Delete (frequent periodic)


CREATE TABLE HEARTBEATS (
EXECUTABLE VARCHAR2(256) NOT NULL,       -- hash of READABLE column
READABLE VARCHAR2(4000) NOT NULL,
HOSTNAME VARCHAR2(128) NOT NULL,
PID NUMBER(10) NOT NULL,
THREAD_ID NUMBER(16) NOT NULL,
THREAD_NAME VARCHAR2(64) NOT NULL,
UPDATED_AT DATE,
CREATED_AT DATE,
CONSTRAINT HEARTBEATS_PK PRIMARY KEY(EXECUTABLE, HOSTNAME, PID, THREAD_ID) using index COMPRESS 1
) PCTFREE 0 TABLESPACE  ATLAS_RUCIO_TRANSIENT_DATA01;


-- ========================================= NAMING_CONVENTIONS =========================================
-- Description: Table to regexp to valide name within scopes
-- Estimated volume: Same order of magnitude than scopes ~5000
-- Access pattern: By scope

CREATE TABLE atlas_rucio.naming_conventions (
   scope VARCHAR2(25 CHAR) NOT NULL,
   regexp VARCHAR2(255 CHAR),
   convention_type VARCHAR(10 CHAR),
   updated_at DATE,
   created_at DATE,
   CONSTRAINT "NAMING_CONVENTIONS_PK" PRIMARY KEY (scope),
   CONSTRAINT "NAMING_CONVENTIONS_SCOPE_FK" FOREIGN KEY(scope) REFERENCES atlas_rucio.scopes (scope),
   CONSTRAINT "NAMING_CONVENTIONS_CREATED_NN" CHECK (CREATED_AT IS NOT NULL),
   CONSTRAINT "NAMING_CONVENTIONS_UPDATED_NN" CHECK (UPDATED_AT IS NOT NULL),
   CONSTRAINT "CVT_TYPE_CHK" CHECK (convention_type IN ('ALL', 'DATASET', 'CONTAINER', 'COLLECTION', 'FILE'))
) ORGANIZATION INDEX TABLESPACE ATLAS_RUCIO_ATTRIBUTE_DATA01;



-- ============================= MESSAGES_HISTORY =========================================
-- Description: Table to store history of messages sent to broker
-- Estimated volume: 20,000 rows per 10. min.
-- Access pattern: high throughput write, rare reads with search by created_at & event_type (low cardinality)

CREATE TABLE messages_history (
    id RAW(16),
    updated_at TIMESTAMP(6),
    created_at TIMESTAMP(6),
    event_type VARCHAR2(1024 CHAR),
    payload VARCHAR2(4000 CHAR),
)  PCTFREE 0 COMPRESS FOR OLTP TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01
PARTITION BY RANGE(CREATED_AT)
INTERVAL ( NUMTODSINTERVAL(1,'DAY') )
(
PARTITION "DATA_BEFORE_01062015" VALUES LESS THAN (TO_DATE('01-06-2015', 'DD-MM-YYYY'))
);


-- ============================= QUARANTINED_REPLICAS =========================================
-- Description: Table to store quarantined replicas
-- Estimated volume: dark data
-- Access pattern: by rse_id

CREATE TABLE QUARANTINED_REPLICAS (
   rse_id RAW(16) NOT NULL,
   path VARCHAR2(1024 CHAR) NOT NULL,
   md5 VARCHAR2(32 CHAR),
   adler32 VARCHAR2(8 CHAR),
   bytes NUMBER(19),
   updated_at DATE,
   created_at DATE,
   CONSTRAINT "QUARANTINED_REPLICAS_PK" PRIMARY KEY (rse_id, path),
   CONSTRAINT "QURD_REPLICAS_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES atlas_rucio.rses (id),
   CONSTRAINT "QURD_REPLICAS_CREATED_NN" CHECK (CREATED_AT IS NOT NULL),
   CONSTRAINT "QURD_REPLICAS_UPDATED_NN" CHECK (UPDATED_AT IS NOT NULL)
) ORGANIZATION INDEX COMPRESS 1 TABLESPACE ATLAS_RUCIO_FACT_DATA01;


COMMENT ON TABLE QUARANTINED_REPLICAS IS 'Table to store the list of inconsistent files at site not known to Rucio and delete ten from the sites.' ;
CREATE UNIQUE INDEX QUARANTINED_REPLICAS_PATH_IDX on QUARANTINED_REPLICAS(PATH,RSE_ID) tablespace ATLAS_RUCIO_FACT_DATA01;


-- ============================= QUARANTINED_REPLICAS_HISTORY =========================================
-- Description: Table to store quarantined replicas
-- Estimated volume: dark data
-- Access pattern: by rse_id

CREATE TABLE QUARANTINED_REPLICAS_HISTORY (
   rse_id RAW(16) NOT NULL,
   path VARCHAR2(1024 CHAR) NOT NULL,
   md5 VARCHAR2(32 CHAR),
   adler32 VARCHAR2(8 CHAR),
   bytes NUMBER(19),
   updated_at DATE,
   created_at DATE,
   deleted_at DATE
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_HIST_DATA01
PARTITION BY RANGE(created_at)
INTERVAL ( NUMTOYMINTERVAL(3,'MONTH') )
( PARTITION "DATA_BEFORE_01032016" VALUES LESS THAN (TO_DATE('01-03-2016', 'DD-MM-YYYY')) );


COMMENT ON TABLE QUARANTINED_REPLICAS_HISTORY IS 'Table of historical QUARANTINED_REPLICAS values of what dark data have been deleted from the sites.' ;

-- ============================= TMP_DIDS_HISTORY =========================================
-- Description: Table to store temporary dids
-- Estimated volume: ?
-- Access pattern: by scope, name,

CREATE TABLE tmp_dids (
    scope VARCHAR2(25 CHAR) NOT NULL,
    name VARCHAR2(255 CHAR) NOT NULL,
    rse_id RAW(16),
    path VARCHAR2(1024 CHAR),
    bytes NUMBER(19),
    md5 VARCHAR2(32 CHAR),
    adler32 VARCHAR2(8 CHAR),
    expired_at DATE,
    parent_scope VARCHAR2(25 CHAR),
    parent_name VARCHAR2(255 CHAR),
    guid RAW(16),
    events NUMBER(19),
    task_id INTEGER,
    panda_id INTEGER,
    offset NUMBER(19),
    updated_at DATE,
    created_at DATE,
    CONSTRAINT "TMP_DIDS_PK" PRIMARY KEY (scope, name)  using index COMPRESS 1,
    CONSTRAINT "TMP_DIDS_CREATED_NN" CHECK (CREATED_AT IS NOT NULL),
    CONSTRAINT "TMP_DIDS_UPDATED_NN" CHECK (UPDATED_AT IS NOT NULL)
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;

CREATE INDEX "TMP_DIDS_EXPIRED_AT_IDX" ON tmp_dids (case when expired_at is not null then rse_id end) COMPRESS 1  TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;


-- ============================= LIFETIME_EXCEPT =========================================
CREATE TABLE lifetime_except (
    id RAW(16),
    scope VARCHAR2(25 CHAR),
    name VARCHAR2(255 CHAR),
    did_type CHAR(1 CHAR),
    account VARCHAR2(25 CHAR),
    comments VARCHAR2(4000 CHAR),
    pattern VARCHAR2(255 CHAR),
    state CHAR(1 CHAR),
    updated_at DATE,
    expires_at DATE,
    created_at DATE,
    CONSTRAINT "LIFETIME_EXCEPT_DID_TYPE_NN" CHECK (did_type IN ('C', 'D', 'F', 'Y', 'X', 'Z')),
    CONSTRAINT "LIFETIME_EXCEPT_STATE_CHK" CHECK (state IN ('A', 'R', 'W'))
) PCTFREE 0 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;
COMMENT ON TABLE lifetime_except IS 'Table for exceptions of the lifetime model';


-- ============================= ARCHIVE_CONTENT =========================================

-- IOT physical layout because of the foreseen high DML rate (inserts and deletes)
CREATE TABLE atlas_rucio.ARCHIVE_CONTENTS
(
  child_scope VARCHAR2(25 CHAR) NOT NULL,
  child_name VARCHAR2(255 CHAR) NOT NULL,
  scope VARCHAR2(25 CHAR) NOT NULL,
  name VARCHAR2(255 CHAR) NOT NULL,
  bytes NUMBER(19),
  adler32 VARCHAR2(8 CHAR),
  offset NUMBER(19),
  md5 VARCHAR2(32 CHAR),
  guid RAW(16),
  length NUMBER(19),
  updated_at DATE,
  created_at DATE,
CONSTRAINT "ARCH_CONTENTS_PK" PRIMARY KEY (child_scope, child_name, scope, name),
CONSTRAINT "ARCH_CONTENTS_PARENT_FK" FOREIGN KEY(scope, name) REFERENCES atlas_rucio.dids (scope, name),
CONSTRAINT "ARCH_CONTENTS_CHLD_FK" FOREIGN KEY(child_scope, child_name) REFERENCES atlas_rucio.dids (scope, name),
CONSTRAINT "ARCH_CONTENTS_CREATED_NN" CHECK (CREATED_AT IS NOT NULL),
CONSTRAINT "ARCH_CONTENTS_UPDATED_NN" CHECK (UPDATED_AT IS NOT NULL)
) ORGANIZATION INDEX
TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;

-- Complementary index
CREATE INDEX atlas_rucio.ARCH_CONT_SCOPE_NAME_IDX ON atlas_rucio.ARCHIVE_CONTENTS(SCOPE, NAME) COMPRESS 1 TABLESPACE ATLAS_RUCIO_TRANSIENT_DATA01;


COMMENT ON TABLE atlas_rucio.ARCHIVE_CONTENTS is 'Content of archives (zip, tar files) in Rucio. Keeps the association about which files are in which zip files. Expected about 50-100K zip files per day. Most of them with a lifetime of one day but few of them can be permanent (archive on tape). The zips will have 8 to 40 constituent files ';


-- ============================= ARCHIVE_CONTENT_HISTORY =========================================

-- Normal table, monthly partitioned, with OLTP compression. Index is partitioned as well, but no partitioned PK as then Oracle raises
"ORA-14039: partitioning columns must form a subset of key columns of a UNIQUE index" error.

CREATE TABLE atlas_rucio.ARCHIVE_CONTENTS_HISTORY
(
scope VARCHAR2(25 CHAR) NOT NULL,
name VARCHAR2(255 CHAR) NOT NULL,
child_scope VARCHAR2(25 CHAR) NOT NULL,
child_name VARCHAR2(255 CHAR) NOT NULL,
bytes NUMBER(19),
adler32 VARCHAR2(8 CHAR),
offset NUMBER(19),
md5 VARCHAR2(32 CHAR),
guid RAW(16),
length NUMBER(19),
updated_at DATE,
created_at DATE,
CONSTRAINT "ARCH_CONT_HIST_CREATED_NN" CHECK (CREATED_AT IS NOT NULL),
CONSTRAINT "ARCH_CONT_HIST_UPDATED_NN" CHECK (UPDATED_AT IS NOT NULL)
)
PCTFREE 0 COMPRESS FOR OLTP TABLESPACE ATLAS_RUCIO_HIST_DATA02
PARTITION BY RANGE (created_at)
 INTERVAL( NUMTOYMINTERVAL(1,'MONTH'))
 (
   PARTITION DATA_BEFORE_01012017 VALUES LESS THAN (TO_DATE('2017-01-01', 'YYYY-MM-DD'))
 )
;

-- Index on SCOPE and NAME
CREATE INDEX atlas_rucio.ARCH_CONT_HIST_IDX ON atlas_rucio.ARCHIVE_CONTENTS_HISTORY(SCOPE, NAME) COMPRESS 2 LOCAL TABLESPACE ATLAS_RUCIO_HIST_DATA02;


COMMENT ON TABLE atlas_rucio.ARCHIVE_CONTENTS_HISTORY is 'Content of archives (zip, tar files) in Rucio. Keeps the association about which files are in which zip files. Second one to keep the history';
