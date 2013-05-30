-- Author: vincent.garonne@cern.ch
-- Date: Tue Jun  4 09:09:19 CEST 2013

CREATE TABLE requests_history (
	id RAW(16),
	updated_at DATE,
	scope VARCHAR2(25 CHAR),
	name VARCHAR2(255 CHAR),
	dest_rse_id RAW(16),
	type VARCHAR(1 CHAR),
	attributes VARCHAR2(4000 CHAR),
	state VARCHAR(1 CHAR),
	external_id VARCHAR2(64 CHAR),
	retry_count NUMBER(3),
	err_msg VARCHAR2(4000 CHAR),
	previous_attempt_id RAW(16),
	created_at DATE,
	CONSTRAINT "REQUESTS_HISTORY_PK" PRIMARY KEY (updated_at, scope, name, dest_rse_id),
	CHECK (type IN ('U', 'D', 'T')),
	CHECK (state IN ('Q', 'S', 'D', 'F'))
) PCTFREE 0;
-- Description: History table for requests


CREATE TABLE callbacks (
	id RAW(16),
	event_type VARCHAR2(1024 CHAR),
	payload VARCHAR2(4000 CHAR),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "CALLBACKS_PK" PRIMARY KEY (id),
	CONSTRAINT "CALLBACKS_EVENT_TYPE_NN" CHECK ("EVENT_TYPE" IS NOT NULL),
	CONSTRAINT "CALLBACKS_PAYLOAD_NN" CHECK ("PAYLOAD" IS NOT NULL),
	CONSTRAINT "CALLBACKS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "CALLBACKS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) PCTFREE 0;
-- Description: Table to store callbacks before sending them
-- Estimated volume: 20,000 rows per 10. min.
-- Acces pattern: list the last callbacks by created data for the last n minutes


CREATE TABLE rse_usage_history (
	rse_id RAW(16),
	source VARCHAR2(255 CHAR),
	used NUMBER(19),
	free NUMBER(19),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "RSE_USAGE_HISTORY_PK" PRIMARY KEY (rse_id, source, updated_at) USING INDEX LOCAL COMPRESS 2
) PCTFREE 0
PARTITION BY LIST (RSE_ID)
(
    PARTITION INITIAL_PARTITION VALUES ('00000000000000000000000000000000')
);
-- Description: Table to store the usage history per RSE (time series)
-- Estimated volume: ~700 RSEs * with two records per 30 min. (e.g. rucio/srm)
-- Access pattern: By rse_id


CREATE TABLE mock_fts_transfers (
	transfer_id RAW(16),
	start_time DATE,
	last_modified DATE,
	state VARCHAR(1 CHAR),
	transfer_metadata VARCHAR2(4000 CHAR),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "MOCK_FTS_TRANSFERS_PK" PRIMARY KEY (transfer_id),
	CONSTRAINT "MOCK_FTS_TRANSFERS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "MOCK_FTS_TRANSFERS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CHECK (state IN ('S', 'R', 'A', 'F', 'X', 'D', 'C'))
) PCTFREE 0;
-- Description: Table to store mock fts transfers


CREATE TABLE account_usage_history (
	account VARCHAR2(25 CHAR),
	rse_id RAW(16),
	files NUMBER(19),
	bytes NUMBER(19),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "ACCOUNT_USAGE_HISTORY_PK" PRIMARY KEY (account, rse_id, updated_at) USING INDEX LOCAL COMPRESS 2
) PCTFREE 0
PARTITION BY LIST (account)
SUBPARTITION BY LIST (rse_id)
(
    PARTITION INITIAL_PARTITION VALUES ('INITIAL_PARTITION')
);
-- Description: Table to store the usage history per account, RSE
-- Estimated volume: ~700 RSEs * 2000 accounts: one record every 30 min.
-- Access pattern: By account, by account rse_id


CREATE TABLE rses (
	id RAW(16),
	rse VARCHAR2(255 CHAR),
	type VARCHAR(4 CHAR),
	deterministic NUMBER(1),
	volatile NUMBER(1),
	updated_at DATE,
	created_at DATE,
	deleted NUMBER(1),
	deleted_at DATE,
	CONSTRAINT "RSES_PK" PRIMARY KEY (id),
	CONSTRAINT "RSES_RSE_UQ" UNIQUE (rse),
	CONSTRAINT "RSES_RSE__NN" CHECK ("RSE" IS NOT NULL),
	CONSTRAINT "RSES_TYPE_NN" CHECK ("TYPE" IS NOT NULL),
	CONSTRAINT "RSES_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "RSES_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "RSES_DELETED_NN" CHECK (DELETED IS NOT NULL),
	CONSTRAINT "RSES_TYPE_CHK" CHECK (type IN ('DISK', 'TAPE')),
	CONSTRAINT "RSE_DETERMINISTIC_CHK" CHECK (deterministic IN (0, 1)),
	CONSTRAINT "RSE_VOLATILE_CHK" CHECK (volatile IN (0, 1)),
	CONSTRAINT "RSES_DELETED_CHK" CHECK (deleted IN (0, 1))
) PCTFREE 0;
-- Description: Table to store the list of RSEs
-- Estimated volume: ~700 which can be reduced to ~200
-- Access pattern: By rse/id


CREATE TABLE subscriptions_history (
	id RAW(16),
	name VARCHAR2(64 CHAR),
	filter VARCHAR2(2048 CHAR),
	replication_rules VARCHAR2(1024 CHAR),
	policyid NUMBER(2),
	state VARCHAR(1 CHAR),
	last_processed DATE,
	account VARCHAR2(25 CHAR),
	lifetime DATE,
	retroactive NUMBER(1),
	expired_at DATE,
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "SUBSCRIPTIONS_HISTORY_PK" PRIMARY KEY (id, updated_at),
	CHECK (state IN ('I', 'A', 'B', 'U', 'N')),
	CONSTRAINT "SUBS_HISTORY_RETROACTIVE_CHK" CHECK (retroactive IN (0, 1))
) PCTFREE 0;
-- Description: Table to store the history of subscriptions


CREATE TABLE did_keys (
	key VARCHAR2(255 CHAR),
	key_type VARCHAR(10 CHAR),
	value_type VARCHAR2(255 CHAR),
	value_regexp VARCHAR2(255 CHAR),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "DID_KEYS_PK" PRIMARY KEY (key),
	CONSTRAINT "DID_KEYS_KEY_TYPE_NN" CHECK (key_type IS NOT NULL),
	CONSTRAINT "DID_KEYS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "DID_KEYS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "DID_KEYS_KEY_TYPE_CHK" CHECK (key_type IN ('ALL', 'DERIVED', 'COLLECTION', 'FILE'))
) PCTFREE 0;
-- Description: Table to store the list of values for a key
-- Estimated volume: ~1000 (campaign ~20, datatype ~400, group,  ~20, prod_step ~30, project ~200, provenance ~10)
-- Access pattern: by key. by key value.


CREATE TABLE identities (
	identity VARCHAR2(255 CHAR),
	type VARCHAR(8 CHAR),
	username VARCHAR2(255 CHAR),
	password VARCHAR2(255 CHAR),
	salt BLOB,
	email VARCHAR2(255 CHAR),
	updated_at DATE,
	created_at DATE,
	deleted NUMBER(1),
	deleted_at DATE,
	CONSTRAINT "IDENTITIES_PK" PRIMARY KEY (identity, type),
	CONSTRAINT "IDENTITIES_TYPE_NN" CHECK ("TYPE" IS NOT NULL),
	CONSTRAINT "IDENTITIES_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "IDENTITIES_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "IDENTITIES_DELETED_NN" CHECK (DELETED IS NOT NULL),
	CONSTRAINT "IDENTITIES_TYPE_CHK" CHECK (type IN ('X509', 'GSS', 'USERPASS')),
	CONSTRAINT "IDENTITIES_DELETED_CHK" CHECK (deleted IN (0, 1))
) PCTFREE 0;
-- Description: Table to store the identities of the users
-- Estimated volume: ~2000 users * gss + x509 credentials : ~4000 rows
-- Access pattern: By identity, type


CREATE TABLE accounts (
	account VARCHAR2(25 CHAR),
	type VARCHAR(7 CHAR),
	status VARCHAR(9 CHAR),
	suspended_at DATE,
	deleted_at DATE,
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "ACCOUNTS_PK" PRIMARY KEY (account),
	CONSTRAINT "ACCOUNTS_TYPE_NN" CHECK ("TYPE" IS NOT NULL),
	CONSTRAINT "ACCOUNTS_STATUS_NN" CHECK ("STATUS" IS NOT NULL),
	CONSTRAINT "ACCOUNTS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "ACCOUNTS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "ACCOUNTS_TYPE_CHK" CHECK (type IN ('GROUP', 'USER', 'SERVICE')),
	CONSTRAINT "ACCOUNTS_STATUS_CHK" CHECK (status IN ('ACTIVE', 'DELETED', 'SUSPENDED'))
) PCTFREE 0;
-- Description: Table to store the list of accounts
-- Estimated volume: ~2000
-- Access pattern: By account


CREATE TABLE account_counters (
	account VARCHAR2(25 CHAR),
	rse_id RAW(16),
	num NUMBER(6),
	files NUMBER(19),
	bytes NUMBER(19),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "ACCOUNT_COUNTERS_PK" PRIMARY KEY (account, rse_id, num) USING INDEX LOCAL COMPRESS 2,
	CONSTRAINT "ACCOUNT_COUNTERS_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
	CONSTRAINT "ACCOUNT_COUNTERS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
	CONSTRAINT "ACCOUNT_COUNTERS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "ACCOUNT_COUNTERS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) PCTFREE 0
PARTITION BY LIST (account)
SUBPARTITION BY LIST (rse_id)
(
    PARTITION INITIAL_PARTITION VALUES ('INITIAL_PARTITION')
);
-- Description: Table to store the disk usage per account and rse_id
-- Estimated volume: ~700 RSEs * 2000 accounts * 50 counters
-- Access pattern: by account, rse_id


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
) PCTFREE 0;
-- Description: Table to mapping between rse attributes and rse
-- Estimated volume: ~700 * 10 rse attributes (t1, t0, etc.)
-- Access pattern: by rse_id. By key. By key/value.



CREATE TABLE rse_usage (
	rse_id RAW(16),
	source VARCHAR2(255 CHAR),
	used NUMBER(19),
	free NUMBER(19),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "RSE_USAGE_PK" PRIMARY KEY (rse_id, source) USING INDEX LOCAL COMPRESS 1,
	CONSTRAINT "RSE_USAGE_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
	CONSTRAINT "RSE_USAGE_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "RSE_USAGE_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) PCTFREE 0
PARTITION BY LIST (RSE_ID)
(
    PARTITION INITIAL_PARTITION VALUES ('00000000000000000000000000000000')
);
-- Description: Table to store the disk usage of a RSE
-- Estimated volume: ~700 RSEs *  ~2 measures (rucio, srm): ~1.400
-- Access pattern: by rse_id, source


CREATE TABLE tokens (
	token VARCHAR2(352 CHAR),
	account VARCHAR2(25 CHAR),
	expired_at DATE,
	ip VARCHAR2(39 CHAR),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "TOKENS_PK" PRIMARY KEY (account, token),
	CONSTRAINT "TOKENS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
	CONSTRAINT "TOKENS_EXPIRED_AT_NN" CHECK ("EXPIRED_AT" IS NOT NULL),
	CONSTRAINT "TOKENS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "TOKENS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) PCTFREE 0;
-- Description: Table to store auth tokens
-- Estimated volume: ~100,000
-- Access pattern: by token. Cleanup of expired token done by account.


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
) PCTFREE 0;
-- Description: Table to store the limits of a a RSE
-- Estimated volume: ~700 RSEs *  ~2 limits (MinFreeSpace, MaxBeingDeletedFiles)
-- Access pattern: by rse_id, name


CREATE TABLE rse_counters (
	rse_id RAW(16),
	num NUMBER(6),
	files NUMBER(19),
	bytes NUMBER(19),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "RSE_COUNTERS_PK" PRIMARY KEY (rse_id, num) USING INDEX LOCAL COMPRESS 1,
	CONSTRAINT "RSE_COUNTERS_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
	CONSTRAINT "RSE_COUNTERS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "RSE_COUNTERS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) PCTFREE 0
PARTITION BY LIST (RSE_ID)
(
    PARTITION INITIAL_PARTITION VALUES ('00000000000000000000000000000000')
);
-- Description: Table to store incrementally the disk usage of a RSE
-- Estimated volume: ~700 RSEs *  10000 counters: ~ 7,000,000
-- Access pattern: by rse_id


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
) PCTFREE 0;
-- Description: Table to store incrementally the disk usage by account, rse
-- Estimated volume: ~700 RSEs *  ~2000 accounts
-- Access pattern: by account. by account/rse_id


CREATE TABLE did_key_map (
	key VARCHAR2(255 CHAR),
	value VARCHAR2(255 CHAR),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "DID_KEY_MAP_PK" PRIMARY KEY (key, value),
	CONSTRAINT "DID_MAP_KEYS_FK" FOREIGN KEY(key) REFERENCES did_keys (key),
	CONSTRAINT "DID_KEY_MAP_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "DID_KEY_MAP_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) PCTFREE 0;
-- Description: Table to store the list of values for a key
-- Estimated volume: ~1000 (campaign ~20, datatype ~400, group,  ~20, prod_step ~30, project ~200, provenance ~10)
-- Access pattern: by key. by key value.



CREATE TABLE account_map (
	identity VARCHAR2(255 CHAR),
	type VARCHAR(8 CHAR),
	account VARCHAR2(25 CHAR),
	is_default NUMBER(1),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "ACCOUNT_MAP_PK" PRIMARY KEY (identity, type, account),
	CONSTRAINT "ACCOUNT_MAP_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
	CONSTRAINT "ACCOUNT_MAP_ID_TYPE_FK" FOREIGN KEY(identity, type) REFERENCES identities (identity, type),
	CONSTRAINT "ACCOUNT_MAP_IS_DEFAULT_NN" CHECK (is_default IS NOT NULL),
	CONSTRAINT "ACCOUNT_MAP_TYPE_NN" CHECK ("TYPE" IS NOT NULL),
	CONSTRAINT "ACCOUNT_MAP_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "ACCOUNT_MAP_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "ACCOUNT_MAP_TYPE_CHK" CHECK (type IN ('X509', 'GSS', 'USERPASS')),
	CONSTRAINT "ACCOUNT_MAP_DEFAULT_CHK" CHECK (is_default IN (0, 1))
) PCTFREE 0;
-- Description: Table to store the mapping account-identity
-- Estimated volume: ~2000 accounts * 4000 identities
-- Access pattern: by identity, type


CREATE TABLE subscriptions (
	id RAW(16),
	name VARCHAR2(64 CHAR),
	filter VARCHAR2(2048 CHAR),
	replication_rules VARCHAR2(1024 CHAR),
	policyid NUMBER(3),
	state VARCHAR(1 CHAR),
	last_processed DATE,
	account VARCHAR2(25 CHAR),
	lifetime DATE,
	retroactive NUMBER(1),
	expired_at DATE,
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "SUBSCRIPTIONS_PK" PRIMARY KEY (id),
	CONSTRAINT "SUBSCRIPTION_NAME_ACCOUNT_UQ" UNIQUE (name, account),
	CONSTRAINT "SUBSCRIPTIONS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
	CONSTRAINT "SUBSCRIPTIONS_RETROACTIVE_NN" CHECK ("RETROACTIVE" IS NOT NULL),
	CONSTRAINT "SUBSCRIPTIONS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "SUBSCRIPTIONS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "SUBSCRIPTIONS_STATE_CHK" CHECK (state IN ('I', 'A', 'B', 'U', 'N')),
	CONSTRAINT "SUBSCRIPTIONS_RETROACTIVE_CHK" CHECK (retroactive IN (0, 1))
) PCTFREE 0;
-- Description: Table to store subscriptions
-- Estimated volume: ~1000
-- Access pattern: by state. by name


CREATE TABLE account_limits (
	account VARCHAR2(25 CHAR),
	rse_expression VARCHAR2(255 CHAR),
	name VARCHAR2(255 CHAR),
	value NUMBER(19),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "ACCOUNT_LIMITS_PK" PRIMARY KEY (account, rse_expression, name),
	CONSTRAINT "ACCOUNT_LIMITS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
	CONSTRAINT "ACCOUNT_LIMITS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "ACCOUNT_LIMITS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) PCTFREE 0;
-- Description: Table to store the limits for an account.
-- Estimated volume: ~2000 accounts * 700 RSE * 1 limits (MaxBytes)
-- Access pattern: by account


CREATE TABLE scopes (
	scope VARCHAR2(25 CHAR),
	account VARCHAR2(25 CHAR),
	is_default NUMBER(1),
	status VARCHAR(1 CHAR),
	closed_at DATE,
	deleted_at DATE,
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "SCOPES_PK" PRIMARY KEY (scope),
	CONSTRAINT "SCOPES_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
	CONSTRAINT "SCOPES_IS_DEFAULT_NN" CHECK (is_default IS NOT NULL),
	CONSTRAINT "SCOPES_STATUS_NN" CHECK (STATUS IS NOT NULL),
	CONSTRAINT "SCOPES_ACCOUNT_NN" CHECK (account IS NOT NULL),
	CONSTRAINT "SCOPES_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "SCOPES_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "SCOPES_DEFAULT_CHK" CHECK (is_default IN (0, 1)),
	CONSTRAINT "SCOPE_STATUS_CHK" CHECK (status IN ('C', 'D', 'O'))
) PCTFREE 0;
-- Description: Table to store the scopes
-- Estimated volume: ~4000
-- Access pattern: by scope


CREATE TABLE rse_protocols (
	rse_id RAW(16),
	scheme VARCHAR2(255 CHAR),
	hostname VARCHAR2(255 CHAR),
	port NUMBER(6),
	prefix VARCHAR2(1024 CHAR),
	impl VARCHAR2(255 CHAR) NOT NULL,
	"read_LAN" INTEGER,
	"write_LAN" INTEGER,
	"delete_LAN" INTEGER,
	"read_WAN" INTEGER,
	"write_WAN" INTEGER,
	"delete_WAN" INTEGER,
	extended_attributes VARCHAR2(1024 CHAR),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "RSE_PROTOCOLS_PK" PRIMARY KEY (rse_id, scheme, hostname, port),
	CONSTRAINT "RSE_PROTOCOL_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
	CONSTRAINT "RSE_PROTOCOLS_IMPL_NN" CHECK ("IMPL" IS NOT NULL),
	CONSTRAINT "RSE_PROTOCOLS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "RSE_PROTOCOLS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL)
) PCTFREE 0;
-- Description: Table to store the list of protocols per RSE
-- Estimated volume: ~700 RSEs *  ~3 protocols = ~ ~2100
-- Access pattern: by rse_id. by rse_id, scheme


CREATE TABLE dids (
	scope VARCHAR2(25 CHAR),
	name VARCHAR2(255 CHAR),
	account VARCHAR2(25 CHAR),
	type VARCHAR(2 CHAR),
	open NUMBER(1),
	monotonic NUMBER(1) DEFAULT '0',
	hidden NUMBER(1) DEFAULT '0',
	obsolete NUMBER(1) DEFAULT '0',
	complete NUMBER(1),
	new NUMBER(1) DEFAULT '1',
	availability VARCHAR(1 CHAR),
	suppressed NUMBER(1) DEFAULT '0',
	bytes NUMBER(19),
	length NUMBER(19),
	md5 VARCHAR2(32 CHAR),
	adler32 VARCHAR2(8 CHAR),
	expired_at DATE,
	deleted_at DATE,
	updated_at DATE,
	created_at DATE,
    events  NUMBER(22),
    guid    RAW(16),
    project VARCHAR2(50 CHAR),
    datatype VARCHAR2(50 CHAR),
    run_number  NUMBER(10),
    stream_name VARCHAR2(50 CHAR),
    prod_step VARCHAR2(50 CHAR),
    version VARCHAR2(50 CHAR),
    campaign VARCHAR2(50 CHAR),
	CONSTRAINT "DIDS_PK" PRIMARY KEY (scope, type, name) USING INDEX LOCAL COMPRESS 2,
	CONSTRAINT "DIDS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account) ON DELETE CASCADE,
	CONSTRAINT "DIDS_SCOPE_FK" FOREIGN KEY(scope) REFERENCES scopes (scope),
	CONSTRAINT "DIDS_MONOTONIC_NN" CHECK ("MONOTONIC" IS NOT NULL),
	CONSTRAINT "DIDS_OBSOLETE_NN" CHECK ("OBSOLETE" IS NOT NULL),
	CONSTRAINT "DIDS_SUPP_NN" CHECK ("SUPPRESSED" IS NOT NULL),
	CONSTRAINT "DIDS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "DIDS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "DIDS_TYPE_CHK" CHECK (type IN ('C', 'D', 'F', 'DF', 'DD', 'DC')),
	CONSTRAINT "DIDS_OPEN_CHK" CHECK (open IN (0, 1)),
	CONSTRAINT "DIDS_MONOTONIC_CHK" CHECK (monotonic IN (0, 1)),
	CONSTRAINT "DIDS_HIDDEN_CHK" CHECK (hidden IN (0, 1)),
	CONSTRAINT "DIDS_OBSOLETE_CHK" CHECK (obsolete IN (0, 1)),
	CONSTRAINT "DIDS_COMPLETE_CHK" CHECK (complete IN (0, 1)),
	CONSTRAINT "DIDS_NEW_CHK" CHECK (new IN (0, 1)),
	CONSTRAINT "DIDS_AVAILABILITY_CHK" CHECK (availability IN ('A', 'D', 'L')),
	CONSTRAINT "FILES_SUPP_CHK" CHECK (suppressed IN (0, 1))
) PCTFREE 0 ENABLE ROW MOVEMENT
PARTITION BY LIST(SCOPE)
SUBPARTITION BY LIST(TYPE)
SUBPARTITION TEMPLATE
    (
    SUBPARTITION C VALUES('C'),
    SUBPARTITION D VALUES('D'),
    SUBPARTITION F VALUES('F'),
    SUBPARTITION DD VALUES('DD'),
    SUBPARTITION DC VALUES('DC'),
    SUBPARTITION DF VALUES('DF')
    )
(
PARTITION INITIAL_PARTITION VALUES ('INITIAL_PARTITION')
);
-- Description: Table to store data identifiers
-- Estimated volume: 0.5 Billion
-- uniqueness constraint on scope,name over all types and deleted data
-- Access pattern:
--                 - by scope, name (type)
--                 - by scope, pattern, type (wildcard queries)
--                 - by expired_at to get the expired datasets
--                 - by new to get the new datasets


CREATE INDEX "DIDS_NEW_IDX" ON dids (new);

CREATE INDEX "DIDS_EXPIRED_AT" ON dids (expired_at);

--/
CREATE OR REPLACE TRIGGER check_did_uniqueness
BEFORE INSERT on DIDS
  FOR EACH ROW
DECLARE
    n number        := 0;
BEGIN
    BEGIN
        SELECT 1 INTO n FROM ATLAS_RUCIO.DIDS
        WHERE      scope = :NEW.scope
               AND name = :NEW.name
               AND type != :NEW.type;

        IF (n = 1) THEN
           RAISE_APPLICATION_ERROR  (-20101, 'unique constraint (ATLAS_RUCIO.DIDS_PK) violated');
        END IF;

    EXCEPTION
        WHEN NO_DATA_FOUND THEN NULL;
    END ;
END;
/

CREATE TABLE requests (
	id RAW(16),
	type VARCHAR(1 CHAR),
	scope VARCHAR2(25 CHAR),
	name VARCHAR2(255 CHAR),
	did_type VARCHAR(1 CHAR) DEFAULT 'F',
	dest_rse_id RAW(16),
	attributes VARCHAR2(4000 CHAR),
	state VARCHAR(1 CHAR),
	external_id VARCHAR2(64 CHAR),
	retry_count NUMBER(3),
	err_msg VARCHAR2(4000 CHAR),
	previous_attempt_id RAW(16),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "REQUESTS_PK" PRIMARY KEY (scope, name, dest_rse_id),
	CONSTRAINT "REQUESTS_DID_FK" FOREIGN KEY(scope, name, did_type) REFERENCES dids (scope, name, type),
	CONSTRAINT "REQUESTS_RSES_FK" FOREIGN KEY(dest_rse_id) REFERENCES rses (id),
	CONSTRAINT "REQUESTS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "REQUESTS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "REQUESTS_TYPE_CHK" CHECK (type IN ('U', 'D', 'T')),
	CONSTRAINT "REQUESTS_STATE_CHK" CHECK (state IN ('Q', 'S', 'D', 'F'))
) PCTFREE 0;
-- Description: Table to store transfer requests
-- Estimated volume: 2 millions

CREATE INDEX "REQUESTS_ID_IDX" ON requests (id);

CREATE INDEX "REQUESTS_TYPE_STATE_IDX" ON requests (type, state);


CREATE TABLE rules (
	id RAW(16),
	subscription_id RAW(16),
	account VARCHAR2(25 CHAR),
	scope VARCHAR2(25 CHAR),
	name VARCHAR2(255 CHAR),
	type VARCHAR(1 CHAR),
	state VARCHAR(11 CHAR),
	rse_expression VARCHAR2(255 CHAR),
	copies SMALLINT,
	expires_at DATE,
	weight VARCHAR2(255 CHAR),
	locked NUMBER(1),
	grouping VARCHAR(1 CHAR),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "RULES_PK" PRIMARY KEY (id),
	CONSTRAINT "RULES_SCOPE_NAME_FK" FOREIGN KEY(scope, name, type) REFERENCES dids (scope, name, type),
	CONSTRAINT "RULES_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
	CONSTRAINT "RULES_SUBS_ID_FK" FOREIGN KEY(subscription_id) REFERENCES subscriptions (id),
	CONSTRAINT "RULES_STATE_NN" CHECK ("STATE" IS NOT NULL),
	CONSTRAINT "RULES_GROUPING_NN" CHECK ("GROUPING" IS NOT NULL),
	CONSTRAINT "RULES_COPIES_NN" CHECK ("COPIES" IS NOT NULL),
	CONSTRAINT "RULES_LOCKED_NN" CHECK ("LOCKED" IS NOT NULL),
	CONSTRAINT "RULES_UQ" UNIQUE (scope, name, account, rse_expression, copies),
	CONSTRAINT "RULES_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "RULES_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "RULES_TYPE_CHK" CHECK (type IN ('C', 'D', 'F')),
	CONSTRAINT "RULES_STATE_CHK" CHECK (state IN ('STUCK', 'REPLICATING', 'OK', 'SUSPENDED')),
	CONSTRAINT "RULES_LOCKED_CHK" CHECK (locked IN (0, 1)),
	CONSTRAINT "RULES_GROUPING_CHK" CHECK (grouping IN ('A', 'D', 'N'))
) PCTFREE 0;
-- Description: Table to store rules
-- Estimated volume:  ~25 millions (versus 1 billion)
-- Access pattern: -- By scope, name
--                 -- By rule_id
                   -- By subscription_id

---                   index on expires_at DATE missing

CREATE TABLE contents (
	scope VARCHAR2(25 CHAR),
	name VARCHAR2(255 CHAR),
	child_scope VARCHAR2(25 CHAR),
	child_name VARCHAR2(255 CHAR),
	type VARCHAR(1 CHAR),
	child_type VARCHAR(1 CHAR),
	length NUMBER(22),
	bytes NUMBER(22),
	adler32 VARCHAR2(8 CHAR),
	md5 VARCHAR2(32 CHAR),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "CONTENTS_PK" PRIMARY KEY (scope, name, child_scope, child_name) USING INDEX LOCAL COMPRESS 1,
	CONSTRAINT "CONTENTS_ID_FK" FOREIGN KEY(scope, name, type) REFERENCES dids (scope, name, type),
	CONSTRAINT "CONTENTS_CHILD_ID_FK" FOREIGN KEY(child_scope, child_name, child_type) REFERENCES dids (scope, name, type) ON DELETE CASCADE,
	CONSTRAINT "CONTENTS_TYPE_NN" CHECK ("TYPE" IS NOT NULL),
	CONSTRAINT "CONTENTS_CHILD_TYPE_NN" CHECK ("CHILD_TYPE" IS NOT NULL),
	CONSTRAINT "CONTENTS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "CONTENTS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "CONTENTS_TYPE_CHK" CHECK (type IN ('C', 'D', 'F')),
	CONSTRAINT "CONTENTS_CHILD_TYPE_CHK" CHECK (child_type IN ('C', 'D', 'F'))
) PCTFREE 0
PARTITION BY LIST (SCOPE)
(
    PARTITION INITIAL_PARTITION VALUES ('Initial_partition')
);
-- Description: Table to store did contents
-- Estimated volume: 0.6 Billion
-- Access pattern:
--                 - by scope, name
--                 - by child_scope, child_name

CREATE INDEX "CONTENTS_CHILD_SCOPE_NAME_IDX" ON contents (child_scope, child_name, scope, name) LOCAL COMPRESS 1;



CREATE TABLE replicas (
	scope VARCHAR2(25 CHAR),
	name VARCHAR2(255 CHAR),
	rse_id RAW(16),
	type VARCHAR(1 CHAR) DEFAULT 'F',
	bytes NUMBER(19),
	md5 VARCHAR2(32 CHAR),
	adler32 VARCHAR2(8 CHAR),
	path VARCHAR2(1024 CHAR),
	state VARCHAR(1 CHAR),
	lock_cnt NUMBER(5),
	accessed_at DATE,
	tombstone DATE,
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "REPLICAS_PK" PRIMARY KEY (scope, rse_id, name) USING INDEX LOCAL COMPRESS 2,
	CONSTRAINT "REPLICAS_LFN_FK" FOREIGN KEY(scope, name, type) REFERENCES dids (scope, name, type),
	CONSTRAINT "REPLICAS_RSE_ID_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
	CONSTRAINT "REPLICAS_STATE_NN" CHECK ("STATE" IS NOT NULL),
	CONSTRAINT "REPLICAS_SIZE_NN" CHECK (bytes IS NOT NULL),
	CONSTRAINT "REPLICAS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "REPLICAS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "REPLICAS_STATE_CHK" CHECK (state IN ('A', 'C', 'B', 'U', 'D'))
) PCTFREE 0
PARTITION BY LIST (SCOPE)
(
    PARTITION INITIAL_PARTITION VALUES ('Initial_partition')
);
-- Description: Table to store file replicas
-- Estimated volume: ~ Billions
-- Access pattern:
--                 - by scope, name
--                 - by rse_id
--                 - by tombstone not null

CREATE INDEX "REPLICAS_TOMBSTONE_IDX" ON replicas (case when TOMBSTONE is not NULL then RSE_ID END, TOMBSTONE);


CREATE TABLE locks (
	scope VARCHAR2(25 CHAR),
	name VARCHAR2(255 CHAR),
	type VARCHAR(1 CHAR) DEFAULT 'F',
	rule_id RAW(16),
	rse_id RAW(16),
	account VARCHAR2(25 CHAR),
	bytes NUMBER(19),
	state VARCHAR(1 CHAR),
	updated_at DATE,
	created_at DATE,
	CONSTRAINT "LOCKS_PK" PRIMARY KEY (scope, name, rule_id, rse_id) USING INDEX LOCAL COMPRESS 1,
	CONSTRAINT "LOCKS_DID_FK" FOREIGN KEY(scope, name, type) REFERENCES dids (scope, name, type),
	CONSTRAINT "LOCKS_RULE_ID_FK" FOREIGN KEY(rule_id) REFERENCES rules (id) ON DELETE CASCADE,
	CONSTRAINT "LOCKS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account),
	CONSTRAINT "LOCKS_RSES_FK" FOREIGN KEY(rse_id) REFERENCES rses (id),
	CONSTRAINT "LOCKS_STATE_NN" CHECK ("STATE" IS NOT NULL),
	CONSTRAINT "LOCKS_CREATED_NN" CHECK ("CREATED_AT" IS NOT NULL),
	CONSTRAINT "LOCKS_UPDATED_NN" CHECK ("UPDATED_AT" IS NOT NULL),
	CONSTRAINT "LOCKS_STATE_CHK" CHECK (state IN ('S', 'R', 'O'))
) PCTFREE 0
PARTITION BY LIST (SCOPE)
(
    PARTITION INITIAL_PARTITION VALUES ('Initial_partition')
);
-- Description: Table to store locks
-- Estimated volume: 1.7 billion
-- Access pattern: -- By scope, name
                    -- By scope, name, rule_id (By rule_id AND state, rule_id)

