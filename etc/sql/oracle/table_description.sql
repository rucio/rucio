
/* Description of the Rucio tables */


COMMENT ON TABLE ACCOUNTS IS 'Account information';
COMMENT ON TABLE ACCOUNT_ATTR_MAP IS 'Mapping accounts with additional key-values';
COMMENT ON TABLE ACCOUNT_LIMITS IS 'Storage limit (bytes) for an account on an RSE';
COMMENT ON TABLE ACCOUNT_MAP IS 'Mapping identities (credentials) to accounts';
COMMENT ON TABLE ACCOUNT_USAGE IS 'Account usage per RSE';
COMMENT ON TABLE ACCOUNT_USAGE_HISTORY IS 'Account usage per RSE history';
COMMENT ON TABLE ALEMBIC_VERSION IS 'Version identifier of the installed database schema';
COMMENT ON TABLE AMICONVENTIONS IS 'AMI dataset naming conventions';
COMMENT ON TABLE ARCHIVE_CONTENTS IS 'Mapping between archive and its constituents';
COMMENT ON TABLE ARCHIVE_CONTENTS_HISTORY IS 'Archive constituent mapping history';
COMMENT ON TABLE BAD_REPLICAS IS 'Replicas which have been declared suspicious/bad/lost/temporary unavailable';
COMMENT ON TABLE BAD_PFNS IS 'Table of pfns which have been declared bad/lost/temporary unavailable to be processed by the minos daemon';
COMMENT ON TABLE COLLECTION_REPLICAS IS 'Collection (Dataset) replica information';
COMMENT ON TABLE CONFIGS IS 'Key-Value pairs of global Rucio configuration';
COMMENT ON TABLE CONFIGS_HISTORY IS 'Configuration history';
COMMENT ON TABLE CONTENTS IS 'Mapping from files to datasets; datasets to containers; containers to other containers';
COMMENT ON TABLE CONTENTS_HISTORY IS 'Contents history';
COMMENT ON TABLE DATASET_LOCKS IS 'Representation of a Rule on a dataset';
COMMENT ON TABLE DELETED_DIDS IS 'Deleted DIDs stored to enforce uniquenes';
COMMENT ON TABLE DIDS IS 'File/Dataset/Container information';
COMMENT ON TABLE DID_KEYS IS 'Possible keys of a did and enforced schema';
COMMENT ON TABLE DID_KEY_MAP IS 'Possible values of keys';
COMMENT ON TABLE DISTANCES IS 'Distance information between two RSEs representing the quality of link';
COMMENT ON TABLE HEARTBEATS IS 'Internal daemon health status used for workload splitting';
COMMENT ON TABLE IDENTITIES IS 'Identities, such as username/password, keys, etc. for accounts';
COMMENT ON TABLE LIFETIME_EXCEPT IS 'Exceptions for dids to be cleaned by the lifetime algorithm';
COMMENT ON TABLE LOCKS IS 'Representation of a Rule on a File';
COMMENT ON TABLE LOGGING_TABPARTITIONS IS 'Table in which logging information of tables partition creation activity is stored';
COMMENT ON TABLE MESSAGES IS 'Messages to be processed by Messaging daemon';
COMMENT ON TABLE MESSAGES_HISTORY IS 'Messages processed by Messaging daemon';
COMMENT ON TABLE NAMING_CONVENTIONS IS 'Naming conventions (regexp) of official dids';
COMMENT ON TABLE QUARANTINED_REPLICAS IS 'Dark Replicas identified by the consistency checker';
COMMENT ON TABLE QUARANTINED_REPLICAS_HISTORY IS 'Dark replicas history';
COMMENT ON TABLE REPLICAS IS 'Replica information';
COMMENT ON TABLE REPLICAS_HISTORY IS 'Replica information history';
COMMENT ON TABLE REQUESTS IS 'Active transfer requests';
COMMENT ON TABLE REQUESTS_HISTORY IS 'Transfer request history';
COMMENT ON TABLE RSES IS 'RSE Information';
COMMENT ON TABLE RSE_ATTR_MAP IS 'Mapping of key-value pairs to RSEs';
COMMENT ON TABLE RSE_LIMITS IS 'Deletion thresholds for RSEs';
COMMENT ON TABLE RSE_PROTOCOLS IS 'Supported protocols and endpoints for RSEs';
COMMENT ON TABLE RSE_TRANSFER_LIMITS IS 'Transfer limits for activities enforced by the Conveyor Throttler';
COMMENT ON TABLE RSE_USAGE IS 'RSE Usage information';
COMMENT ON TABLE RSE_USAGE_HISTORY IS 'RSE Usage information history';
COMMENT ON TABLE RUCIO_ACCOUNTING_HIST_TAB IS 'Special ATLAS internal accounting';
COMMENT ON TABLE RUCIO_ACCOUNTING_LOGICAL_BYTES IS 'Special ATLAS internal accounting';
COMMENT ON TABLE RUCIO_ACCOUNTING_TAB IS 'Special ATLAS internal accounting';
COMMENT ON TABLE RULES IS 'Rule information';
COMMENT ON TABLE RULES_HISTORY IS 'Long-Term rule information history';
COMMENT ON TABLE RULES_HIST_RECENT IS 'Short-Term, detailed, rule information history';
COMMENT ON TABLE SCOPES IS 'Scope information';
COMMENT ON TABLE SOURCES IS 'Replicas currently being used as sources for transfers';
COMMENT ON TABLE SOURCES_HISTORY IS 'Sources history';
COMMENT ON TABLE SUBSCRIPTIONS IS 'Subscription information';
COMMENT ON TABLE SUBSCRIPTIONS_HISTORY IS 'Subscription history';
COMMENT ON TABLE TMP_DIDS IS 'Temporary DIDs';
COMMENT ON TABLE TOKENS IS 'Active Authentication tokens';
COMMENT ON TABLE UPDATED_ACCOUNT_COUNTERS IS 'Table for updated account_rse information to be processed by Abacus';
COMMENT ON TABLE UPDATED_COL_REP IS 'Table for updated collection replica information to be processed by Abacus';
COMMENT ON TABLE UPDATED_DIDS IS 'Table for updated dids to be processed by judge-evaluator';
COMMENT ON TABLE UPDATED_RSE_COUNTERS IS 'Table for updated rse usage information to be processed by Abacus';


