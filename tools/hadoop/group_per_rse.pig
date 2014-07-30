/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
*/

SET mapreduce.map.output.fileoutputformat.compress true;
SET mapred.map.output.compress.codec org.apache.hadoop.io.compress.SnappyCodec;
SET mapreduce.map.output.fileoutputformat.compress.type BLOCK;

register /usr/lib/pig/piggybank.jar;
register /data/replica_dumps/rucioudfs.jar;

dump_reps = LOAD 'replica_dumps/replicas_DATE' USING PigStorage('\t') AS (
    rse_id: chararray,
    scope: chararray,
    dsn: chararray,
    checksum: chararray,
    fsize: chararray,
    creationdate: chararray,
    path: chararray
);

dump_rses = LOAD 'replica_dumps/rses_DATE' USING PigStorage('\t') AS (
    rse_id: chararray,
    rse: chararray
);

replicas = FOREACH dump_reps GENERATE TRIM(rse_id) as rse_id, TRIM(scope) as scope, TRIM(dsn) as dsn, TRIM(checksum) as checksum, TRIM(fsize) as fsize, TRIM(creationdate) as creationdate, TRIM(path) as path;

filter_det = FILTER replicas BY path is null;

filter_nondet = FILTER replicas BY path is not null;

get_path = FOREACH filter_det GENERATE rse_id, scope, dsn, checksum, fsize, creationdate, rucioudfs.GETPATH(scope, dsn) as path;

union_det_nondet = UNION get_path, filter_nondet;

rses = FOREACH dump_rses GENERATE rse_id, rse;

join_reps_rses = JOIN union_det_nondet BY rse_id, rses BY rse_id;

joined_output = FOREACH join_reps_rses GENERATE rses::rse, union_det_nondet::scope, union_det_nondet::dsn, union_det_nondet::checksum, union_det_nondet::fsize, union_det_nondet::creationdate, union_det_nondet::path;

STORE joined_output INTO 'replica_dumps/replicas_per_rse/DATE' USING org.apache.pig.piggybank.storage.MultiStorage('replica_dumps/replicas_per_rse/DATE', '0', 'bz2', '\\t');
