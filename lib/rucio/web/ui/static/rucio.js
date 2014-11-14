/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
 * - Martin Barisits, <martin.barisits@cern.ch>, 2014
 */

/* --- base Rucio client class definition --- */
function RucioClient(token, account) {
    this.token = token;
    this.account = account;
    this.url = 'https://rucio-lb-prod.cern.ch:443';
    this.dumps = '//rucio-hadoop.cern.ch/dumps';
};

/* --- utility function --- */

parse_json_stream = function(data) {
    var split_data = data.split('\n');
    var ret_data = [];
    for (var i = 0; i < split_data.length; i++) {
        if (split_data[i].length <= 0) {
            break;
        }
        ret_data.push(JSON.parse(split_data[i]));
    }
    return ret_data;
};


/* --- rucio client methods --- */

/* get the server version */
RucioClient.prototype.ping = function(options) {
    jQuery.ajax({url: this.url + '/ping',
                 crossDomain: true,
                 success: function(data)
                 {
                     options.success(data);
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* list all scopes */
RucioClient.prototype.list_scopes = function(options) {
    jQuery.ajax({url: this.url + '/scopes/',
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 success: function(data)
                 {
                     options.success(data);
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* list all identities for an account */
RucioClient.prototype.list_identities = function(options) {
    jQuery.ajax({url: this.url + '/accounts/' + options.account + '/identities',
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* list all dids for a scope */
RucioClient.prototype.scope_list = function(options) {
    var url = this.url + '/dids/' + options.scope + '/';
    if ('name' in options || 'recursive' in options) {
        url += '?name=' + options.name;
    };
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* list all subscriptions for an account */
RucioClient.prototype.list_subscriptions = function(options) {
    var url = this.url + '/subscriptions/' + options.account + '/';
    if (options.name) {
        url += options.name;
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* list all subscriptions for an account */
RucioClient.prototype.list_replication_rules = function(options) {
    var url = this.url + '/subscriptions/' + options.account + '/' + options.name + '/Rules';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* list all subscriptions for an account */
RucioClient.prototype.list_subscription_rules_state = function(options) {
    var url = this.url + '/subscriptions/' + options.account + '/' + options.name + '/Rules/States';
    if (options.async == null ) {options.async = true;}
    jQuery.ajax({url: url,
                 crossDomain: true,
                 async: options.async,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* list all subscriptions from dumps */
RucioClient.prototype.list_subscription_rules_state_from_dumps = function(options) {
    var url = this.dumps + '/subscription_states/' + options.date + '/' + options.hour + options.minutes + '.lst';
    jQuery.ajax({url: url,
                 async: false,
                 crossDomain: true,
                 success: function(data)
                 {
                     options.success(data);
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
                });
};

/* Create a new rule for an account */
RucioClient.prototype.create_rule = function(options) {
    var url = this.url + '/rules/';
    if (options.weight == '') { options.weight = null; };
    if (options.lifetime == '') { options.lifetime = null; };
    if (options.source_replica_expression == '') { options.source_replica_expression = null; };
    jQuery.ajax({url: url,
                 crossDomain: true,
                 type: 'POST',
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 data: JSON.stringify({'dids': [{'scope': options.scope, 'name': options.name}],
                                       'account': this.account,
                                       'rse_expression': options.rse_expression,
                                       'copies': parseInt(options.copies),
                                       'grouping': options.grouping,
                                       'weight': options.weight,
                                       'lifetime': parseInt(options.lifetime),
                                       'source_replica_expression': options.source_replica_expression}),
                 dataType: 'json',
                 success: function(data)
                 {
                     options.success(data);
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* list replication rules */
RucioClient.prototype.list_replication_rules = function(options) {
    var url = this.url + '/subscriptions/' + options.account + '/' + options.name + '/Rules?state=' + options.state;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* list all RSEs in the system */
RucioClient.prototype.list_rses = function(options) {
    var url = this.url + '/rses/';
    if (options.expression) {
        url += '?expression=' + encodeURIComponent(options.expression);
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* get current space usage for RSE */
RucioClient.prototype.get_rse_usage = function(options) {
    var url = this.url + '/rses/' + options.rse + '/usage';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* list space usage history for RSE */
RucioClient.prototype.list_rse_usage_history = function(options) {
    var url = this.url + '/rses/' + options.rse + '/usage/history';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
                });
};

/* list space usage history for RSE */
RucioClient.prototype.list_rse_usage_history_from_dumps = function(options) {
    var url = this.dumps + '/rse_usage/' + options.rse;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 success: function(data)
                 {
                     options.success(data);
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
                });
};

/* list all lock states per RSE from dumps */
RucioClient.prototype.get_rse_lock_states_from_dumps = function(options) {
    var url = this.dumps + '/rse_locks/' + options.date + '/' + options.hour + '.lst';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 async: false,
                 success: function(data)
                 {
                     options.success(data);
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
                });
};

/* show DID metadata */
RucioClient.prototype.did_get_metadata = function(options) {
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/meta';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'json',
                 success: function(data)
                 {
                     options.success(data);
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* show DID files */
RucioClient.prototype.did_get_files = function(options) {
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/files';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* show DID replicas*/
RucioClient.prototype.list_replicas = function(options) {
    var url = this.url + '/replicas/list/';
    if (options.async == null) {
        options.async = true;
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 type: 'POST',
                 data: JSON.stringify({'dids': [{'scope': options.scope, 'name': options.name}], 'unavailable': true, 'all_states': true }),
                 async: options.async,
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* list all rules of a DID */
RucioClient.prototype.did_get_rules = function(options) {
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/rules';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* show replication rule */
RucioClient.prototype.list_replication_rule = function(options) {
    var url = this.url + '/rules/' + '/' + options.rule_id;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'json',
                 success: function(data)
                 {
                     options.success(data);
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* get all locks and their states for a rule id */
RucioClient.prototype.get_replica_lock_for_rule_id = function(options) {
    var url = this.url + '/rules/' + options.rule_id + '/locks';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'text',
                 success: function(data)
                 {
                     options.success(parse_json_stream(data));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* get request by did */
RucioClient.prototype.get_request_by_did = function(options) {
    var url = this.url + '/requests/' + options.scope + '/' + options.name + '/' + options.rse;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'json',
                 success: function(data)
                 {
                     options.success(data);
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* get subscription by id */
RucioClient.prototype.get_subscription_by_id = function(options) {
    var url = this.url + '/subscriptions/Id/' + options.id;
    if (options.async == null) {
        options.async = true;
    }
    jQuery.ajax({url: url,
                 async: options.async,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
                 dataType: 'json',
                 success: function(data)
                 {
                     options.success(data);
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};
