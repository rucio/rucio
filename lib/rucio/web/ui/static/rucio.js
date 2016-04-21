/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014-2015
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2016
 * - Martin Barisits, <martin.barisits@cern.ch>, 2014
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2015
 */

/* --- base Rucio client class definition --- */
function RucioClient(token, account) {
    this.token = token;
    this.account = account;
    this.script = 'webui::' + window.location.pathname.replace(/\//g, '-');
    this.headers = {'X-Rucio-Auth-Token': this.token,
                    'X-Rucio-Account': this.account,
                    'X-Rucio-Script': this.script}
    host = window.location.host;
    this.url = 'https://' + host + ':443/proxy';
    this.authurl = 'https://' + host + ':443/auth';
    this.dumps = 'https://' + host + ':443/dumpsproxy';
};

/* --- utility function --- */

parse_json_stream = function(data) {
    var split_data = data.split('\n');
    var ret_data = [];
    for (var i = 0; i < split_data.length; i++) {
        if (split_data[i].length <= 0) {
            break;
        }
        ret_data.push(JSON.parse(split_data[i].replace(/Infinity/g, "-1")));
    }
    return ret_data;
};


/* --- rucio client methods --- */

/* get the server version */
RucioClient.prototype.ping = function(options) {
    jQuery.ajax({url: this.url + '/ping',
                 headers: {'X-Rucio-Script': this.script},
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

/* request rucio auth token with x509 certificate */
RucioClient.prototype.get_auth_token_x509 = function(options) {
    jQuery.ajax({url: this.authurl,
                 crossDomain: true,
                 headers: {'X-Rucio-Account': options.account,
                           'X-Rucio-Script': this.script},
                 success: function(data, textStatus, jqXHR)
                 {
                     options.success(data, textStatus, jqXHR);
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
                 headers: this.headers,
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

/* list all identities for an account */
RucioClient.prototype.list_dids = function(options) {
    var url = this.url + '/dids/' + options.scope + '/dids/search';
    url += "?name=" + options.name;
    if (options.type == "container") {
        url += "&type=container";
    } else if (options.type == "collection") {
        url += "&type=collection";
    } else if (options.type == "file") {
        url += "&type=file";
    } else {
        url += "&type=dataset";
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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


/* list all accounts */
RucioClient.prototype.list_accounts = function(options) {
    var url = this.url + '/accounts';
    if (options.async == null ) {options.async = true;}
    if (options.account_type != null) {
        url += '?account_type=' + options.account_type;
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 dataType: 'text',
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

/* get limits for an account */
RucioClient.prototype.get_account_limits = function(options) {
    if (options.async == null) { options.async = true; }
    jQuery.ajax({url: this.url + '/accounts/' + options.account + '/limits',
                 crossDomain: true,
                 headers: this.headers,
                 dataType: 'text',
                 async: options.async,
                 success: function(data)
                 {
                     options.success(JSON.parse(data.replace(/Infinity/g, "-1")));
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

RucioClient.prototype.list_rules = function(options) {
    url = this.url + '/rules/';
    if (options.activity != "" || options.state != "" || options.rse_expression != "" || options.account != "") {
        url += "?";
    }

    if (options.account != "") {
        url += 'account=' + options.account + '&';
    }

    if (options.created_after != "") {
        url += 'created_after=' + options.created_after + '&';
    }

    if (options.created_before != "") {
        url += 'created_before=' + options.created_before + '&';
    }

    if (options.activity != "") {
        url += 'activity=' + options.activity + '&';
    }
    if (options.rse_expression != "") {
        url += 'rse_expression=' + options.rse_expression + '&';
    }
    if (options.state != "") {
        url += 'state=' + options.state + '&';
    }

    if (options.activity != "" || options.state != "" || options.rse_expression != "" || options.account != "") {
        url = url.slice(0, -1);
    }

    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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


/* list all rules for an account */
RucioClient.prototype.list_account_rules = function(options) {
    url = this.url + '/accounts/' + options.account + '/rules';
    if (options.activity != "" || options.state != "" || options.rse_expression != "") {
        url += "?";
    }

    if (options.activity != "") {
        url += 'activity=' + options.activity + '&';
    }
    if (options.rse_expression != "") {
        url += 'rse_expression=' + options.rse_expression + '&';
    }
    if (options.state != "") {
        url += 'state=' + options.state + '&';
    }

    if (options.activity != "" || options.state != "" || options.rse_expression != "") {
        url = url.slice(0, -1);
    }

    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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
                 headers: this.headers,
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
                 headers: this.headers,
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
                 headers: this.headers,
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
                 headers: this.headers,
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
                 headers: {'X-Rucio-Script': this.script},
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
                 headers: this.headers,
                 data: JSON.stringify({
                     'dids': options.dids,
                     'account': this.account,
                     'ask_approval': options.ask_approval,
                     'activity': options.activity,
                     'rse_expression': options.rse_expression,
                     'copies': parseInt(options.copies),
                     'grouping': options.grouping,
                     'weight': options.weight,
                     'lifetime': parseInt(options.lifetime),
                     'source_replica_expression': options.source_replica_expression,
                     'comment': options.comment,
                     'asynchronous': options.asynchronous
                 }),
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
                 headers: this.headers,
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
                 headers: this.headers,
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

/* get details of an RSE */
RucioClient.prototype.get_rse = function(options) {
    var url = this.url + '/rses/' + options.rse;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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

/* get list of RSE usage per account */
RucioClient.prototype.get_rse_account_usage = function(options) {
    var url = this.url + '/rses/' + options.rse + '/accounts/usage';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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


/* get current space usage for an RSE */
RucioClient.prototype.get_rse_usage = function(options) {
    var url = this.url + '/rses/' + options.rse + '/usage';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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

/* list attributes for an RSE */
RucioClient.prototype.list_rse_attributes = function(options) {
    var url = this.url + '/rses/' + options.rse + '/attr/';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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

/* list space usage history for an RSE from dumps */
RucioClient.prototype.list_rse_usage_history_from_dumps = function(options) {
    var url = this.dumps + '/rse_usage/' + options.rse;
    jQuery.ajax({url: url,
                 headers: {'X-Rucio-Script': this.script},
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
                 headers: {'X-Rucio-Script': this.script},
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
    if (options.async == null) {
        options.async = true;
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 dataType: 'json',
                 async: options.async,
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
                 headers: this.headers,
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


/* List DID parents */
RucioClient.prototype.list_parent_dids = function(options) {
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/parents';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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


/* returns the DID contents */
RucioClient.prototype.list_contents = function(options) {
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/dids';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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
    data = {'dids': [{'scope': options.scope, 'name': options.name}], 'unavailable': true, 'all_states': true }
    if (options.schemes != null) {
        data['schemes'] = options.schemes;
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 dataType: 'text',
                 type: 'POST',
                 data: JSON.stringify(data),
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
                 headers: this.headers,
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
    var url = this.url + '/rules/' + options.rule_id;
    if (options.async == null ) {options.async = true;}
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 async: options.async,
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

/* update rule */
RucioClient.prototype.update_replication_rule = function(options) {
    var url = this.url + '/rules/' + options.rule_id;
    if (options.async == null) {
        options.async = true;
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 async: options.async,
                 data: JSON.stringify({'options': options.params }),
                 type: 'PUT',
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

/* show replication rule */
RucioClient.prototype.delete_replication_rule = function(options) {
    var url = this.url + '/rules/' + options.rule_id;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 type: 'DELETE',
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
                 headers: this.headers,
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

/* get account usage */
RucioClient.prototype.get_account_usage = function(options) {
    var url = this.url + '/accounts/' + options.account + '/usage/';
    if (options.rse) {
        url += options.rse;
    }
    if (options.async == null) {
        options.async = true;
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 dataType: 'text',
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

/* get request by did */
RucioClient.prototype.get_request_by_did = function(options) {
    var url = this.url + '/requests/' + options.scope + '/' + options.name + '/' + options.rse;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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
                 headers: this.headers,
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


/* list space usage and quota of GROUPDISK from dumps */
RucioClient.prototype.get_account_usage_from_dumps = function(options) {
    var url = this.dumps + '/account_usage.lst';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Script': this.script},
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

/* get the bad and suspicious files */
RucioClient.prototype.get_bad_replicas = function(options) {
    var url = this.url + '/replicas/bad/states/';
    if (options.state != "" || options.rse != "") {
        url += "?";
    }
    if (options.state != "" && options.state != undefined) {
        if (options.state == 'SUSPICIOUS'){
             url += 'state=S&';
        }
        if (options.state == 'DELETED'){
            url += 'state=D&';
        }
        if (options.state == 'LOST'){
            url += 'state=L&';
        }
        if (options.state == 'RECOVERED'){
            url += 'state=R&';
        }
        if (options.state == 'BAD'){
            url += 'state=B&';
        }
        if ($.inArray(options.state, ['S', 'D', 'L', 'B', 'R']) > -1){
            url += 'state=' + options.state + '&';
        }
    }
    if (options.rse != "" && options.rse != undefined) {
        url += 'rse=' + options.rse + '&';
    }
    if (options.list_pfns != ""  && options.list_pfns !=undefined) {
        url += 'list_pfns=true&';
    }
    if (options.state != "" || options.rse != "") {
        url = url.slice(0, -1);
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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


/* get the bad and suspicious files summary table */
RucioClient.prototype.get_bad_replicas_summary = function(options) {
    var url = this.url + '/replicas/bad/summary/';
    if (options.rse_expression != "" || options.from_date != "" || options.to_date != "") {
        url += "?";
    }
    if (options.rse_expression != "" && options.rse_expression != undefined) {
        url += 'rse_expression=' + options.rse_expression +'&';
    }
    if (options.from_date != "" && options.from_date != undefined) {
        url += 'from_date=' + options.from_date + '&';
    }
    if (options.to_date != "" && options.to_date != undefined) {
        url += 'to_date=' + options.to_date + '&';
    }
    if (options.rse_expression != "" || options.from_date != "" || options.to_date != "") {
        url = url.slice(0, -1);
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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

/* list all heartbeats */
RucioClient.prototype.list_heartbeats = function(options) {
    var url = this.url + '/heartbeats';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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

/* retrieve a singel data identifier */
RucioClient.prototype.get_did = function(options) {
    var url = this.url + '/dids/' + options.scope + '/' + options.name;
    if (options.dynamic) {
        url += '?dynamic=' + options.dynamic;
    }
    if (options.async == null) {
        options.async = true;
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 dataType: 'json',
                 async: options.async,
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

/* get dbreleases from dumps */
RucioClient.prototype.get_dbreleases_from_dumps = function(options) {
    var url = this.dumps + '/ddo.json';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Script': this.script},
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

/* get cond from dumps */
RucioClient.prototype.get_cond_from_dumps = function(options) {
    var url = this.dumps + '/cond.json';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Script': this.script},
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
RucioClient.prototype.get_scopes = function(options) {
    if (options.async == null ) {options.async = true;}
    jQuery.ajax({url: this.url + '/accounts/' + options.account + '/scopes/',
                 crossDomain: true,
                 headers: this.headers,
                 async: options.async,
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

/* Create a new did with a random sample from the original did */
RucioClient.prototype.create_did_sample = function(options) {
    var url = this.url + '/dids/' + options.input_scope + '/' + options.input_name + '/' + options.output_scope + '/' + options.output_name + '/' + options.nbfiles + '/sample';
    if (options.async == null) {
        options.async = true;
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 type: 'POST',
                 async: options.async,
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

/* Set metadata for a DID */
RucioClient.prototype.set_metadata = function(options) {
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/meta/' + options.key;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 type: 'POST',
                 headers: this.headers,
                 data: JSON.stringify({'value': options.value}),
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

/* Set DID status */
RucioClient.prototype.set_status = function(options) {
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/status';
    if (options.async == null ) {options.async = true;}
    jQuery.ajax({url: url,
                 crossDomain: true,
                 type: 'PUT',
                 headers: this.headers,
                 data: JSON.stringify({'open': options.open}),
                 dataType: 'text',
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

/* get account information */
RucioClient.prototype.get_account_info = function(options) {
    var url = this.url + '/accounts/' + options.account;
    if (options.async == null ) {options.async = true;}
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 dataType: 'json',
                 async: options.async,
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

/* get account attributes */
RucioClient.prototype.list_account_attributes = function(options) {
    var url = this.url + '/accounts/' + options.account + '/attr/';
    if (options.async == null ) {options.async = true;}
    jQuery.ajax({url: url,
                 async: options.async,
                 crossDomain: true,
                 headers: this.headers,
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

/* list dataset replicas */
RucioClient.prototype.list_dataset_replicas = function(options) {
    var url = this.url + '/replicas/' + options.scope + '/' + options.name + '/datasets';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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

/* update quota for account on an RSE */
RucioClient.prototype.set_account_limit = function(options) {
    var url = this.url + '/accountlimits/' + options.account + '/' + options.rse;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 type: 'POST',
                 dataType: 'text',
                 data: JSON.stringify({'bytes': options.bytes}),
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

/* add data identifier */
RucioClient.prototype.add_did = function(options) {
    var url = this.url + '/dids/' + options.scope + '/' + options.name;
    jQuery.ajax({url: url,
                 async: options.async,
                 crossDomain: true,
                 headers: this.headers,
                 type: 'POST',
                 dataType: 'text',
                 data: JSON.stringify({'type': options.type}),
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

/* attach dids */
RucioClient.prototype.attach_dids = function(options) {
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/dids';
    jQuery.ajax({url: url,
                 async: options.async,
                 crossDomain: true,
                 headers: this.headers,
                 type: 'POST',
                 dataType: 'text',
                 data: JSON.stringify({'dids': options.dids}),
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

/* add rse attribute */
RucioClient.prototype.add_rse_attribute = function(options) {
    var url = this.url + '/rses/' + options.rse + '/attr/' + options.key;
    if (options.async == null ) {options.async = true;}
    jQuery.ajax({
        url: url,
        async: options.async,
        crossDomain: true,
        headers: this.headers,
        type: 'POST',
        dataType: 'text',
        data: JSON.stringify({'value': options.value}),
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

/* delete rse attribute */
RucioClient.prototype.delete_rse_attribute = function(options) {
    var url = this.url + '/rses/' + options.rse + '/attr/' + options.key;
    if (options.async == null ) {options.async = true;}
    jQuery.ajax({
        url: url,
        async: options.async,
        crossDomain: true,
        headers: this.headers,
        type: 'DELETE',
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
