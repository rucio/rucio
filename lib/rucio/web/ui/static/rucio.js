/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2015
 * - Martin Barisits, <martin.barisits@cern.ch>, 2014
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2015
 */

/* --- base Rucio client class definition --- */
function RucioClient(token, account) {
    this.token = token;
    this.account = account;
    host = window.location.host;
    this.url = 'https://' + host + ':443/proxy';
    this.authurl = 'https://' + host + ':443/ui/auth';
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

/* request rucio auth token with x509 certificate */
RucioClient.prototype.get_auth_token_x509 = function(options) {
    jQuery.ajax({url: this.authurl,
                 crossDomain: true,
                 headers: {'X-Rucio-Account': options.account },
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

/* list all identities for an account */
RucioClient.prototype.list_dids = function(options) {
    var url = this.url + '/dids/' + options.scope + '/dids/search';
    url += "?name=" + options.name;
    if (options.type == "container") {
        url += "&type=container";
    } else {
        url += "&type=dataset";
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


/* list all accounts */
RucioClient.prototype.list_accounts = function(options) {
    var url = this.url + '/accounts';
    if (options.async == null ) {options.async = true;}
    if (options.account_type != null) {
        url += '?account_type=' + options.account_type;
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
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
    jQuery.ajax({url: this.url + '/accounts/' + options.account + '/limits',
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
                 data: JSON.stringify({'dids': options.dids,
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


/* get list of RSE usage per account */
RucioClient.prototype.get_rse_account_usage = function(options) {
    var url = this.url + '/rses/' + options.rse + '/accounts/usage';
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


/* get current space usage for an RSE */
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

/* list attributes for an RSE */
RucioClient.prototype.list_rse_attributes = function(options) {
    var url = this.url + '/rses/' + options.rse + '/attr/';
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

/* list space usage history for an RSE from dumps */
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
    if (options.async == null) {
        options.async = true;
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
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
    var url = this.url + '/rules/' + options.rule_id;
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

/* show replication rule */
RucioClient.prototype.delete_replication_rule = function(options) {
    var url = this.url + '/rules/' + options.rule_id;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': this.token,
                           'X-Rucio-Account': this.account },
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

/* get account usage */
RucioClient.prototype.get_account_usage = function(options) {
    var url = this.url + '/accounts/' + options.account + '/usage/';
    if (options.rse) {
        url += options.rse;
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


/* list space usage and quota of GROUPDISK from dumps */
RucioClient.prototype.get_account_usage_from_dumps = function(options) {
    var url = this.dumps + '/account_usage.lst';
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
        if (options.state == 'RECOVERED'){
            url += 'state=R&';
        }
        if (options.state == 'BAD'){
            url += 'state=B&';
        }
        if ($.inArray(options.state, ['S', 'D', 'B', 'R']) > -1){
            url += 'state=' + options.state + '&';
        }
    }
    if (options.rse != "" && options.rse != undefined) {
        url += 'rse=' + options.rse + '&';
    }
    if (options.state != "" || options.rse != "") {
        url = url.slice(0, -1);
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


/* get the bad and suspicious files summary table */
RucioClient.prototype.get_bad_replicas_summary = function(options) {
    var url = this.url + '/replicas/bad/summary/';
    var baseurl = this.url + '/replicas/bad/summary/';
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
    dt = $('#badreplicasummary').DataTable();

    var from_date = new Date(2015, 0, 1);
    var to_date = new Date();
    $("#datepicker1").datepicker({
                                      defaultDate: from_date,
                                      onSelect: function(){
                                          from_date = $("#datepicker1").val();
                                          console.log(from_date);
                                      }
                                 });
    $("#datepicker2").datepicker({
                                      defaultDate: to_date,
                                      onSelect: function(){
                                          to_date = $("#datepicker2").val();
                                          console.log(to_date);
                                      }
                                 });
    var token = this.token;
    var account = this.account;
    $("#submit_button").click(function(){
        dt.destroy();
        var date_array = from_date.toString().split('/');
        if (date_array.length == 3){
            from_date = date_array[2] + '-' + date_array[0] + '-' + date_array[1];
        }
        else if (typeof from_date != 'string'){
                 from_date = from_date.toISOString().slice(0, 10);
             }
        date_array = to_date.toString().split('/');
        if (date_array.length == 3){
            to_date = date_array[2] + '-' + date_array[0] + '-' + date_array[1];
        }
        else if (typeof to_date != 'string'){
                 to_date = to_date.toISOString().slice(0, 10);
             }
        url = baseurl + '?from_date=' + from_date + '&to_date=' + to_date;
        jQuery.ajax({url: url,
                     crossDomain: true,
                     headers: {'X-Rucio-Auth-Token': token,
                               'X-Rucio-Account': account },
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
    });
    dt.destroy();
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

