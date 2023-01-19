/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014-2015
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2017
 * - Martin Barisits, <martin.barisits@cern.ch>, 2014
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2015-2019
 * - Stefan Prenner, <stefan.prenner@cern.ch>, 2018
 */

/* --- base Rucio client class definition --- */

function RucioClient(token, account, vo) {
    this.token = token;
    this.account = account;
    this.vo = vo;
    this.script = 'webui::' + window.location.pathname.replace(/\//g, '-');
    this.headers = {'X-Rucio-Auth-Token': this.token,
                    'X-Rucio-Account': this.account,
                    'X-Rucio-VO': this.vo,
                    'X-Rucio-Script': this.script}
    host = window.location.host;
    this.url = 'https://' + host + '/proxy';
    this.authurl = 'https://' + host + '/auth';
    if (window.location.href.includes('/ui/')){
        this.authurl = 'https://' + host + '/ui/auth';
    }
    this.dumps = 'https://' + host + '/dumpsproxy';
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

/* check if current token is expired - older than 1h and, if so, request a new one */
check_token = function() {
    token_created_at = parseInt($.cookie('rucio-auth-token-created-at'));
    current_time = parseInt((new Date).getTime()/1000);

    time_diff = current_time - token_created_at;
    /* a bit less than a full hour to be on the safe side */
    if (time_diff > 3500) {
        if ($.cookie('x-rucio-auth-type') != 'x509'){
            $.cookie('x-rucio-auth-token', "", { expires: -1 });
            $.cookie('rucio-requested-path', window.location.href, { expires: 120 , path: '/'});
            if (window.location.href.includes('/ui/')){
                window.location.href = 'https://' + window.location.host + '/ui/auth';
            } else {
                window.location.href = 'https://' + window.location.host + '/auth';
            }
        } else {
            r.get_auth_token_x509({
                account: this.account,
                vo: this.vo,
                async: false,
                success: function(data, textStatus, jqXHR) {
                    r.token = jqXHR.getResponseHeader('X-Rucio-Auth-Token');
                    r.headers['X-Rucio-Auth-Token'] = r.token;
                    $.cookie('x-rucio-auth-token', r.token, { path: '/' });
                    $.cookie('rucio-auth-token-created-at', current_time, { path: '/'})
                }
            });
        }
    }
};

/* --- rucio rest client methods --- */

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
    if (options.async == null) { options.async = true; }
    jQuery.ajax({url: this.authurl,
                 crossDomain: true,
                 headers: {'X-Rucio-Account': options.account,
                           'X-Rucio-VO': this.vo,
                           'X-Rucio-Script': this.script},
                 async: options.async,
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
    check_token();
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
    check_token();
    jQuery.ajax({url: this.url + '/accounts/' + options.account + '/identities',
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

/* add identity to an account */
RucioClient.prototype.add_identity = function(options) {
    check_token();
    var url = this.url + '/accounts/' + options.account + '/identities';
    if (options.async == null) { options.async = true; }
    console.log(options);
    jQuery.ajax({url: url,
                 async: options.async,
                 crossDomain: true,
                 headers: this.headers,
                 type: 'POST',
                 dataType: 'text',
                 data: JSON.stringify({'identity': options.identity,
                                       'authtype': options.authtype,
                                       'email': options.email}),
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

/* delete identity association from account */
RucioClient.prototype.del_identity = function(options) {
    check_token();
    var url = this.url + '/accounts/' + options.account + '/identities';
    if (options.async == null) { options.async = true; }
    console.log(options);
    jQuery.ajax({url: url,
                 async: options.async,
                 crossDomain: true,
                 headers: this.headers,
                 type: 'DELETE',
                 dataType: 'text',
                 data: JSON.stringify({'identity': options.identity,
                                       'authtype': options.authtype,
                                       'default': options.default}),
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

/* add an attribute to an account */
RucioClient.prototype.add_account_attribute = function(options) {
    check_token();
    var url = this.url + '/accounts/' + options.account + '/attr/' + options.key;
    if (options.async == null) { options.async = true; }
    console.log(options);
    jQuery.ajax({url: url,
                 async: options.async,
                 crossDomain: true,
                 headers: this.headers,
                 type: 'POST',
                 dataType: 'text',
                 data: JSON.stringify({'key': options.key,
                                       'value': options.value}),
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

/* delete account attribute */
RucioClient.prototype.delete_account_attribute = function(options) {
    check_token();
    var url = this.url + '/accounts/' + options.account + '/attr/' + options.key;
    if (options.async == null) { options.async = true; }
    console.log(options);
    jQuery.ajax({url: url,
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


/* list dids */
RucioClient.prototype.list_dids = function(options) {
    check_token();
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
    check_token();
    var url = this.url + '/accounts';
    if (options.async == null ) { options.async = true; }
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
    check_token();
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
    check_token();
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
    check_token();
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
    check_token();
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
    check_token();
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
    check_token();
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
    check_token();
    var url = this.url + '/subscriptions/' + options.account + '/' + options.name + '/Rules/States';
    if (options.async == null ) { options.async = true; }
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

/* Create a new rule for an account */
RucioClient.prototype.create_rule = function(options) {
    check_token();
    var url = this.url + '/rules/';
    if (options.weight == '') { options.weight = null; };
    if (options.lifetime == '') { options.lifetime = null; };
    if (options.source_replica_expression == '') { options.source_replica_expression = null; };
    if (options.nofity == '') { options.notify = null; };
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
                     'asynchronous': options.asynchronous,
                     'notify': options.notify
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
    check_token();
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
    check_token();
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
    check_token();
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

/* add RSE */
RucioClient.prototype.add_rse = function(rse, options) {
    check_token();
    var url = this.url + '/rses/' + rse;
    jQuery.ajax({url: url,
                 data: JSON.stringify(options.values),
                 crossDomain: true,
                 headers: this.headers,
                 contentType: 'application/json',
                 type: 'POST',
                 success: function(data, textStatus, jqXHR)
                 {
                     options.success(data);
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
        });
};

/* delete RSE */
RucioClient.prototype.delete_rse = function(options) {
    check_token();
    var url = this.url + '/rses/' + options.rse;
    jQuery.ajax({url: url,
                 type: 'DELETE',
                 crossDomain: true,
                 headers: this.headers,
                 success: function(data, textStatus, jqXHR)
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
    check_token();
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
    check_token();
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
    check_token();
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

/* delete RSE protocol */
RucioClient.prototype.delete_rse_protocol = function(options) {
    check_token();
    var url = this.url + '/rses/' + options.rse + '/protocols/' + options.scheme + '/' + options.hostname + '/' + options.port;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 dataType: 'text',
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

/* delete RSE protocol */
RucioClient.prototype.add_rse_protocol = function(options) {
    check_token();
    var url = this.url + '/rses/' + options.rse + '/protocols/' + options.scheme;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 contentType: 'application/json',
                 type: 'POST',
                 data: JSON.stringify({
                    'hostname': options.hostname,
                    'port': options.port,
                    'impl': options.implementation,
                    'prefix': options.prefix,
                    'domains': options.domains,
                    'extended_attributes': options.extended_attributes
                 }),
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

/* show available metadata */
RucioClient.prototype.show_metadata = function(options) {
    var url = this.url + '/meta/';
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

/* show DID metadata */
RucioClient.prototype.did_get_metadata = function(options) {
    check_token();
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/meta';
    if (options.async == null) { options.async = true; }
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

/* show generic DID metadata */
RucioClient.prototype.did_get_generic_metadata = function(options) {
    check_token();
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/did_meta';
    if (options.async == null) { options.async = true; }
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
    check_token();
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
    check_token();
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
    check_token();
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
    check_token();
    var url = this.url + '/replicas/list/';
    if (options.async == null) { options.async = true; }
    data = {'dids': [{'scope': options.scope, 'name': options.name}], 'unavailable': true, 'all_states': true, 'ignore_availability': true}
    if (options.schemes != null) {
        data['schemes'] = options.schemes;
    }
    if (options.browser_enabled) {
        data['rse_expression'] = 'browser_enabled=1';
    }
    var t_header = $.extend({}, this.headers);
    if(options.meta) {
        t_header['Accept'] = 'application/metalink4+xml';
    }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: t_header,
                 dataType: 'text',
                 type: 'POST',
                 data: JSON.stringify(data),
                 async: options.async,
                 success: function(data)
                 {
                     if(options.meta){
                         options.success(data);
                     } else {
                         options.success(parse_json_stream(data));
                     }
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown);
                 }
                });
};

/* list all rules of a DID */
RucioClient.prototype.did_get_rules = function(options) {
    check_token();
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
    check_token();
    var url = this.url + '/rules/' + options.rule_id;
    if (options.async == null ) { options.async = true; }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 async: options.async,
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

/* update rule */
RucioClient.prototype.update_replication_rule = function(options) {
    check_token();
    var url = this.url + '/rules/' + options.rule_id;
    if (options.async == null) { options.async = true; }
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
    check_token();
    var url = this.url + '/rules/' + options.rule_id;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 type: 'DELETE',
                 data: JSON.stringify({'purge_replicas': options.purge_replicas}),
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
    check_token();
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

/* get detailed information for stuck locks */
RucioClient.prototype.examine_rule = function(options) {
    check_token();
    var url = this.url + '/rules/' + options.rule_id + '/analysis';
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

/* get account usage */
RucioClient.prototype.get_account_usage = function(options) {
    check_token();
    var url = this.url + '/accounts/' + options.account + '/usage/';
    if (options.rse) { url += options.rse; }
    if (options.async == null) { options.async = true; }
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
    check_token();
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
    check_token();
    var url = this.url + '/subscriptions/Id/' + options.id;
    if (options.async == null) { options.async = true; }
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

/* Update an existing subscription */
RucioClient.prototype.update_subscription = function(options) {
    var url = this.url + '/subscriptions/' + options.account + '/' + options.name;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
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


/* Create a subscription */
RucioClient.prototype.create_subscription = function(options) {
    var url = this.url + '/subscriptions/' + options.account + '/' + options.name;
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 data: JSON.stringify({'options': options.params}),
                 type: 'POST',
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


/* Create a new Lifetime Model exception */
RucioClient.prototype.create_lifetime_exception = function(options) {
    var url = this.url + '/lifetime_exceptions/';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 type: 'POST',
                 headers: this.headers,
                 data: JSON.stringify({
                     'dids': options.dids,
                     'account': this.account,
                     'pattern': options.pattern,
                     'comments': options.comments,
                     'expires_at': options.expires_at
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


/* List Lifetime Model exceptions */
RucioClient.prototype.list_lifetime_exceptions = function(options) {
    var url = this.url + '/lifetime_exceptions/';
    jQuery.ajax({url: url,
                 crossDomain: true,
                 type: 'GET',
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


/* get the bad and suspicious files */
RucioClient.prototype.get_bad_replicas = function(options) {
    check_token();
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
    check_token();
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

/* get the suspicious files summary */
RucioClient.prototype.get_suspicious_files = function(options) {
    //check_token();
    var url = this.url + '/replicas/suspicious/';
    if (options.rse_expression != "" || options.younger_than != "" || options.nattempts != "") {
        url += "?";
    }
    if (options.rse_expression != "" && options.rse_expression != undefined) {
        url += 'rse_expression=' + options.rse_expression +'&';
    }
    if (options.younger_than != "" && options.younger_than != undefined) {
        url += 'younger_than=' + options.younger_than + '&';
    }
    if (options.nattempts != "" && options.nattempts != undefined) {
        url += 'nattempts=' + options.nattempts + '&';
    }
    if (options.rse_expression != "" || options.from_date != "" || options.to_date != "") {
        url = url.slice(0, -1);
    }
    console.log(url);
    console.log(this.headers);
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 dataType: 'json',
                 type: 'GET',
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

/* Declare bad PFNs */
RucioClient.prototype.declare_bad_pfns = function(options) {
    //check_token();
    var url = this.url + '/replicas/bad/pfns/';
    if (options.pfns == '') { options.pfns = []; };
    if (options.reason == '') { options.reason = 'LOST'; };
    if (options.state == '') { options.state = null; };
    if (options.expires_at == '') { options.expires_at = null; };
    console.log(url);
    console.log(this.headers);
    console.log(options);
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 type: 'POST',
                 dataType: 'text',
                 data: JSON.stringify({
                     'pfns' : options.pfns,
                     'reason': options.reason,
                     'state': options.state,
                     'expires_at': options.expires_at
                 }),
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

/* list all heartbeats */
RucioClient.prototype.list_heartbeats = function(options) {
    check_token();
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
    check_token();
    var url = this.url + '/dids/' + options.scope + '/' + options.name;
    if (options.dynamic) { url += '?dynamic=' + options.dynamic; }
    if (options.async == null) { options.async = true; }
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

/* list all scopes */
RucioClient.prototype.get_scopes = function(options) {
    check_token();
    if (options.async == null ) { options.async = true; }
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
    check_token();
    var url = this.url + '/dids/sample';
    if (options.async == null) { options.async = true; }
    jQuery.ajax({url: url,
                 crossDomain: true,
                 headers: this.headers,
                 type: 'POST',
                 async: options.async,
                 data: JSON.stringify({
                    'input_scope': options.input_scope,
                    'input_name': options.input_name,
                    'output_scope': options.output_scope,
                    'output_name': options.output_name,
                    'nbfiles': options.nbfiles
                 }),
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
    check_token();
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
    check_token();
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/status';
    if (options.async == null ) { options.async = true; }
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
    check_token();
    var url = this.url + '/accounts/' + options.account;
    if (options.async == null ) { options.async = true; }
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
    check_token();
    var url = this.url + '/accounts/' + options.account + '/attr/';
    if (options.async == null) { options.async = true; }
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
    check_token();
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
    check_token();
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
    check_token();
    var url = this.url + '/dids/' + options.scope + '/' + options.name;
    if (options.async == null) { options.async = true; }
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
    check_token();
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/dids';
    if (options.async == null) { options.async = true; }
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

/* detach dids */
RucioClient.prototype.detach_dids = function(options) {
    check_token();
    var url = this.url + '/dids/' + options.scope + '/' + options.name + '/dids';
    if (options.async == null) { options.async = true; }
    jQuery.ajax({url: url,
        async: options.async,
        crossDomain: true,
        headers: this.headers,
        type: 'DELETE',
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
    check_token();
    var url = this.url + '/rses/' + options.rse + '/attr/' + options.key;
    if (options.async == null ) { options.async = true; }
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
    check_token();
    var url = this.url + '/rses/' + options.rse + '/attr/' + options.key;
    if (options.async == null ) { options.async = true; }
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

/* send trace */
RucioClient.prototype.send_trace = function(options) {
    var url = this.url + '/traces/';
    if (options.async == null) { options.async = true; }
    jQuery.ajax({
        url: url,
        async: options.async,
        crossDomain: true,
        headers: {'X-Rucio-Script': this.script},
        type: 'POST',
        dataType: 'text',
        data: JSON.stringify({
            "eventVersion": options.eventVersion,
            "account": this.account,
            "vo": this.vo,
            "protocol": options.protocol,
            "uuid": options.uuid,
            "datasetScope": options.datasetScope,
            "eventType": options.eventType,
            "remoteSite": options.remoteSite,
            "dataset": options.dataset,
            "filename": options.filename,
            "filesize": options.filesize,
            "scope": options.scope,
            "clientState": options.clientState
        }),
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

/* --- rucio dumps methods --- */

/* list all subscriptions from dumps */
RucioClient.prototype.list_subscription_rules_state_real_time = function(options) {
    check_token();
    // replace root with actual account
    var url = this.url + '/subscriptions/' + options.account + '/Rules/States';
    jQuery.ajax({url: url,
                 headers: {...this.headers },
                 async: false,
                 crossDomain: true,
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

/* list space usage history for an RSE from dumps */
RucioClient.prototype.list_account_usage_history = function(options) {
    check_token();
    var url = this.url + '/accounts/' + options.account + '/usage/history/' + options.rse;
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
