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
 */

/* --- base Rucio client class definition --- */
function RucioClient(token, account) {
    this.token = token;
    this.account = account;
    this.url = 'https://mlassnig-dev.cern.ch:443';
};

/* --- utility function --- */

parse_json_stream = function(data) {
    var split_data = data.split('\n');
    var ret_data = []
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
                     options.success(data)
                 },
                 error: function(jqXHR, textStatus, errorThrown)
                 {
                     options.error(jqXHR, textStatus, errorThrown)
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
                     options.error(jqXHR, textStatus, errorThrown)
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
                     options.error(jqXHR, textStatus, errorThrown)
                 }
        });
};

/* list all subscriptions for an account */
RucioClient.prototype.list_subscriptions = function(options) {
    var url = this.url + '/subscriptions/' + options.account + '/';
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
                     options.error(jqXHR, textStatus, errorThrown)
                 }
        });
};
