/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 */

/* token and account handling */
if ('x-rucio-auth-token' in $.cookie()) {
    token = $.cookie('x-rucio-auth-token');
}
if ('rucio-selected-account' in $.cookie()) {
    account = $.cookie('rucio-selected-account');
} else {
    $.cookie('rucio-selected-account', account, { path: '/' });
}
var available_accounts = $.cookie('rucio-available-accounts').split(' ');

function set_account(acct) {
    account = acct;
    $.cookie('rucio-selected-account', account, { path: '/' });
    $('#current_account').text(account);
}

/* extract URL parameters */
function url_param(key){
    var result = new RegExp(key + "=([^&]*)", "i").exec(window.location.search);
    return result && unescape(result[1]) || "";
}

/* quick search */
function did_search(did) {
    var scope = did.split(':')[0];
    var name = did.split(':')[1];
    if (window.location.href.indexOf('/ui/')>-1) {
        window.location.href = '/ui/search?scope=' + scope + '&name=' + name;
    } else {
        window.location.href = '/search?scope=' + scope + '&name=' + name;
    }
}

/* engage */
var r = new RucioClient(token, account);
$(document).ready(function() {
    r.ping({success: function(data) { $('#rucio_server_version').html(data.version);}});

    $('#current_account').text(account);
    available_accounts.forEach(function(acct) {
        $('#accountselecter').append("<li><a onClick=\"set_account('" + acct + "')\">" + acct + "</a></li>")
    });

    $('#searchbox').keyup(function(e) {
        if (e.keyCode == 13) {
            did_search($('#searchbox').val());
        }
    });
});
