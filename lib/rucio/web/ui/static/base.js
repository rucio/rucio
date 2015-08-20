/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2015
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

function updateQueryStringParameter(uri, key, value) {
    var re = new RegExp("([?&])" + key + "=.*?(&|$)", "i");
    var separator = uri.indexOf('?') !== -1 ? "&" : "?";
    if (uri.match(re)) {
        return uri.replace(re, '$1' + key + "=" + value + '$2');
    }
    else {
        return uri + separator + key + "=" + value;
    }
}

function set_account(account) {
    r.get_auth_token_x509({
        account: account,
        success: function(data, textStatus, jqXHR) {
            var new_token = jqXHR.getResponseHeader('X-Rucio-Auth-Token');
            $.cookie('rucio-selected-account', account, { path: '/' });
            $.cookie('x-rucio-auth-token', new_token, { path: '/' });
            $('#current_account').text(account);
            new_href = window.location.href;
            if (window.location.href.indexOf('account=') > -1) {
                new_href = updateQueryStringParameter(window.location.href, 'account', account);
            }
            window.location.href = new_href;
        }, error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });

}

/* extract URL parameters */
function url_param(key){
    var result = new RegExp(key + "=([^&]*)", "i").exec(window.location.search);
    return result && unescape(result[1]) || "";
}

/* change URL to add the given parameter */
function insertParam(key, value)
{
    var new_path = document.location.pathname + "?" + key + "=" + encodeURIComponent(value);
    window.history.pushState("object or string", "Title", new_path);
}

/* clear all URL parameters */
function clearParams()
{
    var new_path = document.location.pathname;
    window.history.pushState("object or string", "Title", new_path);
}

function test_rule(id) {
    found_rule = false;
    r.list_replication_rule({
        'rule_id': id,
        async: false,
        success: function(data) {
            found_rule = true;
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log('not a rule');
        }
    });
    return found_rule;
};

function guess_scope(name) {
    if (name.indexOf(':') > -1) {
        return name.split(':');
    }
    var items = name.split('.')
    if (items.length <= 1) {
        return false;
    }
    var scope = items[0];
    if (name.indexOf('user') === 0 || name.indexOf('group') === 0) {
        scope = items[0] + '.' + items[1];
    }
    return [scope, name];
};

/* quick search */
function did_search(input) {
    if (/^[a-z0-9]+$/.test(input) && input.length == 32) {
        if (test_rule(input)) {
            if (document.location.href.indexOf('/ui/')>-1) {
                document.location.href = '/ui/rule?rule_id=' + input;
            } else {
                document.location.href = '/rule?rule_id=' + input;
            }
        }
    }

    guessed_scope_name = guess_scope(input);
    if (guessed_scope_name) {
        var scope = guessed_scope_name[0];
        var name = guessed_scope_name[1];

        if (document.location.href.indexOf('/ui/')>-1) {
            document.location.href = '/ui/did?scope=' + scope + '&name=' + name;
        } else {
            document.location.href = '/did?scope=' + scope + '&name=' + name;
        }
    }
}

/* engage */
var r = new RucioClient(token, account);
$(document).ready(function() {
    r.ping({
        success: function(data) {
            $('#rucio_server_version').html(data.version);
        }, error: function(jqXHR, textStatus, errorThrown) {
            console.log(textStatus);
        }
    });

    $('#current_account').text(account);
    available_accounts.forEach(function(acct) {
        $('#accountselecter').append("<li><a onClick=\"set_account('" + acct + "')\">" + acct + "</a></li>")
    });

    $('#searchbox').keyup(function(e) {
        if (e.keyCode == 13) {
            did_search($('#searchbox').val());
        }
    });

    if (window.location.host == "rucio-ui-dev.cern.ch") {
        $("#warning_header").html('<div style="height: 1.6em; background-color: red;"> <center style="font-size: 1.0rem;"> Development Instance </center> </div>');
    }
});
