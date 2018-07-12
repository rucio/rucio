/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2018
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

function save_account_attr(acc) {
    r.list_account_attributes({
        account: acc,
        async: false,
        success: function(attributes) {
            $.cookie('rucio-account-attr', JSON.stringify(attributes), { path: '/' });
        }, error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });
}

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

function set_account(acc) {
    r.get_auth_token_x509({
        account: acc,
        success: function(data, textStatus, jqXHR) {
            var new_token = jqXHR.getResponseHeader('X-Rucio-Auth-Token');
            $.cookie('rucio-selected-account', acc, { path: '/' });
            $.cookie('x-rucio-auth-token', new_token, { path: '/' });
            current_time = parseInt((new Date).getTime()/1000);
            $.cookie('rucio-auth-token-created-at', current_time, { path: '/'});
            $('#current_account').text(acc);
            save_account_attr(acc);
            new_href = window.location.href;
            if (window.location.href.indexOf('&account=') > -1 || window.location.href.indexOf('?account=') > -1) {
                new_href = updateQueryStringParameter(window.location.href, 'account', acc);
            } else if (window.location.href.indexOf('ui_account=') > -1) {
                new_href = updateQueryStringParameter(window.location.href, 'ui_account', acc);
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
    if (/^[a-zA-Z0-9]+$/.test(input) && input.length == 32) {
        if (test_rule(input)) {
            if (document.location.href.indexOf('/ui/')>-1) {
                document.location.href = '/ui/rule?rule_id=' + input;
            } else {
                document.location.href = '/rule?rule_id=' + input;
            }
            return;
        }
    }

    if (document.location.href.indexOf('/ui/')>-1) {
        document.location.href = '/ui/search?pattern=' + input;
    } else {
        document.location.href = '/search?pattern=' + input;
    }
}

function check_attributes() {
    if ($.cookie('rucio-account-attr') == undefined) {
        return;
    }
    attrs = JSON.parse($.cookie('rucio-account-attr'));

    $.each(attrs, function(index, attr) {
        if ((attr.key == 'admin' && attr.value == true) || (attr.key.startsWith('country-') && attr.value == 'admin')) {
            $('#r2d2_dropdown').append('<li><a id="approve_rules_link" href="/r2d2/approve">Approve rules</a></li>');
            $('#r2d2_dropdown').append('<li><a id="manage_quota_link" href="/r2d2/manage_quota">Quota Management</a></li>');
            $('#admin_dropdown').css('display', '');
        }
    });
}

function fix_links() {
    $('a[href^="/"]').each(function(){
        /* only add the prefix if it's not already added */
        if ($(this).attr("href").indexOf('/ui/') == -1) {
            var newUrl = '/ui' + $(this).attr("href");
            $(this).attr("href", newUrl);
        }
    });
}

/* engage */
var r = new RucioClient(token, account);
$(document).ready(function() {
    $('#rucio_webui_version').html(get_version());
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

    check_attributes();

    /* if the webui is run as a dev or demo instance
     * change all links to start the url with '/ui/'
     */
    if (document.location.href.indexOf('/ui/')>-1) {
        fix_links()
    };

    /* do the same for all dynamically created links */
    $(document).ajaxSuccess(function() {
        if (document.location.href.indexOf('/ui/')>-1) {
            fix_links();
        };
    });
});
