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
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2017-2018
 */

var chosen_account = url_param('account');
var chosen_name = url_param('name')

handle_metadata = function(data) {
    var sorted_keys = Object.keys(data).sort()
    for(var i=0; i<sorted_keys.length; ++i) {
        if (data[sorted_keys[i]] != undefined) {
            let row = $('<tr></tr>');
            row.append($('<th></th>').text(sorted_keys[i]));
            $('#t_metadata').append(row);
            if (typeof data[sorted_keys[i]] === 'boolean'){
                let color = data[sorted_keys[i]] ? "green" : "red";
                row.append($('<td></td>', {'style': 'color: ' + color}).text(data[sorted_keys[i]]));
            } else if (sorted_keys[i] == 'filter' || sorted_keys[i] == 'replication_rules'){
                var obj = JSON.parse(data[sorted_keys[i]]);
                var str = JSON.stringify(obj, null, 2)
                row.append($('<td></td>').append($('<pre></pre>').text(str)));
            } else {
                row.append($('<td></td>').text(data[sorted_keys[i]]));
            }
        }
    }
};

$(document).ready(function(){
    options = {};
    options['error'] = function(jqXHR, textStatus, errorThrown) {
        $('#result').html('Could not find the subscription.');
    };
    if (url_param('id') != '') {
        options['id'] = url_param('id');
        options['success'] = function(data) {
            if (data == '') {
                $('#result').text('Could not find the subscription ' + url_param('rule_id'));
            } else {
                handle_metadata(data);
            }
        };
        r.get_subscription_by_id(options);
        $('#subbar-details').text('[' + url_param('id') + ']');
    } else {
        options['name'] =  url_param('name');
        options['account'] = url_param('account');
        options['success'] = function(data) {
            if (data == '') {
                $('#result').text('Could not find the subscription ' + url_param('rule_id'));
            } else {
                handle_metadata(data[0]);
            }
        };
        r.list_subscriptions(options);
        $('#subbar-details').text('[' + url_param('account') + ':' + url_param('name') + ']');
        $('#subscription_editor').click(function(){
            window.location.href='/subscriptions_editor?name=' + url_param('name') + '&account=' + url_param('account');
        })

    }
});
