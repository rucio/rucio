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

$(document).ready(function(){
    $('#subbar-details').html('[' + url_param('account') + ':' + url_param('name') + ']');

    r.list_subscriptions({'name': url_param('name'),
                'account': url_param('account'),
                             success: function(data) {
                                 if (data == '') {
                                     $('#result').html('Could not find subscription ' + url_param('rule_id'));
                                 } else {
                                     data = data[0];
                                     var sorted_keys = Object.keys(data).sort()
                                     for(var i=0; i<sorted_keys.length; ++i) {
                                         if (data[sorted_keys[i]] != undefined) {
                                             if (typeof data[sorted_keys[i]] === 'boolean'){
                                                 if (data[sorted_keys[i]]) {
                                                     $('#t_metadata').append($('<tr><th>' + sorted_keys[i] + '</th><td style="color: green;">' + data[sorted_keys[i]] + '</td></tr>'));
                                                 } else {
                                                     $('#t_metadata').append($('<tr><th>' + sorted_keys[i] + '</th><td style="color: red;">' + data[sorted_keys[i]] + '</td></tr>'));
                                                 }
                                             } else {
                                                 $('#t_metadata').append($('<tr><th>' + sorted_keys[i] + '</th><td>' + data[sorted_keys[i]] + '</td></tr>'));
                                             }
                                         }
                                     }
                                 }
                             },
                             error: function(jqXHR, textStatus, errorThrown) {
                                 $('#result').html('Could not find the rule.');
                             }});
});
