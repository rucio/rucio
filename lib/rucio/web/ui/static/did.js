/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 */

$(document).ready(function(){
    $('#subbar-details').html('[' + url_param('scope') + ':' + url_param('name') + ']');

    r.did_get_metadata({'scope': url_param('scope'),
                        'name': url_param('name'),
                        success: function(data) {
                            if (data == '') {
                                $('#result').html('Could not find scope ' + url_param('scope'));
                            } else {
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
                                r.did_get_rules({'scope': url_param('scope'),
                                                 'name': url_param('name'),
                                                 success: function(rules) {
                                                     if (rules != '') {
                                                         r.list_subscriptions({'account' : data.account,
                                                                               success: function(subs_data) {

                                                                                   var dt = $('#dt_data').DataTable( {
                                                                                       bAutoWidth: false,
                                                                                       columns: [{'data': 'rule'},
                                                                                                 {'data': 'subscription'},
                                                                                                 {'data': 'updated_at', 'width': '15em'}]
                                                                                   });
                                                                                   $('#dt_data_length').find('select').attr('style', 'width: 4em;');
                                                                                   $('#dt_data_filter').find('input').attr('style', 'width: 10em; display: inline');

                                                                                   var all_sub_ids=[];
                                                                                   subs_data.forEach(function(s) {
                                                                                       all_sub_ids.push(s.id);
                                                                                   });

                                                                                   rules.forEach(function(r) {
                                                                                       var tmp_sub = '';
                                                                                       var tmp_hint = '';
                                                                                       if (r.subscription_id != null) {
                                                                                           var tmp_s = $.grep(subs_data, function(s){ return s.id == r.subscription_id; })[0];
                                                                                           tmp_sub = tmp_s.name;
                                                                                           tmp_hint = tmp_s.replication_rules;

                                                                                       }
                                                                                       dt.row.add({'rule': r.rse_expression,
                                                                                                   'subscription': '<span data-tooltip aria-haspopup="true" class="has-tip" title="' + tmp_hint.replace(/"/g,'') + '">' + tmp_sub + '</span>',
                                                                                                   'updated_at': r.updated_at});
                                                                                   });
                                                                                   dt.order([0, 'desc']).draw();
                                                                               }
                                                                              });
                                                     }
                                                 },
                                                 error: function(jqXHR, textStatus, errorThrown) {
                                                     $('#result').html(errorThrown);
                                                 }});
                            }
                        },
                        error: function(jqXHR, textStatus, errorThrown) {
                            $('#result').html('Could not find the DID.');
                        }});

});
