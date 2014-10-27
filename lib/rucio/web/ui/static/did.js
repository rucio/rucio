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

$(document).ready(function(){
    $('#subbar-details').html('[' + url_param('scope') + ':' + url_param('name') + ']');

    r.did_get_metadata({'scope': url_param('scope'),
                        'name': url_param('name'),
                        success: function(data) {
                            if (data == '') {
                                $('#result').html('Could not find scope ' + url_param('scope'));
                            } else {
                                var sorted_keys = Object.keys(data).sort();
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
                                                         var dt = $('#dt_data').DataTable( {
                                                             bAutoWidth: false,
                                                             sEmtpyTable: "No rules found",
                                                             columns: [{'data': 'rule'},
                                                                       {'data': 'account'},
                                                                       {'data': 'subscription'},
                                                                       {'data': 'updated_at', 'width': '15em'}]
                                                         });
                                                         $('#dt_data_length').find('select').attr('style', 'width: 4em;');
                                                         $('#dt_data_filter').find('input').attr('style', 'width: 10em; display: inline');
                                                         rules.forEach(function(r) {
                                                             var tmp_sub = '-';
                                                             var tmp_hint = '';
                                                             if (r.subscription_id != null) {
                                                                 // get subscription by id
                                                                 // Waiting for RUCIO-644 for enable saarching by subscription id
                                                                 //tmp_sub = '<span data-tooltip aria-haspopup="true" class="has-tip" title="' + tmp_hint.replace(/"/g,'') + '">' + tmp_sub + '</span>'
                                                             }
                                                             r.rse_expression = '<a href="/rule?rule_id=' + r.id + '">' + r.rse_expression + '</a>';
                                                             dt.row.add({'rule': r.rse_expression,
                                                                         'account': r.account,
                                                                         'subscription': tmp_sub,
                                                                         'updated_at': r.updated_at});
                                                         });
                                                         dt.order([0, 'asc']).draw();
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

    var table_files = [];
    r.list_replicas({'scope': url_param('scope'),
                     'name': url_param('name'),
                     success: function(replicas) {
                         var dt2 = $('#dt_files').DataTable( {
                             bAutoWidth: false,
                             columns: [{'data': 'name'},
                                       {'data': 'rses'}
                                      ]
                         });

                         $.each(replicas, function(index, replica) {
                             table_files[replica['name']] = [];
                             var str_rses = "";
                             var sorted_rses = Object.keys(replica['states']).sort();
                             $.each(sorted_rses, function(index, rse) {
                                 var state = replica['states'][rse];
                                 str_rses += "<font color=";
                                 if (state == 'AVAILABLE') {
                                     str_rses += "green>" + rse;
                                 } else if (state == 'UNAVAILABLE') {
                                     str_rses += "red>" + rse;
                                 } else if (state == 'COPYING') {
                                     str_rses += "orange>" + rse;
                                 } else if (state == 'BEING_DELETED') {
                                     str_rses += "black>" + rse;
                                 } else if (state == 'BAD') {
                                     str_rses += "pink>" + rse;
                                 } if (state == 'SOURCE') {
                                     str_rses += "blue>" + rse;
                                 }
                                 str_rses += "</font><br>";
                             });
                             var lfn = replica['scope'] + ':' + replica['name'];
                             dt2.row.add({'name': lfn,
                                          'rses': str_rses
                                        });
                         });
                         dt2.order([0, 'asc']).draw();
                     }
                    });


});
