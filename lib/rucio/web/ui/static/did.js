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
    var scope = url_param('scope');
    var name = url_param('name');

    if (name.indexOf(':') > -1) {
        var splits = name.split(":");
        scope = splits[0];
        name = splits[1];
    }

    $('#subbar-details').html('[' + scope + ':' + name + ']');

    r.did_get_metadata({'scope': scope,
                        'name': name,
                        success: function(data) {
                            $("#loading").html("");
                            if (data == '') {
                                $('#result').html('Could not find scope ' + scope);
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
                                            if (sorted_keys[i] == 'scope') {
                                                data[sorted_keys[i]] = "<a href=/search?scope=" + data['scope'] + "&name=undefined>" + data['scope'] + "</a>";
                                            }
                                            $('#t_metadata').append($('<tr><th>' + sorted_keys[i] + '</th><td>' + data[sorted_keys[i]] + '</td></tr>'));
                                        }
                                    }
                                }
                                r.did_get_rules({'scope': scope,
                                                 'name': name,
                                                 success: function(rules) {
                                                     if (rules != '') {
                                                         var dt = $('#dt_data').DataTable( {
                                                             bAutoWidth: false,
                                                             sEmtpyTable: "No rules found",
                                                             columns: [{'data': 'rule'},
                                                                       {'data': 'state'},
                                                                       {'data': 'account'},
                                                                       {'data': 'subscription'},
                                                                       {'data': 'updated_at', 'width': '15em'}]
                                                         });
                                                         $('#dt_data_length').find('select').attr('style', 'width: 4em;');
                                                         $('#dt_data_filter').find('input').attr('style', 'width: 10em; display: inline');
                                                         rules.forEach(function(rule) {
                                                             var tmp_sub = '-';
                                                             if (rule.subscription_id != null) {
                                                                 r.get_subscription_by_id({'id': rule.subscription_id,
                                                                                           'async': false,
                                                                                           success: function(subscription) {
                                                                                               tmp_sub = '<a href="/subscription?name=' + subscription.name + '&account=' + subscription.account + '">' + subscription.name + '</a>';
                                                                                           },
                                                                                           error: function(jqXHR, textStatus, errorThrown) {
                                                                                               console.log(textStatus);
                                                                                           }});
                                                             }
                                                             rule.rse_expression = '<a href="/rule?rule_id=' + rule.id + '">' + rule.rse_expression + '</a>';
                                                             if (rule.state == 'OK') {
                                                                 rule.state = "<font color=green>" + rule.state + "</font>";
                                                             } else if (rule.state == 'REPLICATING') {
                                                                 rule.state = "<font color=orange>" + rule.state + "</font>";
                                                             } else if (rule.state == 'STUCK') {
                                                                 rule.state = "<font color=RED>" + rule.state + "</font>";
                                                             }
                                                             dt.row.add({'rule': rule.rse_expression,
                                                                         'state': rule.state,
                                                                         'account': rule.account,
                                                                         'subscription': tmp_sub,
                                                                         'updated_at': rule.updated_at});
                                                         });
                                                         dt.order([0, 'asc']).draw();
                                                         $('#loading_rules').html('');
                                                     }
                                                 },
                                                 error: function(jqXHR, textStatus, errorThrown) {
                                                     $('#loading_rules').html(errorThrown);
                                                 }});
                            }
                        },
                        error: function(jqXHR, textStatus, errorThrown) {
                            $('#loading').html('<font color="red">Could not find the DID.</font>');
                        }});

    var table_files = [];
    r.list_replicas({'scope': scope,
                     'name': name,
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
