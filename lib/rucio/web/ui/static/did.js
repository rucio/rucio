/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2015
 */

html_replicas_base = '<div id="t_replicas" class="columns panel">' +
    '<h4>Replica States</h4>' +
    '</div>';

html_replicas_table = '<table id="dt_replicas" class="compact stripe order-column" style="word-wrap: break-word;">' +
    '<thead><th>Filename</th><th>Replicas</th></thead>' +
    '<tfoot><th>Filename</th><th>Replicas</th></tfoot>' +
    '</table>' +
    '<div>' +
    '<h5>Color Codes</h5>' +
    '<font color=green>AVAILABLE</font> ' +
    '<font color=red>UNAVAILABLE</font> ' +
    '<font color=orange>COPYING</font> ' +
    '<font color=black>BEING_DELETED</font> ' +
    '<font color=pink>BAD</font> ' +
    '<font color=blue>SOURCE</font> ' +
    '</div>';

html_contents = '<div id="t_contents" class="columns panel">' +
    '<h4>Contents</h4>' +
    '<table id="dt_contents" class="compact stripe order-column cell-border" style="word-wrap: break-word;">' +
    '<thead><th>DID</th><th>DID Type</th></thead>' +
    '<tfoot><th>DID</th><th>DID Type</th></tfoot>' +
    '</table>' +
    '</div>';

html_rules_base = '<div id="t_rules" class="columns panel">' +
    '<h4>Rules</h4>' +
    '<div id="loading_rules" "class="row"><div class="small-1 small-centered columns"><img src="/media/spinner.gif"></div>' +
    '</div>';

html_rules_table = '<table id="dt_rules" class="compact stripe order-column" style="word-wrap: break-word;">' +
    '<thead><th>Rule</th><th>State</th><th>Account</th><th>Subscription</th><th>Last modified</th></thead>' +
    '<tfoot><th>Rule</th><th>State</th><th>Account</th><th>Subscription</th><th>Last modified</th></tfoot>' +
    '</table>';

load_replicas = function(scope, name) {
    var table_files = [];
    $('#load_replicas').html('');
    $('#t_replicas').append('<div id="loader_replicas" "class="row"><div class="small-1 small-centered columns"><img src="/media/spinner.gif"></div>');
    r.list_replicas({'scope': scope,
                     'name': name,
                     success: function(replicas) {
                         $('#loader_replicas').html('');
                         $('#t_replicas').append(html_replicas_table);
                         var dt2 = $('#dt_replicas').DataTable( {
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
                         $('#dt_replicas_length').find('select').attr('style', 'width: 4em;');
                         $('#dt_replicas_filter').find('input').attr('style', 'width: 10em; display: inline');

                     }
                    });
}

load_rules = function(scope, name) {
    $('#result').append(html_rules_base);
    r.did_get_rules({'scope': scope,
                     'name': name,
                     success: function(rules) {
                         if (rules != '') {
                             data = [];
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
                                 data.push({'rule': rule.rse_expression,
                                             'state': rule.state,
                                             'account': rule.account,
                                             'subscription': tmp_sub,
                                             'updated_at': rule.updated_at});
                             });
                             $('#t_rules').append(html_rules_table);
                             var dt = $('#dt_rules').DataTable( {
                                 data: data,
                                 bAutoWidth: false,
                                 sEmtpyTable: "No rules found",
                                 columns: [{'data': 'rule'},
                                           {'data': 'state'},
                                           {'data': 'account'},
                                           {'data': 'subscription'},
                                           {'data': 'updated_at', 'width': '15em'}]
                             });
                             $('#dt_rules_length').find('select').attr('style', 'width: 4em;');
                             $('#dt_rules_filter').find('input').attr('style', 'width: 10em; display: inline');
                             dt.order([0, 'asc']).draw();
                             $('#loading_rules').html('');
                         } else {
                             $('#loading_rules').html('No rules found for this DID.');
                         }
                     },
                     error: function(jqXHR, textStatus, errorThrown) {
                         $('#loading_rules').html(errorThrown);
                     }
                    });
};

handle_container = function(scope, name) {
    load_rules(scope, name);
    $('#result').append(html_contents);
    $('#result').append(html_replicas_base);
    $('#t_replicas').append('<div id="load_replicas">Click here to load replicas</div>');
    $('#load_replicas').click(function() {
        load_replicas(scope, name);
    });
    r.list_contents({'scope': scope,
                     'name': name,
                     success: function(dids) {
                         data = [];
                         $.each(dids, function(index, did) {
                             did_link = '<a href="/did?scope=' + did['scope'] + '&name=' + did['name'] + '">' + did['scope'] + ':' + did['name'] + '</a>';
                             data.push({'did': did_link, 'type': did['type']});
                         });
                         var dt = $('#dt_contents').DataTable( {
                             data: data,
                             bAutoWidth: false,
                             columns: [{'data': 'did', 'width': '80%'},
                                       {'data': 'type', 'width': '20%'}]
                         });
                         $('#dt_contents_length').find('select').attr('style', 'width: 4em;');
                         $('#dt_contents_filter').find('input').attr('style', 'width: 10em; display: inline');

                     }, error: function(jqXHR, textStatus, errorThrown) {
                         $('#loading').html('<font color="red">Could not list the content for this container.</font>');
                     }});
};

handle_dataset = function(scope, name) {
    load_rules(scope, name);
    $('#result').append(html_replicas_base);
    load_replicas(scope, name);
};

handle_file = function(scope, name) {
    $('#result').append(html_replicas_base);
    load_replicas(scope, name);
};

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
                                if (data['bytes'] != undefined) {
                                    data['filesize'] = filesize(data['bytes']);
                                    delete data['bytes'];
                                }
                                var sorted_keys = Object.keys(data).sort();
                                if (data['did_type'] == 'CONTAINER') {
                                    handle_container(scope, name);
                                } else if (data['did_type'] == 'DATASET') {
                                    handle_dataset(scope, name);
                                } else {
                                    handle_file(scope, name);
                                }
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
                            }
                        },
                        error: function(jqXHR, textStatus, errorThrown) {
                            $('#loading').html('<font color="red">Could not find the DID.</font>');
                        }});
});
