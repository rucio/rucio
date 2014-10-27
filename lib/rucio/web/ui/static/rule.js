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


function create_rseplot(locks_data) {
    var ok = [];
    var replicating = [];
    var stuck = [];
    var categories = [];
    $.each(locks_data, function(rse, states) {
        if ('OK' in states) {
            ok.push(states['OK']);
        } else {
            ok.push(0);
        }
        if ('REPLICATING' in states) {
            replicating.push(states['REPLICATING']);
        } else {
            replicating.push(0);
        }
        if ('STUCK' in states) {
            stuck.push(states['STUCK']);
        } else {
            stuck.push(0);
        }
        categories.push(rse);
    });
    $("#rseplot").attr('style', 'height: 40em;');
    var chart_tmp = $("#rseplot").highcharts( {
        plotOptions: { column: { stacking: 'normal' }
                     },
        chart: { type: 'column' },
        yAxis: { title: { text: 'Locks' },
                 min: 0
               },
        xAxis: { title: { text: 'RSE' },
                 categories: [],
                 labels: {rotation:-45}},
        credits: false,
        title: { text: 'Locks per RSE' },
        series: []
    });

    var chart = chart_tmp.highcharts();
    chart.addSeries( {
        animation: false,
        name: 'Ok',
        data: ok,
        redraw: false,
        color: 'green'
    });
    chart.addSeries( {
        animation: false,
        name: 'Replicating',
        data: replicating,
        redraw: false,
        color: 'orange'
    });
    chart.addSeries( {
        animation: false,
        name: 'Stuck',
        data: stuck,
        redraw: false,
        color: 'red'
    });
    chart.xAxis[0].setCategories(categories);
    chart.hideLoading();
    chart.redraw();
}

function show_details(file_data) {
    var dt = $('#dt_files').DataTable( {
        bAutoWidth: false,
        columns: [{'data': 'name'},
                  {'data': 'rses'}
                 ]
    });

    $.each(file_data, function(file, rses) {
        var str_rses = "";
        var sorted_rses = Object.keys(rses).sort();
        $.each(sorted_rses, function(index, rse) {
            var state = rses[rse];
            str_rses += "<font color=";
            if (state == 'OK') {
                str_rses += "green>" + rse;
            } else if (state == 'REPLICATING') {
                str_rses += "orange>" + rse;
            } else if (state == 'STUCK') {
                str_rses += "red>" + rse;
            }
            str_rses += "</font><br>";
        });
        dt.row.add({'name': file,
                     'rses': str_rses
                    });
    });
    dt.order([0, 'asc']).draw();
}

$(document).ready(function(){
    $('#subbar-details').html('[' + url_param('rule_id') + ':' + url_param('name') + ']');

    $("#show_locks").click(function() {
        r.get_replica_lock_for_rule_id({'rule_id': url_param('rule_id'),
                                        success: function(data) {
                                            var rse_locks_data = {};
                                            var file_data = {};
                                            $.each(data, function(index, lock) {
                                                var rse = lock['rse'];
                                                var state = lock['state'];
                                                var lfn = lock['scope'] + ":" + lock['name'];
                                                if (!(rse in rse_locks_data)) {
                                                    rse_locks_data[rse] = {};
                                                }
                                                if (!(state in rse_locks_data[rse])) {
                                                    rse_locks_data[rse][state] = 0;
                                                }
                                                rse_locks_data[rse][state] += 1;
                                                if (!(lfn in file_data)) {
                                                    file_data[lfn] = {};
                                                }
                                                file_data[lfn][rse] = state;
                                            });
                                            create_rseplot(rse_locks_data);
                                            $("#locks_details").append("<h4>Lock States per File</h4><table id=\"dt_files\" class=\"compact stripe order-column cell-border\" style=\"word-wrap: break-word;\"><thead><th>Filename</th><th>RSEs</th></thead><tfoot><th>Filename</th><th>RSEs</th></tfoot></table>");
                                            show_details(file_data);
                                            $("#show_locks").html("");
                                        },
                                        error: function(jqXHR, textStatus, errorThrown) {
                                            $('#result').html('Could not find the rule.');
                                        }}
                                      );
    });

    r.list_replication_rule({'rule_id': url_param('rule_id'),
                             success: function(data) {
                                 if (data == '') {
                                     $('#result').html('Could not find rule ' + url_param('rule_id'));
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
                                 }
                             },
                             error: function(jqXHR, textStatus, errorThrown) {
                                 $('#result').html('Could not find the rule.');
                             }});
});
