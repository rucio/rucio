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

var ids = null;

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
    $("#rseplot").attr('style', 'height: 40em; width: 60em; margin: 0 auto;');
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
        color: 'green',
        pointWidth: 40
    });
    chart.addSeries( {
        animation: false,
        name: 'Replicating',
        data: replicating,
        redraw: false,
        color: 'orange',
        pointWidth: 40
    });
    chart.addSeries( {
        animation: false,
        name: 'Stuck',
        data: stuck,
        redraw: false,
        color: 'red',
        pointWidth: 40
    });
    chart.xAxis[0].setCategories(categories);
    chart.hideLoading();
    chart.redraw();
}

function link_to_fts(e) {
    var target = e.target;
    var items = target.attributes['0'].nodeValue.split(",");
    var scope = items[0];
    var name = items[1];
    var rse = items[2];
    $("#" + e.target.id).html("loading...");
    r.get_request_by_did({'scope': scope,
                          'name': name,
                          'rse': rse,
                          success: function(data){
                              host = data['external_host'];
                              id = data['external_id'];
                              url = host.slice(0, -1) + '9/ftsmon/#/job/' + id;
                              link = "<a href=" + url + ">" + url.split('#')[0] + "...</a>";
                              $("#" + e.target.id).html(link);
                          },
                          error: function(jqXHR, textStatus, errorThrown) {
                              $("#" + e.target.id).html("cannot generate link");
                          }
                         });
};

function link_to_dashboard(file, scope, rse) {
    var site = rse.split("_")[0];
    var token = rse.split("_")[1];
    var link = "http://dashb-atlas-ddm.cern.ch/ddm2/#d.dst.site=";
    link += site;
    link += "&d.dst.token=";
    link += token;
    link += "&d.name=";
    link += file;
    link += "&d.scope=";
    link += scope;
    link += "&grouping.dst=%28site,token%29&tab=details";

    url = "<a href=" + link + ">link</a>";
    return url;
}

function show_details(file_data) {
    var dt = $('#dt_files').DataTable( {
        bAutoWidth: false,
        fnDrawCallback:update_links,
        columns: [{'data': 'name'},
                  {'data': 'rses'},
                  {'data': 'dashboard'},
                  {'data': 'ftsmon'}
                 ]
    });

    ids = [];
    var i = 0;
    $.each(file_data, function(file, rses) {
        var str_rses = "";
        var sorted_rses = Object.keys(rses).sort();
        var ftsmon = "";
        var scope = file.split(":")[0];
        var name = file.split(":")[1];
        var dashboard = "";

        $.each(sorted_rses, function(index, rse) {
            var state = rses[rse];
            str_rses += "<font color=";
            dashboard += "<div>" + link_to_dashboard(name, scope, rse) + "</div>";
            if (state == 'OK') {
                str_rses += "green>" + rse;
                ftsmon += '<div style="visibility: hidden;">.</div>';
            } else if (state == 'REPLICATING') {
                str_rses += "orange>" + rse;
                value = scope + ',' + name + ',' + rse;
                id = 'ftsmon' + i;
                ftsmon += '<div id=' + id + ' value=' + value + '>click to generate link</div>';
                ids.push(id);
            } else if (state == 'STUCK') {
                str_rses += "red>" + rse;
                value = scope + ',' + name + ',' + rse;
                id = 'ftsmon' + i;
                ftsmon += '<div id=' + id + ' value=' + value + '>click to generate link</div>';
                ids.push(id);
            }
            str_rses += "</font><br>";
            i += 1;
        });
        dt.row.add({'name': file,
                    'rses': str_rses,
                    'dashboard': dashboard,
                    'ftsmon': ftsmon
                    });
    });
    dt.order([0, 'asc']).draw();
}

function update_links() {
    if (ids == null) {
        return;
    }
    $.each(ids, function(index, id) {
        $('#' + id).click(link_to_fts);
    });
}

function load_locks() {
    $("#show_locks").html("Loading, please wait...");
    r.get_replica_lock_for_rule_id({'rule_id': url_param('rule_id'),
                                    success: function(data) {
                                        $("#lock_title").html("");
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
                                        $("#locks_details").append("<h4>Lock States per File</h4><table id=\"dt_files\" class=\"compact stripe order-column cell-border\" style=\"word-wrap: break-word;\"><thead><th>Filename</th><th>RSEs</th><th>DDM Dashboard</th><th>FTS Monitoring</th></thead><tfoot><th>Filename</th><th>RSEs</th><th>DDM Dashboard</th><th>FTS Monitoring</th></tfoot></table>");
                                        show_details(file_data);
                                        $("#show_locks").html("");

                                    },
                                    error: function(jqXHR, textStatus, errorThrown) {
                                        $('#loading').html('Could not find the rule.');
                                    }}
                                  );
}

$(document).ready(function(){
    $('#subbar-details').html('[' + url_param('rule_id') + ':' + url_param('name') + ']');

    r.list_replication_rule({'rule_id': url_param('rule_id'),
                             success: function(data) {
                                 $("#loading").html("");
                                 if (data == '') {
                                     $('#result').html('Could not find rule ' + url_param('rule_id'));
                                 } else {
                                     $("#locks").attr('class', 'columns panel');
                                     $("#locks").html("<h4 id=\"locks_title\">Locks Overview</h4><div id=\"show_locks\">Please click to show locks</div><div id=\"rseplot\"></div><div id=\"locks_details\"></div>");
                                     $("#show_locks").click(load_locks);
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
                                                 if (sorted_keys[i] == 'name') {
                                                     data[sorted_keys[i]] = "<a href=/did?scope=" + data['scope'] + "&name=" + data['name'] + ">" + data['name']  + "</a>";
                                                 }
                                                 if (sorted_keys[i] == 'scope') {
                                                     data[sorted_keys[i]] = "<a href=/search?scope=" + data['scope'] + "&name=undefined>" + data['scope'] + "</a>";
                                                 }
                                                 if (sorted_keys[i] == 'state') {
                                                     if (data['state'] == 'OK') {
                                                         data[sorted_keys[i]] = "<font color='green'>" + data['state'] + "</a>";
                                                     } else if (data['state'] == 'REPLICATING') {
                                                         data[sorted_keys[i]] = "<font color='orange'>" + data['state'] + "</a>";
                                                     } else if (data['state'] == 'STUCK') {
                                                         data[sorted_keys[i]] = "<font color='red'>" + data['state'] + "</a>";
                                                     }
                                                 }
                                                 $('#t_metadata').append($('<tr><th>' + sorted_keys[i] + '</th><td>' + data[sorted_keys[i]] + '</td></tr>'));
                                             }
                                         }
                                     }
                                 }
                             },
                             error: function(jqXHR, textStatus, errorThrown) {
                                 $('#loading').html('<font color="red">Could not find the rule.</font>');
                             }});
});
