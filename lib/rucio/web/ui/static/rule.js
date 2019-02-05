/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2019
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 */

var ids = null;
var expires_at = null;
var rse_expression = null;

function clear_date() {
    if (rse_expression.indexOf('SCRATCHDISK') > -1) {
        $('#ext_error').html('<font color="red">You cannot remove the lifetime from rule at SCRATCHDISK</font>');
        $('#row_datechanger').slideDown();
        return;
    }
    r.update_replication_rule({
        rule_id: url_param('rule_id'),
        params: {'lifetime': null},
        async: false,
        success: function(data) {
            location.reload();
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert(jqXHR['responseText']);
        }
    });
}

function extend_expiration() {
    var days = parseInt($('#extension_days').val());
    if (isNaN(days)) {
        $('#ext_error').html('<font color="red">Please enter a valid positive integer</font>');
        return;
    }
    if (days <= 0) {
        $('#ext_error').html('<font color="red">Please enter a positive integer</font>');
        return;
    }
    var now = new Date();
    var new_date = new Date();
    if (expires_at != null) {
        var new_date = new Date(expires_at);
    }
    new_date.setDate(new_date.getDate() + days);
    var new_lifetime = parseInt((new_date - now) / 1000);
    if (rse_expression.indexOf('SCRATCHDISK') > -1) {
        if (new_lifetime > (15 * 86400)) {
            $('#ext_error').html('<font color="red">You cannot set the lifetime for rules at SCRATCHDISK to more than 15 days</font>');
            return;
        }
    }
    r.update_replication_rule({
        rule_id: url_param('rule_id'),
        params: {'lifetime': new_lifetime},
        async: false,
        success: function(data) {
            location.reload();
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert(jqXHR['responseText']);
        }
    });
}

function approve_rule(id, action, comment) {
    $("#alert_box").html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    var approve = false;
    if (action == 'approve') {
        approve = true;
    }

    r.update_replication_rule({
        rule_id: id,
        params: {'approve': approve, 'comment': comment},
        async: true,
        success: function(data) {
            var alert_text = '<div data-alert class="alert-box success radius">The rule has been successfully '
            if (approve == true) {
                alert_text += 'approved';
            } else {
                alert_text += 'denied';
            }
            alert_text += '.</div>';
            $("#alert_box").html(alert_text);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            error_details = JSON.parse(jqXHR.responseText);
            var alert_text = '<div data-alert class="alert-box alert radius">'
            if (error_details['ExceptionClass'] == 'AccessDenied') {
                alert_text += 'Your account does not have the rights to approve this rule. If you have multiple accounts please try another one.';
            } else if (error_details['ExceptionClass'] == 'RucioException' || error_details['ExceptionClass'] == 'RuleNotFound') {
                return;
            }
            alert_text += '<a href="#" class="close">&times;</a></div>';
            $("#alert_box").html(alert_text);
        }
    });
}

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
    var items = $("#" + e.target.id).attr('value').split(",");
    var scope = items[0];
    var name = items[1];
    var rse = items[2];
    $("#" + e.target.id).html("loading...");
    r.get_request_by_did({'scope': scope,
                          'name': name,
                          'rse': rse,
                          success: function(data){
                              if (data == null) {
                                  $("#" + e.target.id).html("the request cannot be found, this shouldn't happen. Please contact <a href='mailto:atlas-adc-ddm-support@cern.ch'>ddm support</a>");
                              }
                              if (data['state'] != 'SUBMITTED') {
                                  $("#" + e.target.id).html("The request has not yet been submitted");
                              } else {
                                  host = data['external_host'];
                                  id = data['external_id'];
                                  url = host.slice(0, -1) + '9/ftsmon/#/job/' + id;
                                  link = "<a href=" + url + ">" + url.split('#')[0] + "...</a>";
                                  $("#" + e.target.id).html(link);
                              }
                          },
                          error: function(jqXHR, textStatus, errorThrown) {
                              $("#" + e.target.id).html("cannot generate link");
                          }
                         });
};

function link_to_new_atlas_dashboard(file, scope, rse) {
    var items = rse.split("_");
    var site = items.slice(0,-1).join('_');
    var token = items.slice(-1)[0];
    var link = "https://monit-grafana.cern.ch/d/FtSFfwdmk/ddm-transfers?panelId=56&fullscreen&orgId=17&var-binning=$__auto_interval_binning&var-groupby=dst_cloud&var-activity=All&var-src_cloud=All&var-src_site=All&var-src_country=All&var-src_endpoint=All&var-columns=src_cloud&var-dst_cloud=All&var-dst_endpoint=";

    link += rse;
    link += "&var-enr_filters=data.name%7C%3D%7C";
    link += file;
    link += "&var-enr_filters=data.scope%7C%3D%7C";
    link += scope;
    link += "&var-measurement=ddm_transfer&var-retention_policy=raw&from=now-30d&to=now"

    url = '<a target="_blank" href=' + link + ">link</a>";
    return url;
}

function link_to_old_atlas_dashboard(file, scope, rse) {
    var items = rse.split("_");
    var site = items.slice(0,-1).join('_');
    var token = items.slice(-1)[0];
    var link = "http://dashb-atlas-ddm-old.cern.ch/ddm2/#d.dst.site=";
    link += site;
    link += "&d.dst.token=";
    link += token;
    link += "&d.name=";
    link += file;
    link += "&d.scope=";
    link += scope;
    link += "&grouping.dst=%28site,token%29&tab=details";

    url = '<a target="_blank" href=' + link + ">old</a>";
    return url;
}


function show_details(file_data) {
    columns = [{'data': 'name'},
               {'data': 'rses'},
               {'data': 'ftsmon'},
               {'data': 'state'}
              ];
    columnDefs = [{'targets': [3],
                  'visible': false,
                  'searchable': true
                 }];

    if (policy == 'atlas') {
        columns = [{'data': 'name'},
                   {'data': 'rses'},
                   {'data': 'dashboard'},
                   {'data': 'ftsmon'},
                   {'data': 'state'}
                  ];
        columnDefs = [{'targets': [4],
                       'visible': false,
                       'searchable': true
                      }];
    }
    var dt = $('#dt_files').DataTable( {
        bAutoWidth: false,
        fnDrawCallback:update_links,
        columns: columns,
        columnDefs: columnDefs,
        oLanguage: {'sSearch': 'Search by name, RSE or state'}
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
        var str_state = "";

        $.each(sorted_rses, function(index, rse) {
            var state = rses[rse];
            str_rses += "<font color=";
            dashboard += "<div>" + link_to_new_atlas_dashboard(name, scope, rse) + " (" + link_to_old_atlas_dashboard(name, scope, rse) + ")</div>";
            if (state == 'OK') {
                str_rses += "green>" + rse;
                ftsmon += '<div style="visibility: hidden;">.</div>';
                str_state += 'Ok ';
            } else if (state == 'REPLICATING') {
                str_rses += "orange>" + rse;
                value = scope + ',' + name + ',' + rse;
                id = 'ftsmon' + i;
                ftsmon += '<div id=' + id + ' value=' + value + '>click to generate link</div>';
                ids.push(id);
                str_state += 'Replicating ';
            } else if (state == 'STUCK') {
                str_rses += "red>" + rse;
                value = scope + ',' + name + ',' + rse;
                id = 'ftsmon' + i;
                ftsmon += '<div id=' + id + ' value=' + value + '>click to generate link</div>';
                ids.push(id);
                str_state += 'Stuck ';
            }
            str_rses += "</font><br>";
            i += 1;
        });
        if (policy == 'atlas') {
            dt.row.add({'name': file,
                        'rses': str_rses,
                        'dashboard': dashboard,
                        'ftsmon': ftsmon,
                        'state': str_state
                       });
        } else {
            dt.row.add({'name': file,
                        'rses': str_rses,
                        'ftsmon': ftsmon,
                        'state': str_state
                       });
        }
    });
    dt.order([0, 'asc']).draw();
    if (url_param('lock_state') != '') {
        $('#dt_files').dataTable().fnFilter(url_param('lock_state'));
        window.location.hash = '#lock_states';
    }
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
    $("#show_locks").html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    r.get_replica_lock_for_rule_id({
        'rule_id': url_param('rule_id'),
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
            window.location.hash = '#locks';
            if (policy == 'atlas') {
                $("#locks_details").append("<h4 id=\"lock_states\">Lock States per File</h4><table id=\"dt_files\" class=\"compact stripe order-column cell-border\" style=\"word-wrap: break-word;\"><thead><th>Filename</th><th>RSEs</th><th>DDM Dashboard</th><th>FTS Monitoring</th></thead><tfoot><th>Filename</th><th>RSEs</th><th>DDM Dashboard</th><th>FTS Monitoring</th></tfoot></table>");
            } else {
                $("#locks_details").append("<h4 id=\"lock_states\">Lock States per File</h4><table id=\"dt_files\" class=\"compact stripe order-column cell-border\" style=\"word-wrap: break-word;\"><thead><th>Filename</th><th>RSEs</th><th>FTS Monitoring</th></thead><tfoot><th>Filename</th><th>RSEs</th><th>FTS Monitoring</th></tfoot></table>");
            }
            show_details(file_data);
            $("#show_locks").html("");
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $('#loading').html('Could not find the rule.');
        }
    });
}

function add_boost_button() {
    if ($.cookie('rucio-account-attr') == undefined) {
        return;
    }
    attrs = JSON.parse($.cookie('rucio-account-attr'));

    is_admin = false
    $.each(attrs, function(index, attr) {
        if (attr.key == 'admin' && attr.value == true) {
            is_admin = true;
        }
    });

    if (is_admin == false) {
        return;
    }

    $("#boost_button").html('<div class="button small expand">Boost rule</div>');

    $("#boost_button").click(function() {
        params = {};
        params['priority'] = 5;

        $("#boost_message").html('<img width="5%" height="5%" src="/media/spinner.gif">');
        r.update_replication_rule({
            'rule_id': url_param('rule_id'),
            'params': params,
            'success': function(data) {
                $('#boost_message').html('<font color="green">Successfully updated rule priority</font>');
            },
            error: function(jqXHR, textStatus, errorThrown)
            {
                if (jqXHR.status == 500) {
                    $('#boost_message').html('<font color="red">Cannot increase priority at the moment.</font>');
                    return;
                }
                excpt = JSON.parse(jqXHR.responseText)
                $('#boost_message').html('<font color="red">' + excpt['ExceptionMessage'] + '</font>');
            }
        })
    });
}

function load_examine() {
    $("#show_examine").html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    r.examine_rule({
        'rule_id': url_param('rule_id'),
        success: function(data) {
            $("#examine_details").append("<table id=\"dt_examine\" class=\"compact stripe order-column cell-border\" style=\"word-wrap: break-word;\"><thead><th>Filename</th><th>RSEs</th><th>Attempts</th><th>Last Retry</th><th>Last Error</th><th>Last Source</th><th>Available Source</th><th>Blacklisted Sources</th></thead><tfoot><th>Filename</th><th>RSEs</th><th>Attempts</th><th>Last Retry</th><th>Last Error</th><th>Last Source</th><th>Available Source</th><th>Blacklisted Sources</th></tfoot></table>");
            var dt = $('#dt_examine').DataTable( {
                bAutoWidth: false,
                fnDrawCallback:update_links,
                columns: [{'data': 'name'},
                          {'data': 'rse'},
                          {'data': 'attempts'},
                          {'data': 'last_time'},
                          {'data': 'last_error'},
                          {'data': 'last_source'},
                          {'data': 'available_srcs'},
                          {'data': 'blacklisted_srcs'}
                         ],
                oLanguage: {'sSearch': 'Search by name, RSE or state'}
            });
            $.each(data['transfers'], function(index, lock) {
                available_srcs = "";
                blacklisted_srcs = "";
                $.each(lock['sources'], function(index, src) {
                    if (src[1] == true) {
                        available_srcs += src[0] + ', ';
                    } else {
                        blacklisted_srcs += src[0] + ', ';
                    }
                });
                lock['available_srcs'] = available_srcs.slice(0, -2);
                lock['blacklisted_srcs'] = blacklisted_srcs.slice(0, -2);
                dt.row.add(lock);
            });
            dt.order([0, 'asc']).draw();
            $("#show_examine").html("");
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $("#show_examine").html("");
            $('#examine_details').html('<font color="red">Could not load the data.</font>');
        }
    });
}

$(document).ready(function(){
    $('#subbar-details').html('[' + url_param('rule_id') + ':' + url_param('name') + ']');

    if (url_param('action') != "") {
        if (url_param('action') == 'deny') {
            $('#denymodal').foundation('reveal', 'open');
            $('#confirm_deny_button').click(function() {
                comment = $('#deny_reason_input').val();
                approve_rule(url_param('rule_id'), url_param('action'), comment);
                $('#denymodal').foundation('reveal', 'close');
            });
        } else {
            approve_rule(url_param('rule_id'), url_param('action'));
        }
    }
    r.list_replication_rule({
        'rule_id': url_param('rule_id'),
        success: function(data) {
            $("#loading").html("");
            if (data == '') {
                $('#result').html('Could not find rule ' + url_param('rule_id'));
            } else {
                $("#locks").attr('class', 'columns panel');
                $("#locks").html("<h4 id=\"locks_title\">Locks Overview</h4><div id=\"show_locks\">Please click to show locks</div><div id=\"rseplot\"></div><div id=\"locks_details\"></div>");
                $("#show_locks").click(load_locks);
                var sorted_keys = Object.keys(data).sort();
                rse_expression = data['rse_expression'];
                if (data['expires_at'] == null) {
                    data['expires_at'] = 'never';
                } else {
                    expires_at = data['expires_at'];
                }
                if (data['state'] == 'STUCK') {
                    $("#examine").attr('class', 'columns panel');
                    $("#examine").html("<h4 id=\"locks_title\">Examine Rule</h4><div id=\"show_examine\">Please click to load detailed information about stuck locks. It may take a moment.</div><div id=\"examine_details\"></div>");
                    $("#show_examine").click(load_examine);
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
                            if (sorted_keys[i] == 'subscription_id') {
                                data[sorted_keys[i]] = "<a href=/subscription?id=" + data['subscription_id'] + ">" + data['subscription_id'] + "</a>";
                            }
                            if (sorted_keys[i] == 'expires_at') {
                                data[sorted_keys[i]] += '<i style="visibility:hidden;" class="step fi-plus"></i><a><i title="Extend expiration date" id="change_date" class="step fi-plus size-18"></i></a><i style="visibility:hidden;" class="step fi-plus"></i><a><i title="Remove expiration date" id="clear_date" class="step fi-x size-18"></i></a>';
                            }
                            $('#t_metadata').append($('<tr id="row_' + sorted_keys[i] + '"><th>' + sorted_keys[i] + '</th><td>' + data[sorted_keys[i]] + '</td></tr>'));
                            if (sorted_keys[i] == 'expires_at') {
                                $('#t_metadata').append($('<tr hidden id="row_datechanger"><th></th><td>Days to add to current lifetime: <input text="text" value="7" size="3" id="extension_days"/><a class="button tiny" id="extend_button" style="height: 1.7rem;">Apply</a> <div id="ext_error"></div></div></td></tr>'));
                                $('#extend_button').click(extend_expiration);
                            }
                            if (sorted_keys[i] == 'child_rule_id') {
                                data[sorted_keys[i]] = "<a href=/rule?rule_id=" + data['child_rule_id'] + ">" + data['child_rule_id'] + "</a>";
                            }

                        }
                    }
                }

                $('#clear_date').click(clear_date);
                $('#change_date').click(function() {
                    if ($('#row_datechanger').is(":hidden")) {
                        $('#row_datechanger').slideDown();
                    } else {
                        $('#row_datechanger').hide();
                    }
                });
                if (url_param('show_locks') == 'true') {
                    window.location.hash = '#locks';
                    load_locks();
                }
                add_boost_button();
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $('#loading').html('<font color="red">Could not find the rule.</font>');
        }});
});
