/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2015
 */

var html_table = '<h4>Rules</h4><form><div id="selector_row" class="row collapse"><div class="large-2 columns"><label>Endpoint<select id="endpoint_selector"></select></label></div><div class="large-2 columns"><label>State<select id="state_selector"></select></label></div><div class="large-2 columns"><label>Data Type<select id="datatype_selector"></select></label></div><div class="large-2 columns"><label>Project<select id="project_selector"></select></label></div><div class="large-2 columns"><label>Stream<select id="stream_selector"></select></label></div><div class="large-2 columns"><label>Age<select id="age_selector"><option value=""></option><option value="6h">6 hours</option><option value="12h">12 hours</option><option value="16h">18 hours</option><option value="1d">1 day</option><option value="2d">2 days</option><option value="4d">4 days</option></select></label></div></div></form><div id="loader"></div><div id="selector"></div><table id="resulttable" class="compact stripe order-column" style="word-wrap: break-word; width: 100%;"><thead><tr><th>Name</th><th>Endpoint</th><th>State</th><th>Creation Date</th><th>Data Type</th><th>Project</th><th>Stream</th><th>Version</th><th>OK</th><th>Replicating</th><th>Stuck</th></tr></thead><tfoot><tr><th>Name</th><th>Endpoint</th><th>State</th><th>Creation Date</th><th>Data Type</th><th>Project</th><th>Stream</th><th>Version</th><th>OK</th><th>Replicating</th><th>Stuck</th></tr></tfoot></table>';

age_to_date = function(age) {
    var type = age.slice(-1);
    if (type != 'd' && type != 'h') {
        return new Date();
    }
    var interval = parseInt(age.slice(0,-1));
    var today = new Date();
    if (type == 'h') {
        return new Date(today.getTime() - (interval*1000*60*60));
    } else {
        return new Date(today.getTime() - (interval*1000*60*60*24));
    }
}

get_metadata = function(name) {
    var splits = name.split('.');
    var metadata = {'project': splits[0], 'stream_name': splits[2], 'datatype': splits[4], 'version': splits[5]};
    return metadata;
}

get_state = function(locks_ok, locks_rep, locks_stuck) {
    var state = '<font color="';
    if (locks_ok != 0) {
        if (locks_rep != 0) {
            if (locks_stuck != 0) {
                state += 'red">Stuck</font>';
            } else {
                var ratio = locks_ok / (locks_ok + locks_rep) * 100;
                if (ratio >= 90.0) {
                    state += 'green">90% transfers done</font>';
                } else {
                    state += 'orange">Transferring</font>';
                }
            }
        } else {
            if (locks_stuck != 0) {
                state += 'red">Stuck</font>';
            } else {
                state += 'green">Done</font>';
            }
        }
    } else {
        if (locks_rep != 0) {
            if (locks_stuck != 0) {
                state += 'red">Stuck</font>';
            } else {
                state += 'pink">Subscribed</font>';
            }
        } else {
            if (locks_stuck != 0) {
                state += 'red">Stuck</font>';
            } else {
                state += 'black">Initialised</font>';
            }
        }
    }
    return state;
}

$.fn.dataTable.ext.search.push(
    function( settings, data, dataIndex ) {
        var created_at = Date.parse(data[3]);
        var threshold = $("#age_selector").val();
        if (threshold == "") {
            return true;
        }
        threshold = age_to_date(threshold);
        if (created_at < threshold) {
            return true;
        }
        return false;
    }
);

apply_selects = function() {
    var endpoint = url_param('endpoint');
    if (endpoint != "") {
        $("#endpoint_selector").val(endpoint);
        $("#endpoint_selector").trigger("change");
    }
    var state = url_param('state');
    if (state != "") {
        $("#state_selector").val(state);
        $("#state_selector").trigger("change");
    }
    var datatype = url_param('datatype');
    if (datatype != "") {
        $("#datatype_selector").val(datatype);
        $("#datatype_selector").trigger("change");
    }
    var project = url_param('project');
    if (project != "") {
        $("#project_selector").val(project);
        $("#project_selector").trigger("change");
    }
    var stream = url_param('stream');
    if (stream != "") {
        $("#stream_selector").val(stream);
        $("#stream_selector").trigger("change");
    }
    var age = url_param('age');
    if (age != "") {
        $("#age_selector").val(age);
        $("#age_selector").trigger("change");
    }
}


load_data = function(account, activity, first) {
    $("#results").html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    r.list_account_rules({
        account: account,
        activity: activity,
        state: '',
        rse_expression: '',
        success: function(data) {
            var filtered_data = [];
            var ok_threshold = age_to_date('7d');
            $.each(data, function(index, value) {
                var created_at = Date.parse(value.created_at);
                if (value.state == "OK" && created_at < ok_threshold) {
                    return;
                }
                metadata = get_metadata(value.name);
                value.link = '<a href="/rule?rule_id=' + value.id + '">' + value.name + '</a>';
                value.state = get_state(value.locks_ok_cnt, value.locks_replicating_cnt, value.locks_stuck_cnt);
                if (value.locks_ok_cnt > 0) {
                    value.locks_ok_cnt = '<font color="green">' + value.locks_ok_cnt + '</font>';
                }
                if (value.locks_replicating_cnt > 0) {
                    value.locks_replicating_cnt = '<a href="/rule?rule_id=' + value.id + '&show_locks=true&lock_state=replicating" style="color: orange">' + value.locks_replicating_cnt + '</a>';
                }
                if (value.locks_stuck_cnt > 0) {
                    value.locks_stuck_cnt = '<a href="/rule?rule_id=' + value.id + '&show_locks=true&lock_state=stuck" style="color: red">' + value.locks_stuck_cnt + '</a>';
                }

                value.datatype = metadata.datatype;
                value.stream = metadata.stream_name;
                value.version = 0;
                value.project = metadata.project;
                filtered_data.push(value);
            });

            $('#results').html(html_table);
            var dt = $('#resulttable').DataTable( {
                data: filtered_data,
                paging: false,
                "bAutoWidth": false,
                initComplete: function () {
                    var api = this.api();
                    api.columns().indexes().flatten().each( function ( i ) {
                        var column = api.column( i );
                        if ($(column.header()).text() == 'Name' || $(column.header()).text() == 'Creation Date' || $(column.header()).text() == 'OK' || $(column.header()).text() == 'Replicating' || $(column.header()).text() == 'Stuck'  || $(column.header()).text() == 'Version') {
                            return;
                        }
                        if ($(column.header()).text() == 'Endpoint') {
                            var select = $("#endpoint_selector");
                        }
                        if ($(column.header()).text() == 'State') {
                            var select = $("#state_selector");
                        }
                        if ($(column.header()).text() == 'Data Type') {
                            var select = $("#datatype_selector");
                        }
                        if ($(column.header()).text() == 'Project') {
                            var select = $("#project_selector");
                        }
                        if ($(column.header()).text() == 'Stream') {
                            var select = $("#stream_selector");
                        }
                        select.append( '<option value=""></option>' );
                        select.on( 'change', function () {
                            var val = $(this).val();

                            column.search( val ? '^'+val+'$' : '', true, false ).draw()
                        } );

                        column.data().unique().sort().each( function ( d, j ) {
                            if ($(column.header()).text() == 'State') {
                                d = $(d).text();
                            }
                            select.append( '<option value="'+d+'">'+d+'</option>' )
                        });
                    } );
                },
                "oLanguage": {
                        "sProcessing": "test..."
                    },
                columns: [{'data': 'link', 'width': '20%'},
                          {'data': 'rse_expression', 'width': '15%'},
                          {'data': 'state', 'width': '5%'},
                          {'data': 'created_at', 'width': '12%'},
                          {'data': 'datatype', 'width': '8%'},
                          {'data': 'project', 'width': '8%'},
                          {'data': 'stream', 'width': '10%'},
                          {'data': 'version', 'width': '7%'},
                          {'data': 'locks_ok_cnt', 'width': '5%'},
                          {'data': 'locks_replicating_cnt', 'width': '5%'},
                          {'data': 'locks_stuck_cnt', 'width': '5%'}]
            });
            dt.order([2, 'desc'], [3, 'asc']).draw();
            $('#loader').html('');
            $("#age_selector").on( 'change', function () {
                dt.draw();
            } );
            if (first) {
                apply_selects();
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (errorThrown == "Not Found") {
                $('#problem').html("No rules found");
            }
        }
    });
}

generate_link = function() {
    var chosen_account = $("#account_input").val();
    var chosen_activity = $("#activity_input").val();
    var endpoint = $("#endpoint_selector").val()
    var state = $("#state_selector").val();
    var datatype = $("#datatype_selector").val();
    var project = $("#project_selector").val();
    var stream = $("#stream_selector").val();
    var age = $("#age_selector").val();

    var link = window.location.href.split('?')[0];
    link += '?account=' + encodeURIComponent(chosen_account);
    link += "&activity=" + encodeURIComponent(chosen_activity);
    if (endpoint != "" && endpoint != undefined) {
        link += "&endpoint=" + encodeURIComponent(endpoint);
    }
    if (state != "" && state != undefined) {
        link += "&state=" + encodeURIComponent(state);
    }
    if (datatype != "" && datatype != undefined) {
        link += "&datatype=" + encodeURIComponent(datatype);
    }
    if (project != "" && project != undefined) {
        link += "&project=" + encodeURIComponent(project);
    }
    if (stream != "" && stream != undefined) {
        link += "&stream=" + encodeURIComponent(stream);
    }
    if (age != "" && age != undefined) {
        link += "&age=" + encodeURIComponent(age);
    }

    $("#copyurl").html("<a href=" + link + ">" + link + "</a>");
    $('#myModal').foundation('reveal', 'open');
}

$(document).ready(function(){
    var url_account = url_param('account');
    var url_activity = url_param('activity');

    $("#load_button").click(function(event) {
        chosen_account = $("#account_input").val();
        chosen_activity = $("#activity_input").val();

        if (chosen_account != "" && chosen_activity != "" ) {
            load_data(chosen_account, chosen_activity, first=false);
        }
    });
    if (url_account != "" && url_activity != "") {
        $("#account_input").val(url_account);
        $("#activity_input").val(url_activity);
        load_data(url_account, url_activity, first=true);
    }

    $("#url_button").click(function(event) {
        generate_link();
    });

    $('#activity_input').keyup(function(e) {
        if (e.keyCode == 13) {
            chosen_account = $("#account_input").val();
            chosen_activity = $("#activity_input").val();

            if (chosen_account != "" && chosen_activity != "" ) {
                load_data(chosen_account, chosen_activity, first=false);
            }
        }
    });

});
