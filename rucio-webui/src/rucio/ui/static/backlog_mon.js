/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2015-2020
 */

var html_table = '<h4>Rules</h4><form><div id="selector_row" class="row collapse"><div class="large-2 columns"><label>Data Type<select id="datatype_selector"></select></label></div><div class="large-2 columns"><label>Project<select id="project_selector"></select></label></div><div class="large-2 columns"><label>Stream<select id="stream_selector"></select></label></div><div id="selector"><div class="large-5 columns"></div><div class="large-1 columns"><label style="visibility: hidden;">.</label><a class="button postfix inline" id="url_button">Get Link</a></div> </div><table id="resulttable" class="compact stripe order-column" style="word-wrap: break-word; width: 100%;"><thead><tr><th>Name</th><th>Endpoint</th><th>State</th><th>Creation Date</th><th>Data Type</th><th>Project</th><th>Stream</th><th>Version</th><th>OK</th><th>Replicating</th><th>Stuck</th></tr></thead><tfoot><tr><th>Name</th><th>Endpoint</th><th>State</th><th>Creation Date</th><th>Data Type</th><th>Project</th><th>Stream</th><th>Version</th><th>OK</th><th>Replicating</th><th>Stuck</th></tr></tfoot></table>';


age_to_date = function(age) {
    if (age == '') {
        return '';
    }
    var type = age.slice(-1);
    if (type != 'd' && type != 'h') {
        return new Date();
    }
    var interval = parseInt(age.slice(0,-1));
    var today = new Date();
    if (type == 'h') {
        return new Date(today.getTime() - (interval*1000*60*60)).toUTCString().slice(0,-3) + 'UTC';
    } else {
        return new Date(today.getTime() - (interval*1000*60*60*24)).toUTCString().slice(0,-3) + 'UTC';
    }
};


get_metadata = function(name) {
    var splits = name.split('.');
    var metadata = {'project': splits[0], 'stream_name': splits[2], 'datatype': splits[4], 'version': splits[5]};
    return metadata;
};


get_state = function(locks_ok, locks_rep, locks_stuck) {
    if (locks_ok != 0) {
        if (locks_rep != 0) {
            if (locks_stuck != 0) {
                return 'stuck';
            } else {
                var ratio = locks_ok / (locks_ok + locks_rep) * 100;
                if (ratio >= 90.0) {
                    return '90% transfers done';
                } else {
                    return 'transferring';
                }
            }
        } else {
            if (locks_stuck != 0) {
                return 'stuck';
            } else {
                return 'done';
            }
        }
    } else {
        if (locks_rep != 0) {
            if (locks_stuck != 0) {
                return 'stuck';
            } else {
                return 'subscribed';
            }
        } else {
            if (locks_stuck != 0) {
                return 'stuck';
            } else {
                return 'initialised';
            }
        }
    }
};


get_color_state = function(locks_ok, locks_rep, locks_stuck, show_state) {
    var color = '<font color="';
    var state = get_state(locks_ok, locks_rep, locks_stuck);
    if (state == 'done') {
        color += 'green">Done</font>';
    } else if (state == '90% transfers done') {
        color += 'green">90% transfers done</font>';
    } else if (state == 'transferring') {
        color += 'orange">Transferring</font>';
    } else if (state == 'initialised') {
        color += 'black">Initialised</font>';
    } else if (state == 'subscribed') {
        color += 'pink">Subscribed</font>';
    } else if (state == 'stuck') {
        color += 'red">Stuck</font>';
    }
    return color;
};


apply_selects = function() {
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
};


load_data = function(account, activity, created_after, created_before, rse, state) {
    $("#results").html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    r_state = '';
    if (state == 'done' || state == 'initialised') {
        r_state = 'O';
    } else if (state == 'stuck') {
        r_state = 'S';
    } else if (state == 'transferring' || state == '90% transfers done' || state == 'subscribed') {
        r_state = 'R';
    }

    r.list_rules({
        account: account,
        activity: activity,
        state: r_state,
        rse_expression: rse,
        created_before: created_before,
        created_after: created_after,
        success: function(data) {
            var filtered_data = [];
            $.each(data, function(index, value) {
                if (state != '') {
                    if (get_state(value.locks_ok_cnt, value.locks_replicating_cnt, value.locks_stuck_cnt) != state) {
                        return;
                    }
                }

                if (value.name.startsWith('data') || value.name.startsWith('mc')) {
                    metadata = get_metadata(value.name);
                    value.datatype = metadata.datatype;
                    value.stream = metadata.stream_name;
                    value.version = 0;
                    value.project = metadata.project;
                } else {
                    value.datatype = '';
                    value.stream = '';
                    value.version = '';
                    value.project = '';
                }
                value.link = '<a href="/rule?rule_id=' + value.id + '">' + value.name + '</a>';
                value.state = get_color_state(value.locks_ok_cnt, value.locks_replicating_cnt, value.locks_stuck_cnt, state);
                if (value.locks_ok_cnt > 0) {
                    value.locks_ok_cnt = '<font color="green">' + value.locks_ok_cnt + '</font>';
                }
                if (value.locks_replicating_cnt > 0) {
                    value.locks_replicating_cnt = '<a href="/rule?rule_id=' + value.id + '&show_locks=true&lock_state=replicating" style="color: orange">' + value.locks_replicating_cnt + '</a>';
                }
                if (value.locks_stuck_cnt > 0) {
                    value.locks_stuck_cnt = '<a href="/rule?rule_id=' + value.id + '&show_locks=true&lock_state=stuck" style="color: red">' + value.locks_stuck_cnt + '</a>';
                }
                value.created_at = new Date(value.created_at).toISOString();
                filtered_data.push(value);
            });

            $('#results').html(html_table);
            $("#url_button").click(function(event) {
                show_link();
            });

            var dt = $('#resulttable').DataTable( {
                data: filtered_data,
                paging: false,
                "bAutoWidth": false,
                initComplete: function () {
                    var api = this.api();
                    api.columns().indexes().flatten().each( function ( i ) {
                        var column = api.column( i );
                        if ($(column.header()).text() == 'Name' ||$(column.header()).text() == 'Endpoint' || $(column.header()).text() == 'State' ||  $(column.header()).text() == 'Creation Date' || $(column.header()).text() == 'OK' || $(column.header()).text() == 'Replicating' || $(column.header()).text() == 'Stuck'  || $(column.header()).text() == 'Version') {
                            return;
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
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (errorThrown == "Not Found") {
                $('#problem').html("No rules found");
            }
        }
    });
};


get_url = function() {
    var chosen_account = $("#account_input").val();
    var chosen_activity = $("#activity_input").val();
    var endpoint = $("#rse_input").val()
    var state = $("#state_selector").val();
    var datatype = $("#datatype_selector").val();
    var project = $("#project_selector").val();
    var stream = $("#stream_selector").val();
    var age = $("#age_selector").val();
    var age_mode = $("#age_mode_selector").val();

    var link = window.location.href.split('?')[0];
    link += '?account=' + encodeURIComponent(chosen_account);
    link += "&activity=" + encodeURIComponent(chosen_activity);
    if (endpoint != "" && endpoint != undefined) {
        link += "&endpoint=" + encodeURIComponent(endpoint);
    }
    if (state != "" && state != undefined) {
        link += "&state=" + encodeURIComponent(state);
    }
    /*if (datatype != "" && datatype != undefined) {
        link += "&datatype=" + encodeURIComponent(datatype);
    }
    if (project != "" && project != undefined) {
        link += "&project=" + encodeURIComponent(project);
    }
    if (stream != "" && stream != undefined) {
        link += "&stream=" + encodeURIComponent(stream);
    }*/
    if (age != "" && age != undefined) {
        link += "&age=" + encodeURIComponent(age);
    }
    if (age_mode != "" && age_mode != undefined) {
        link += "&age_mode=" + encodeURIComponent(age_mode);
    }

    return link;
};


show_link = function() {
    link = get_url();
    $("#copyurl").html("<a href=" + link + ">" + link + "</a>");
    $('#myModal').foundation('reveal', 'open');
};


enter_key = function(e) {
    if (e.keyCode == 13) {
        trigger_load();
    }
};


trigger_load = function() {
    chosen_account = $("#account_input").val();
    chosen_activity = $("#activity_input").val();
    chosen_rse = $("#rse_input").val();
    chosen_state = $("#state_selector").val();
    chosen_age_mode = $("#age_mode_selector").val();
    chosen_age = age_to_date($("#age_selector").val());

    if (chosen_account != "") {
        if (chosen_activity == "") {
            chosen_activity = "default";
            }
        if (chosen_age_mode == 'younger') {
            load_data(chosen_account, chosen_activity, chosen_age, '', chosen_rse, chosen_state);
        } else {
            load_data(chosen_account, chosen_activity, '', chosen_age, chosen_rse, chosen_state);
        }
    } else {
        $('#results').html('<font color="red">You have to specify an account</font>');
    }
};


$(document).ready(function(){
    r.list_rses({
        success: function(data) {
            rses = [];
            $.each(data, function(index, value) {
                rses.push(value['rse']);
            });
            $("#rse_input").autocomplete({
                source: rses
            });
        }
    });

    var url_account = url_param('account');
    var url_activity = url_param('activity');
    var url_age = url_param('age');
    var url_age_mode = url_param('age_mode');
    var url_state = url_param('state');
    var url_rse = url_param('endpoint');

    url_param = false;

    chosen_account = '';
    chosen_activity = '';
    chosen_age = '12h';
    chosen_age_mode = 'younger';
    chosen_state = '';
    chosen_rse = '';

    if (url_account != "") {
        url_param = true;
        chosen_account = url_account;
    }

    if (url_activity != "") {
        url_param = true;
        chosen_activity = url_activity;
    }
    if (url_age != "") {
        url_param = true;
        if (url_age == '6h' || url_age == '12h' || url_age == '18h' || url_age == '1d' || url_age == '2d' || url_age == '4d') {
            chosen_age = url_age;
        } else {
            chosen_age = '12h';
        }
    }

    if (url_age_mode != "") {
        chosen_age_mode = url_age_mode;
    }

    if (url_state != "") {
        url_param = true;
        chosen_state = url_state.toLowerCase();
    }

    if (url_rse != "") {
        url_param = true;
        chosen_rse = url_rse;
    }

    if (url_param) {
        $('#account_input').val(chosen_account);
        $('#activity_input').val(chosen_activity);
        $('#rse_input').val(chosen_rse);
        $('#state_selector').val(chosen_state);
        $('#age_selector').val(chosen_age);
        $('#age_mode_selector').val(chosen_age_mode);
        chosen_age = age_to_date(chosen_age);
        if (chosen_age_mode == 'younger') {
            load_data(chosen_account, chosen_activity, chosen_age, '', chosen_rse, chosen_state);
        } else {
            load_data(chosen_account, chosen_activity, '', chosen_age, chosen_rse, chosen_state);
        }
    }

    $("#load_button").click(trigger_load);

    $('#account_input').keyup(enter_key)
    $('#activity_input').keyup(enter_key);
    $('#rse_input').keyup(enter_key);
});
