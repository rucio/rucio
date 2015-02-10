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

var html_table = '<h4>Rules</h4><form><div id="selector_row" class="row collapse"><div class="large-2 columns"><label>Endpoint<select id="endpoint_selector"></select></label></div><div class="large-2 columns"><label>State<select id="state_selector"></select></label></div><div class="large-2 columns"><label>Data Type<select id="datatype_selector"></select></label></div><div class="large-2 columns"><label>Project<select id="project_selector"></select></label></div><div class="large-2 columns"><label>Stream<select id="stream_selector"></select></label></div><div class="large-2 columns"><label>Age<select id="age_selector"><option value=""></option><option value="6h">6 hours</option><option value="12h">12 hours</option><option value="16h">18 hours</option><option value="1d">1 day</option><option value="2d">2 days</option><option value="4d">4 days</option></select></label></div></div></form><div id="loader"></div><div id="selector"></div><table id="resulttable" class="compact stripe order-column" style="word-wrap: break-word;"><thead><tr><th>Name</th><th>Endpoint</th><th>State</th><th>Creation Date</th><th>Data Type</th><th>Project</th><th>Stream</th><th>Version</th><th>OK</th><th>Replicating</th><th>Stuck</th></tr></thead><tfoot><tr><th>Name</th><th>Endpoint</th><th>State</th><th>Creation Date</th><th>Data Type</th><th>Project</th><th>Stream</th><th>Version</th><th>OK</th><th>Replicating</th><th>Stuck</th></tr></tfoot></table>';

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
        if (locks_rep != 0 && locks_stuck != 0) {
            var ratio = locks_ok / (locks_ok + locks_rep + locks_stuck) * 100;
            if (ratio >= 90.0) {
                state += 'green">90% transfers done</font>';
            }
        }
        else if (locks_rep == 0 && locks_stuck == 0) {
            state += 'green">Done</font>';
        } else if (locks_rep != 0 && locks_stuck == 0) {
            state += 'orange">Transferring</font>';
        } else {
            state += 'red">Stuck</font>';
        }
    } else {
        if (locks_rep != 0 && locks_stuck == 0) {
            state += 'pink">Subscribed</font>';
        } else if (locks_rep != 0 && locks_stuck != 0) {
            state += 'red">Stuck</font>';
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


load_data = function(account, activity) {
    $('#loader').html('<b>loading data .... please wait, this may take some time...</b><p>');

    $('#results').html(html_table);
    r.list_account_rules({
        account: account,
        activity: activity,
        state: '',
        rse_expression: '',
        success: function(data) {
            var filtered_data = [];
            var ok_threshold = age_to_date('1d');
            $.each(data, function(index, value) {
                var created_at = Date.parse(value.created_at);
                if (value.state == "OK" && created_at < ok_threshold) {
                    return;
                }
                metadata = get_metadata(value.name);
                value.link = '<a href="/rule?rule_id=' + value.id + '">' + value.name + '</a>';
                value.state = get_state(value.locks_ok_cnt, value.locks_replicating_cnt, value.locks_stuck_cnt);
                value.datatype = metadata.datatype;
                value.stream = metadata.stream_name;
                value.version = 0;
                value.project = metadata.project;
                filtered_data.push(value);
            });

            var dt = $('#resulttable').DataTable( {
                data: filtered_data,
                paging: false,
                autoWidth: true,
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
                columns: [{'data': 'link'},
                          {'data': 'rse_expression'},
                          {'data': 'state'},
                          {'data': 'created_at'},
                          {'data': 'datatype'},
                          {'data': 'project'},
                          {'data': 'stream'},
                          {'data': 'version'},
                          {'data': 'locks_ok_cnt'},
                          {'data': 'locks_replicating_cnt'},
                          {'data': 'locks_stuck_cnt'}]
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

}

$(document).ready(function(){
    var url_account = url_param('account');
    var url_activity = url_param('activity');

    $("#load_button").click(function(event) {
        chosen_account = $("#account_input").val();
        chosen_activity = $("#activity_input").val();

        if (chosen_account != "" && chosen_activity != "" ) {
            load_data(chosen_account, chosen_activity);
        }
    });
    if (url_account != "" && url_activity != "") {
        $("#account_input").val(url_account);
        $("#activity_input").val(url_activity);
        load_data(url_account, url_activity);
    }
});
