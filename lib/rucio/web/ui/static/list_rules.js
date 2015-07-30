/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2015
 */

var dt = null;

update_rule_lifetime = function(id) {
    r.update_replication_rule({
        rule_id: id,
        params: {'lifetime': 7*86400},
        success: function(data) {
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert(jqXHR['responseText']);
        }
    });
}

age_to_date = function(age) {
    var type = age.split(' ')[1];
    if (type != 'days' && type != 'hours' && type != 'minutes') {
        return new Date();
    }
    var interval = parseInt(age.split(' ')[0]);
    var today = new Date();
    if (type == 'days') {
        return new Date(today.getTime() - (interval*1000*60*60*24)).toUTCString().slice(0,-3) + 'UTC';
    } else if (type == 'hours') {
        return new Date(today.getTime() - (interval*1000*60*60)).toUTCString().slice(0,-3) + 'UTC';
    } else {
        return new Date(today.getTime() - (interval*1000*60)).toUTCString().slice(0,-3) + 'UTC';
    }
}

get_rules = function(account, rse, activity, state, created_before, created_after) {
    var download_name = "rules_" + account;
    if (state != "") {
        download_name += "_" + state;
    }
    if (activity != "") {
        download_name += "_" + activity;
    }
    download_name += ".json";

    if (state.toLowerCase() == 'replicating') {
        state = 'R';
    } else if (state.toLowerCase() == 'ok') {
        state = 'O';
    } else if (state.toLowerCase() == 'stuck') {
        state = 'S';
    } else {
        state = '';
    }

    $('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div><br>');
    r.list_rules({
        account: account,
        rse_expression: rse,
        activity: activity,
        created_after: created_after,
        created_before: created_before,
        state: state,
        success: function(data) {
            var filtered_data = [];
            //var threshold = age_to_date(age);
            $.each(data, function(index, value) {
                //var created_at = Date.parse(value.created_at);
                //if (created_at > threshold) {
                //    return;
                //}
                value.link = '<a href="/rule?rule_id=' + value.id + '">' + value.name + '</a>';
                if (value.locks_ok_cnt > 0) {
                    value.locks_ok_cnt = '<font color="green">' + value.locks_ok_cnt + '</font>';
                }
                if (value.locks_replicating_cnt > 0) {
                    value.locks_replicating_cnt = '<a href="/rule?rule_id=' + value.id + '&show_locks=true&lock_state=replicating" style="color: orange">' + value.locks_replicating_cnt + '</a>';
                }
                if (value.locks_stuck_cnt > 0) {
                    value.locks_stuck_cnt = '<a href="/rule?rule_id=' + value.id + '&show_locks=true&lock_state=stuck" style="color: red">' + value.locks_stuck_cnt + '</a>';
                }
                if (value.state == 'OK') {
                    value.state = '<font color="green">' + value.state + '</font>';
                }
                if (value.state == 'REPLICATING') {
                    value.state = '<font color="orange">' + value.state + '</font>';
                }
                if (value.state == 'STUCK') {
                    value.state = '<font color="red">' + value.state + '</font>';
                }
                filtered_data.push(value);
            });

            var download = '<a href="data:application/octet-stream;base64,' + btoa(JSON.stringify(filtered_data)) + '" download="' + download_name + '">download as JSON</a>';
            $('#downloader').html(download);

            if ( $.fn.dataTable.isDataTable( '#resulttable' ) ) {
                table = $('#resulttable').DataTable();
                table.destroy();
            }
            dt = $('#resulttable').DataTable( {
                data: filtered_data,
                bAutoWidth: false,
                pageLength: 100,
                "oLanguage": {
                        "sProcessing": "test..."
                    },
                columns: [{'data': 'link', width: '30%'},
                          {'data': 'rse_expression', width: '20%'},
                          {'data': 'created_at', width: '20%'},
                          {'data': 'state', width: '12%'},
                          {'data': 'locks_ok_cnt', width: '5%'},
                          {'data': 'locks_replicating_cnt', width: '7%'},
                          {'data': 'locks_stuck_cnt', width: '6%'}]
            });
            $("#delete").html("<a class=\"button tiny\" id=\"delete_button\">delete rule</a>");
            $("#resulttable").on('click', 'tr', function() {
                if ( $(this).hasClass('selected') ) {
                    $(this).removeClass('selected');
                }
                else {
                    dt.$('tr.selected').removeClass('selected');
                    $(this).addClass('selected');
                }
            });

            $('#delete_button').click( function () {
                if ( dt.rows('.selected').data().length == 0) {
                    alert("you have to select a rule first");
                    return;
                }
                var name = dt.row('.selected').data()['name'];
                var rse = dt.row('.selected').data()['rse_expression'];
                var ok = confirm("This will set the lifetime to 1 week from now for the rule for " + name + " at " + rse + ", are you sure?");
                if (ok) {
                    var id = dt.row('.selected').data()['id'];
                    update_rule_lifetime(id);
                }

            } );
            $('#resulttable_length').find('select').attr('style', 'width: 4em;');
            $('#resulttable_filter').find('input').attr('style', 'width: 10em; display: inline');
            dt.order([0, 'asc']).draw();
            $('#loader').html('');
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (errorThrown == "Not Found") {
                $('#problem').html("No rules found");
            }
        }
    });

}

$(document).ready(function(){
    $('#subbar-details').html('[' + url_param('account') + ', ' + url_param('name') + ', ' + url_param('state') + ', ' + url_param('rse_expression')+ ']');

    start_date = new Date();
    start_date.setDate(start_date.getDate()-14);
    $("#datepicker1").datepicker({
        defaultDate: start_date,
        onSelect: function(){
            $('#age_input').val('');
            from_date = $("#datepicker1").val();
            $("#datepicker2").datepicker('setDate', from_date).datepicker('option', 'minDate', from_date);
        }
    });
    $("#datepicker2").datepicker({
        defaultDate: new Date(),
        onSelect: function(){
            $('#age_input').val('');
            to_date = $("#datepicker2").val();
        }
    });

    var chosen_account = "";
    var chosen_activity = "";
    var chosen_rse = "";
    var chosen_state = "";
    if (url_param('account') != undefined) {
        chosen_account = url_param('account');
        $("#account_input").val(chosen_account);
    }

    if (url_param('rse') != undefined) {
        chosen_rse = url_param('rse');
        $("#rse_input").val(chosen_rse);
    }

    if (url_param('activity') != undefined) {
        chosen_activity = url_param('activity');
        $("#activity_input").val(chosen_activity);
    }

    if (url_param('state') != undefined) {
        chosen_state = url_param('state');
        $("#state_selector").val(chosen_state.toUpperCase());
    }

    var state = url_param('state');
    var age = '14d';

    if (url_param('age') != undefined) {
        age = url_param('age');
    }

    created_before = "";
    if (url_param('older_than') != "") {
        created_before = age_to_date(url_param('older_than'));
    }

    created_after = age_to_date('14 days');
    if (url_param('younger_than') != "") {
        created_after = age_to_date(url_param('younger_than'));
    }

    get_rules(chosen_account, chosen_rse, chosen_activity, chosen_state, created_before, created_after);
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

    $('#custom_dates').click( function () {
        if ($('#date_panel').is(":hidden")) {
            $('#date_panel').slideDown();
        } else {
            $('#date_panel').slideUp();
        }
    });

    $('#apply_button').click( function () {
        $('#date_panel').slideUp();
        chosen_account = $("#account_input").val();
        chosen_rse = $("#rse_input").val();
        chosen_activity = $("#activity_input").val();
        chosen_state = $("#state_selector").val();
        chosen_age = $("#age_input").val();
        chosen_age_type = $("#age_selector").val();

        created_after = "";
        created_before = "";
        if (chosen_age.length > 0) {
            created_after = age_to_date(chosen_age + ' ' + chosen_age_type);
        } else {
            created_after = new Date($('#datepicker1').val()).toUTCString().slice(0,-3) + 'UTC';
            created_before = new Date($('#datepicker2').val()).toUTCString().slice(0,-3) + 'UTC';
        }

        get_rules(chosen_account, chosen_rse, chosen_activity, chosen_state, created_before, created_after)
    });

});
