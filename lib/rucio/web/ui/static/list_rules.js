/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2015, 2017
 */

var dt = null;

update_rule_lifetime = function(id) {
    r.update_replication_rule({
        rule_id: id,
        params: {'lifetime': 3600},
        async: false,
        success: function(data) {
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert(jqXHR['responseText']);
        }
    });
}

format_time = function(s) {
    var ret = "";
    if (s < 3600) {
        s = s / 60;
        ret = Math.ceil(s) + "m";
    } else if (s >= 3600 && s < 86400) {
        s = s / 3600;
        ret = Math.ceil(s) + "h";
    } else if (s >= 86400) {
        s = s / 86400;
        ret = Math.ceil(s) + "d";
    }
    return ret;
}

age_to_date = function(age) {
    var type = age.split(' ')[1];
    if (type != 'days' && type != 'hours' && type != 'minutes') {
        return new Date(today.getTime() - (14*1000*60*60*24)).toUTCString().slice(0,-3) + 'UTC';
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
    $('#results_panel').hide();
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
    } else if (state.toLowerCase() == 'waiting_approval') {
        state = 'W';
    } else if (state.toLowerCase() == 'inject') {
        state = 'I';
    } else if (state.toLowerCase() == 'suspended') {
        state = 'U';
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
            $('#results_panel').show();
            $.each(data, function(index, value) {
                var time_to_expire = 10000;
                value.lifetime = "-";
                if (value.expires_at != undefined) {
                    time_to_expire = parseInt(((new Date(value.expires_at)) - (new Date())) / 1000);
                    value.lifetime = '<span data-tooltip aria-haspopup="true" class="has-tip" title="Expires at: ' + value.expires_at + '">' + format_time(time_to_expire) + '</span>';
                }
                new_name = "";
                name_split = value.name.split('.');
                $.each(name_split, function(index, split) {
                    if (index != name_split.length-1 ) {
                        new_name += split + '.<wbr>';
                    } else {
                        new_name += split;
                    }
                });

                if (time_to_expire < 3600) {
                    value.link = '<i title="This rule will expire in less than an hour" class="step fi-alert size-18"></i> <a href="/rule?rule_id=' + value.id + '">' + value.scope + ':' + new_name + '</a>';
                } else {
                    value.link = '<a href="/rule?rule_id=' + value.id + '">' + value.scope + ':' + new_name + '</a>';
                }
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
                if (value.state == 'WAITING_APPROVAL') {
                    value.state = '<font color="purple">' + value.state + '</font>';
                }
                if (value.state == 'INJECT') {
                    value.state = '<font color="pink">' + value.state + '</font>';
                }

                filtered_data.push(value);
            });

            var download = '<a href="data:application/octet-stream;base64,' + btoa(JSON.stringify(filtered_data)) + '" download="' + download_name + '">download as JSON</a>';
            $('#downloader').html(download);

            if (dt != null ) {
                dt.destroy();
            } else {
                $("#resulttable").on('click', 'tr', function() {
                    $(this).toggleClass('selected');
                });
            }

            dt = $('#resulttable').DataTable( {
                data: filtered_data,
                bAutoWidth: false,
                pageLength: 100,
                "oLanguage": {
                        "sProcessing": "test..."
                    },
                columns: [{'data': 'link', width: '30%'},
                          {'data': 'account', width: '7%'},
                          {'data': 'rse_expression', width: '18%'},
                          {'data': 'created_at', width: '10%'},
                          {'data': 'lifetime', width: '7%'},
                          {'data': 'state', width: '10%'},
                          {'data': 'locks_ok_cnt', width: '5%'},
                          {'data': 'locks_replicating_cnt', width: '7%'},
                          {'data': 'locks_stuck_cnt', width: '6%'}]
            });
            $("#selectall").html("<a class=\"button small\" id=\"selectall_button\">Select all</a>");
            $("#delete").html("<a class=\"alert button tiny\" id=\"delete_button\">Delete rule(s)</a>");

            $('#selectall_button').on('click', function() {
                $.each(dt.rows({filter: 'applied'}).nodes(), function(index, row) {
                    $(row).addClass('selected');
                });
            });

            $('#delete_button').click( function () {
                if ( dt.rows('.selected').data().length == 0) {
                    alert("you have to select a rule first");
                    return;
                }
                var info_text = "This will delete the following rule(s) in 1 hour from now:\n";
                $.each(dt.rows('.selected').data(), function(index, row) {
                    var name = row['name'];
                    var rse = row['rse_expression'];
                    info_text += '\n' + name + ' at ' + rse;
                });
                info_text += '\n\nAre you sure?';
                var ok = confirm(info_text);

                if (ok) {
                    $.each(dt.rows('.selected').data(), function(index, row) {
                        var id = row['id'];
                        update_rule_lifetime(id);
                    });

                    location.reload();
                }

            } );
            $('#resulttable_length').find('select').attr('style', 'width: 4em;');
            $('#resulttable_filter').find('input').attr('style', 'width: 10em; display: inline');
            dt.order([3, 'desc']).draw();
            $('#loader').html('');
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $('#loader').html('<text color="red">' + jqXHR.responseText.split(':')[1] + '</text></br>');
        }
    });
};

apply_selects = function () {
    $('#date_panel').slideUp();
    chosen_account = $("#account_input").val();
    chosen_rse = $("#rse_input").val();
    chosen_activity = $("#activity_input").val();
    chosen_state = $("#state_selector").val();
    chosen_age = $("#age_input").val();
    chosen_age_type = $("#age_selector").val();

    created_after = "";
    created_before = "";
    if (chosen_age != 'custom') {
        created_after = age_to_date(chosen_age + ' ' + chosen_age_type);
    } else {
        created_after = new Date($('#datepicker1').val()).toUTCString().slice(0,-3) + 'UTC';
        created_before = new Date($('#datepicker2').val()).toUTCString().slice(0,-3) + 'UTC';
    }
    get_rules(chosen_account, chosen_rse, chosen_activity, chosen_state, created_before, created_after)
};


$(document).ready(function(){
    $('#results_panel').hide();
    start_date = new Date();
    start_date.setDate(start_date.getDate()-14);
    $("#datepicker1").datepicker({
        defaultDate: start_date,
        onSelect: function(){
            $('#age_input').val('custom');
            from_date = $("#datepicker1").val();
            $("#datepicker2").datepicker('setDate', from_date).datepicker('option', 'minDate', from_date);
        }
    });
    $("#datepicker2").datepicker({
        defaultDate: new Date(),
        onSelect: function(){
            $('#age_input').val('custom');
            to_date = $("#datepicker2").val();
        }
    });

    var chosen_account = "";
    var chosen_activity = "";
    var chosen_rse = "";
    var chosen_state = "";
    var chosen_interval = "14 days";
    var params_used = false;
    if (url_param('account') != '') {
        chosen_account = url_param('account');
        params_used = true;
    }

    if (url_param('rse') != '') {
        chosen_rse = url_param('rse');
        params_used = true;
    }

    if (url_param('activity') != '') {
        chosen_activity = url_param('activity');
        params_used = true;
    }

    if (url_param('state') != '') {
        chosen_state = url_param('state');
        params_used = true;
    }

    created_before = "";
    created_after = age_to_date('14 days');
    if (url_param('interval') != '') {
        interval = url_param('interval');

        value = interval.slice(0,-1);
        if (interval.slice(-1) == 'd') {
            created_after = age_to_date(value + ' days')
            $('#age_input').val(value);
            $('#age_selector').val('days');
        } else if (interval.slice(-1) == 'h') {
            created_after = age_to_date(value + ' hours')
            $('#age_input').val(value);
            $('#age_selector').val('hours');
        } else if (interval.slice(-1) == 'm') {
            created_after = age_to_date(value + ' minutes')
            $('#age_input').val(value);
            $('#age_selector').val('minutes');
        } else {
            $('#loader').html('Please give a correct interval. E.g., 2d, 12h or 2m');
            return;
        }
        params_used = true;
    }

    if (!params_used) {
        chosen_activity = "User Subscriptions";
        chosen_account = account;
    }
    $("#account_input").val(chosen_account);
    $("#rse_input").val(chosen_rse);
    $("#activity_input").val(chosen_activity);
    $("#state_selector").val(chosen_state.toUpperCase());

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

    $('#apply_button').click(apply_selects);

    $("#account_input").keypress(function(event){
        if(event.keyCode == 13){
            apply_selects();
        }
    });

    $("#rse_input").keypress(function(event){
        if(event.keyCode == 13){
            apply_selects();
        }
    });

    $("#activity_input").keypress(function(event){
        if(event.keyCode == 13){
            apply_selects();
        }
    });

    $("#age_input").keypress(function(event){
        if(event.keyCode == 13){
            apply_selects();
        }
    });

});
