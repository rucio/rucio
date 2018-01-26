/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2015-2016, 2018
 */

var dt = null;

approve_rule = function(id, approve, comment) {
    r.update_replication_rule({
        rule_id: id,
        params: {'approve': approve, 'comment': comment},
        async: true,
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

get_rules = function(account, rse, activity, created_before, created_after) {
    $('#results_panel').hide();

    $('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div><br>');
    r.list_rules({
        account: account,
        rse_expression: rse,
        activity: activity,
        created_after: created_after,
        created_before: created_before,
        state: 'W',
        success: function(data) {
            var filtered_data = [];
            $.each(data, function(index, value) {
                new_name = ""
                name_split = value.name.split('.');
                $.each(name_split, function(index, split) {
                    if (index != name_split.length-1 ) {
                        new_name += split + '.<wbr>';
                    } else {
                        new_name += split;
                    }
                });

                value.link = '<a href="/rule?rule_id=' + value.id + '">' + value.scope + ':' + new_name + '</a>';

                value.approve = '<a id="approve_' + value.id + '" href="#" class="button tiny success postfix inline">Approve</a>';
                value.deny = '<a id="deny_' + value.id + '" href="#" class="button tiny alert postfix inline">Deny</a>';

                value.open = "[loading]";
                value.filesize = "[loading]";
                value.length = "[loading]";
                                   
                filtered_data.push(value);
            });

            if (dt != null ) {
                dt.destroy();
            }

            dt = $('#resulttable').DataTable( {
                data: filtered_data,
                bAutoWidth: false,
                pageLength: 100,
                "oLanguage": {
                        "sProcessing": "test..."
                    },
                columns: [{'data': 'link', width: '15%'},
                          {'data': 'account', width: '5%'},
                          {'data': 'rse_expression', width: '10%'},
                          {'data': 'created_at', width: '10%'},
                          {'data': 'expires_at', width: '10%'},
                          {'data': 'filesize', width: '5%'},
                          {'data': 'length', width: '5%'},
                          {'data': 'open', width: '5%'},
                          {'data': 'did_type', width: '5%'},
                          {'data': 'grouping', width: '5%'},
                          {'data': 'comments', width: '15%'},
                          {'data': 'approve', width: '5%'},
                          {'data': 'deny', width: '5%'}]
            });

            $('#resulttable_length').find('select').attr('style', 'width: 4em;');
            $('#resulttable_filter').find('input').attr('style', 'width: 10em; display: inline');

            $('#results_panel').show();

            num_rules = dt.rows().eq(0).length
            rules_cnt = 0;
            dt.rows().eq(0).each(function(index){
                var d = dt.row(index).data();
                r.get_did({
                    scope: d.scope,
                    name: d.name,
                    dynamic: true,
                    async: true,
                    success: function(meta) {
                        d.open = meta.open;
                        d.filesize = filesize(meta.bytes, {'base': 10});
                        d.length = meta.length;
                        dt.row(index).data(d).draw();
                        rules_cnt += 1;
                        if (rules_cnt == num_rules) {
                            dt.order([3, 'desc']).draw();
                            $('#loader').html('');
                            $.each(filtered_data, function(index, value) {
                                $('#approve_' + value.id).click(function() {
                                    rule_id = this.id.split('_')[1];
                                    approve_rule(rule_id, true);
                                    dt.row($(this).parents('tr')).remove().draw();
                                });
                                $('#deny_' + value.id).click(function() {
                                    $('#denymodal').foundation('reveal', 'open');

                                    rule_id = this.id.split('_')[1];
                                    var tmp = $(this).parents('tr');
                                    $('#confirm_deny_button').attr("rule_id", rule_id)
                                    $('#confirm_deny_button').click(function() {
                                        $("#deny_reason_input").focus();
                                        rule_id = this.attributes.rule_id.value;
                                        comment = $('#deny_reason_input').val();
                                        approve_rule(rule_id, false, comment);
                                        dt.row(tmp).remove().draw();
                                        $('#denymodal').foundation('reveal', 'close');
                                    });
                                });
                            });
                        }
                    },
                    error: function(jqXHR, textStatus, errorThrown) {
                        $('#loader').html('<text color="red">' + jqXHR.responseText.split(':')[1] + '</text></br>');
                    }
                });
            });
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
    console.log(chosen_age);
    if (chosen_age != '') {
        if (chosen_age != 'custom') {
            created_after = age_to_date(chosen_age + ' ' + chosen_age_type);
        } else {
            created_after = new Date($('#datepicker1').val()).toUTCString().slice(0,-3) + 'UTC';
            created_before = new Date($('#datepicker2').val()).toUTCString().slice(0,-3) + 'UTC';
        }
    }
    console.log(created_before);
    get_rules(chosen_account, chosen_rse, chosen_activity, created_before, created_after)
};

function check_priviliges() {
    if ($.cookie('rucio-account-attr') == undefined) {
        return false;
    }
    attrs = JSON.parse($.cookie('rucio-account-attr'));

    found = false;
    $.each(attrs, function(index, attr) {
        if ((attr.key == 'admin' && attr.value == true) || (attr.key.startsWith('country-') && attr.value == 'admin')) {
            found = true;
        }
    });
    return found;
};

$(document).ready(function(){
    $('#subbar-details').html('[' + url_param('account') + ', ' + url_param('name') + ', ' + url_param('state') + ', ' + url_param('rse_expression')+ ']');

    if (check_priviliges() == false) {
        $('#results').html('<font color="red">Your account does not have the rights to display this page.</font>');
        return;
    }
    r.get_account_info({
        account: account,
        success: function(info) {
            console.log(info);
        }, error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });

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
    var chosen_activity = "User Subscriptions";
    var chosen_rse = "";
    if (url_param('account') != '') {
        chosen_account = url_param('account');
        $("#account_input").val(chosen_account);
    }

    if (url_param('rse') != '') {
        chosen_rse = url_param('rse');
        $("#rse_input").val(chosen_rse);
    }

    if (url_param('activity') != '') {
        chosen_activity = url_param('activity');
        $("#activity_input").val(chosen_activity);
    }

    created_before = "";
    created_after = "";
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
        age = url_param('age');
    }

    get_rules(chosen_account, chosen_rse, chosen_activity, created_before, created_after);
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
