/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2020
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2017
 */

display_data = function(data, chosen_account, date, hour, minutes) {
    var tmp = {};
    $.each(data, function(index, value) {
        var { name, state } = value;
        var sub_state = state;
        var count = 0;
        if("count" in value) {
            count = value.count;
        }
        if (sub_state == 'INACTIVE') {
            return;
        }
        if (acc != chosen_account) {
            return true;
        }
        if (!(name in tmp)) {
            tmp[name] = [0, 0, 0, 0];
        }
        if (state == 'OK') {
            if (count > 0){
                tmp[name][0] = '<a href="/subscriptions/rules?name=' + name + '&state=O' + '&account=' + chosen_account + '">' + count + '</a>';
            }
        } else if (state == 'REPLICATING') {
            if (count > 0){
                tmp[name][1] = '<a href="/subscriptions/rules?name=' + name + '&state=R' + '&account=' + chosen_account + '">' + count + '</a>';
            }
        } else if (state == 'STUCK'){
            if (count > 0){
                tmp[name][2] = '<a href="/subscriptions/rules?name=' + name + '&state=S' + '&account=' + chosen_account + '">' + count + '</a>';
            }
        } else if (state == 'SUSPENDED'){
            if (count > 0){
                tmp[name][3] = '<a href="/subscriptions/rules?name=' + name + '&state=U' + '&account=' + chosen_account + '">' + count + '</a>';
            }
        }
    });
    data = [];
    $.each(tmp, function(key, values) {
        data.push({'name': '<a href="/subscription?name=' + key + '&account=' + chosen_account + '">' + key + '</a>', 'ok': values[0], 'rep': values[1], 'stuck': values[2], 'suspended': values[3]});
    });
    if (data.length == 0) {
        $('#loader').html('No subscriptions found for the chosen account (' + chosen_account + ')');
        $('#resulttable').html('');
        return;
    }
    var dt = $('#resulttable').DataTable( {
        data: data,
        bAutoWidth: false,
        pageLength: 100,
        columns: [{'data': 'name'},
                  {'data': 'ok'},
                  {'data': 'rep'},
                  {'data': 'stuck'},
                  {'data': 'suspended'}]
    });
    $('#resulttable_length').find('select').attr('style', 'width: 4em;');
    $('#resulttable_filter').find('input').attr('style', 'width: 10em; display: inline');
    dt.order([0, 'asc']).draw();
    $('#loader').html('');
    $('#last_update').html('<font color="orange">Last Update: ' + date + " " + hour + ":" + minutes + '</font>');
}

get_date = function(period) {
    var now = new Date((new Date).getTime() - period*60000);
    var date = now.getFullYear() + '-';
    if ((now.getMonth() + 1) < 10) {
        date += '0' + (now.getMonth() + 1);
    } else {
        date += (now.getMonth() + 1);
    }
    date += '-';
    if (now.getDate() < 10) {
        date += '0' + now.getDate();
    } else {
        date += now.getDate();
    }
    var hour = now.getHours();
    if (hour < 10) {
        hour = '0' + hour;
    }
    var minutes = Math.floor((now.getMinutes()) / 10) * 10;
    if (minutes < 10) {
        minutes = '0' + minutes;
    }

    return [date, hour, minutes];
}

retrieve_data = function(chosen_account, try_cnt) {
    if (try_cnt > 2) {
        $('#loader').html('<font color="red">Cannot find subscription monitor data for the last hour</font></br>');
        return;
    }
    date = get_date(try_cnt*10);

    r.list_subscription_rules_state_real_time({
        date: date[0],
        hour: date[1],
        minutes: date[2],
        account: chosen_account,
        success: function(data) {
            if (data.length == 0) {
                retrieve_data(chosen_account, try_cnt + 1);
                return;
            }
            display_data(data, chosen_account, date[0], date[1], date[2]);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (errorThrown == "Not Found") {
                $('#loader').html("No subscriptions found");
            }
        }
    });
}

$(document).ready(function(){
    var chosen_account = account;

    if (url_param('account')) {
        chosen_account = url_param('account');
    } else {
        insertParam('account', chosen_account);
    }

    var link_list_rules = '/r2d2?account=' + chosen_account;
    $("#show_rules").attr("href", link_list_rules);
    $('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div><br>');
    $('#subbar-details').html('[' + chosen_account + ']');

    retrieve_data(chosen_account, 0);
});
