/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2015
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 */

$(document).ready(function(){
    var chosen_account = account;

    if (url_param('account')) {
        chosen_account = url_param('account');
    } else {
        insertParam('account', chosen_account);
    }

    var link_list_rules = '/list_rules?account=' + chosen_account;
    $("#show_rules").attr("href", link_list_rules);
    $('#loader').html('<b>loading data .... please wait, this may take some time...</b><p>');
    $('#subbar-details').html('[' + chosen_account + ']');

    var now = new Date();
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
    var minutes = Math.floor((now.getMinutes() - 1) / 10) * 10;
    if (minutes < 10) {
        minutes = '0' + minutes;
    }
    r.list_subscription_rules_state_from_dumps({
        date: date,
        hour: hour,
        minutes: minutes,
        success: function(data) {
            var tmp = {};
            data = data.split('\n');
            $.each(data, function(index, value) {
                values = value.split('\t');
                var acc = values[0];
                var name = values[1];
                var state = values[2];
                var count = parseInt(values[3]);
                var sub_state = values[4];
                if (sub_state == 'I') {
                    return;
                }
                if (acc != chosen_account) {
                    return true;
                }
                if (!(name in tmp)) {
                    tmp[name] = [0, 0, 0, 0];
                }
                if (state == 'O') {
                    if (count > 0){
                        tmp[name][0] = '<a href="/subscriptions/rules?name=' + name + '&state=OK' + '&account=' + chosen_account + '">' + count + '</a>';
                    }
                } else if (state == 'R') {
                    if (count > 0){
                        tmp[name][1] = '<a href="/subscriptions/rules?name=' + name + '&state=Replicating' + '&account=' + chosen_account + '">' + count + '</a>';
                    }
                } else if (state == 'S'){
                    if (count > 0){
                        tmp[name][2] = '<a href="/subscriptions/rules?name=' + name + '&state=Stuck' + '&account=' + chosen_account + '">' + count + '</a>';
                    }
                } else if (state == 'U'){
                    if (count > 0){
                        tmp[name][3] = '<a href="/subscriptions/rules?name=' + name + '&state=Suspended' + '&account=' + chosen_account + '">' + count + '</a>';
                    }
                }
            });
            data = [];
            $.each(tmp, function(key, values) {
                data.push({'name': '<a href="/subscription?name=' + key + '&account=' + chosen_account + '">' + key + '</a>', 'ok': values[0], 'rep': values[1], 'stuck': values[2], 'suspended': values[3]});
            });
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
            $('#last_update').html('Last Update: ' + date + " " + hour + ":" + minutes);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (errorThrown == "Not Found") {
                $('#problem').html("No subscriptions found");
                $('#loader').html('');
            }
        }
    });
});
