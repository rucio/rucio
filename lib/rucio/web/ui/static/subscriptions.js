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

$(document).ready(function(){

    var chosen_account = account;

    if (url_param('account')) {
        chosen_account = url_param('account');
    }

    $('#subbar-details').html('[' + chosen_account + ']');
    r.list_subscription_rules_state({
        account: chosen_account,
        name: 'none',
        success: function(data) {
            var tmp = {};
            $.each(data, function(index, value) {
                name = value[1];
                state = value[2];
                count = parseInt(value[3]);
                if (!(name in tmp)) {
                    tmp[name] = [0, 0, 0, 0];
                }
                if (state == 'OK') {
                    if (count > 0){
                        tmp[name][0] = '<a href="/subscriptions/rules?name=' + name + '&state=' + state + '&account=' + account + '">' + count + '</a>';
                    }
                } else if (state == 'REPLICATING') {
                    if (count > 0){
                        tmp[name][1] = '<a href="/subscriptions/rules?name=' + name + '&state=Replicating' + '&account=' + account + '">' + count + '</a>';
                    }
                } else if (state == 'STUCK'){
                    if (count > 0){
                        tmp[name][2] = '<a href="/subscriptions/rules?name=' + name + '&state=Stuck' + '&account=' + account + '">' + count + '</a>';
                    }
                } else if (state == 'SUSPENDED'){
                    if (count > 0){
                        tmp[name][3] = '<a href="/subscriptions/rules?name=' + name + '&state=Suspended' + '&account=' + account + '">' + count + '</a>';
                    }
                }
            });

            data = [];
            $.each(tmp, function(key, values) {
                    data.push({'name': key, 'ok': values[0], 'rep': values[1], 'stuck': values[2], 'suspended': values[3]});
            });

            var dt = $('#resulttable').DataTable( {
                data: data,
                bAutoWidth: false,
                columns: [{'data': 'name'},
                          {'data': 'ok'},
                          {'data': 'rep'},
                          {'data': 'stuck'},
                          {'data': 'suspended'}]
            });
            $('#resulttable_length').find('select').attr('style', 'width: 4em;');
            $('#resulttable_filter').find('input').attr('style', 'width: 10em; display: inline');
            dt.order([0, 'asc']).draw();
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (errorThrown == "Not Found") {
                $('#problem').html("No subscriptions found");
            }
        }
    });
});
