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

    $('#subbar-details').html('[' + url_param('account') + ', ' + url_param('name') + ', ' + url_param('state') + ']');

    $('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    r.list_replication_rules({
        account: url_param('account'),
        name: url_param('name'),
        state: url_param('state'),
        success: function(data) {
            $.each(data, function(index, value) {
                value.name = '<a href="/rule?rule_id=' + value.id + '">' + value.name + '</a>';
                if (value.locks_ok_cnt > 0) {
                    value.locks_ok_cnt = '<font color="green">' + value.locks_ok_cnt + '</font>';
                }
                if (value.locks_replicating_cnt > 0) {
                    value.locks_replicating_cnt = '<font color="orange">' + value.locks_replicating_cnt + '</font>';
                }
                if (value.locks_stuck_cnt > 0) {
                    value.locks_stuck_cnt = '<font color="red">' + value.locks_stuck_cnt + '</font>';
                }

            });
            $('#results').html('<table id="resulttable" class="compact stripe order-column" style="word-wrap: break-word;"><thead><tr><th>Name</th><th>Creation Date</th><th>Locks OK</th><th>Locks Replicating</th><th>Locks Stuck</th></tr></thead><tfoot><tr><th>Name</th><th>Creation Date</th><th>Locks OK</th><th>Locks Replicating</th><th>Locks Stuck</th></tr></tfoot></table>');

            var dt = $('#resulttable').DataTable( {
                data: data,
                bAutoWidth: false,
                pageLength: 100,
                "oLanguage": {
                        "sProcessing": "test..."
                    },
                columns: [{'data': 'name', width: '60%'},
                          {'data': 'created_at', width: '22%'},
                          {'data': 'locks_ok_cnt', width: '6%'},
                          {'data': 'locks_replicating_cnt', width: '6%'},
                          {'data': 'locks_stuck_cnt', width: '6%'}]
            });
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
});
