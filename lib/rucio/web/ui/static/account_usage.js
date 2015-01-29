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

$(document).ready(function(){
    r.get_account_usage_from_dumps({
        success: function(ret_data) {
            var str_data = ret_data.split('\n');
            var data = [];
            $.each(str_data, function(index, value) {
                if (value == "") {
                    return;
                }
                values = value.split('\t');
                var tmp = {};
                tmp['account'] = values[0];
                tmp['rse'] = values[1];
                tmp['quota'] = values[2];
                tmp['usage'] = values[3];
                tmp['difference'] = values[4];
                tmp['total_quota'] = values[5];
                tmp['total_used'] = values[6];
                data.push(tmp);
            });
            
            var dt = $('#resulttable').DataTable( {
                data: data,
                bAutoWidth: false,
                paging: false,
                columns: [{'data': 'account'},
                          {'data': 'rse'},
                          {'data': 'quota'},
                          {'data': 'usage'},
                          {'data': 'difference'},
                          {'data': 'total_quota'},
                          {'data': 'total_used'}]
            });
            dt.order([0, 'asc']).draw();
            $('#loader').html('');
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (errorThrown == "Not Found") {
                $('#problem').html("Cannot load account usage");
                $('#loader').html('');
            }
        }
    });
});
