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
            var overview = {};
            $.each(str_data, function(index, value) {
                if (value == "") {
                    return;
                }
                values = value.split('\t');
                var tmp = {};
                var tmp_overview = {};
                var to_tb = 1000*1000*1000*1000;
                tmp['account'] = values[0];
                tmp['rse'] = values[1];
                tmp['quota'] = (parseInt(values[2]) / to_tb).toFixed(2);
                tmp['usage'] = (parseInt(values[3]) / to_tb).toFixed(2);
                tmp['difference'] = (parseInt(values[4]) / to_tb).toFixed(2);
                tmp['total_quota'] = (parseInt(values[5]) / to_tb).toFixed(2);
                tmp['total_used'] = (parseInt(values[6]) / to_tb).toFixed(2);
                tmp['total_difference'] = (tmp['total_quota'] - tmp['total_used']).toFixed(2);
                data.push(tmp);

                tmp_overview['account'] = values[0];
                tmp_overview['quota'] = tmp['total_quota'];
                tmp_overview['usage'] = tmp['total_used'];
                tmp_overview['difference'] = tmp['total_difference'];

                if (overview[values[0]] == undefined) {
                    overview[values[0]] = tmp_overview;
                }
            });

            var data_overview = [];
            $.each(overview, function(key, value) {
                data_overview.push(value);
            });

            var dt_overview = $('#resulttable_overview').DataTable( {
                data: data_overview,
                bAutoWidth: false,
                paging: false,
                columns: [{'data': 'account'},
                          {'data': 'quota'},
                          {'data': 'usage'},
                          {'data': 'difference'}]
            });
            dt_overview.order([0, 'asc']).draw();

            var dt = $('#resulttable_details').DataTable( {
                data: data,
                bAutoWidth: false,
                paging: false,
                columns: [{'data': 'account'},
                          {'data': 'rse'},
                          {'data': 'quota'},
                          {'data': 'usage'},
                          {'data': 'difference'}]
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
