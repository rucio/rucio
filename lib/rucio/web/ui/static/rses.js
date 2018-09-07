/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2017
 * - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018
 */

list_rses = function() {
    r.list_rses({
        success: function(data) {
            $('#loader').html("");
            $.each(data, function(index, item) {
                item['link'] = '<a href="/rse?rse=' + item['rse'] + '">' + item['rse'] + '</a>';
            });
            var dt = $('#resulttable').DataTable({
                data: data,
                bAutoWidth: false,
                pageLength: 100,
                columns: [{'data': 'link'},
                          {'data': 'rse_type'},
                          {'data': 'city'},
                          {'data': 'region_code'},
                          {'data': 'country_name'},
                          {'data': 'ISP'},
                          {'data': 'time_zone'},
                          {'data': 'deterministic'},
                          {'data': 'volatile'},
                          {'data': 'staging_area'}]
            });
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (errorThrown == "Not Found") {
                $('#loader').html("");
                $('#error').html("No RSEs found");
            }
        }
    })
};

$(document).ready(function(){
    list_rses();
});
