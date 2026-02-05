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
            let sanitisedData = Array();
            $.each(data, function(index, item) {
                sanitisedData[index] = {
                    'link': $('<div>').append($('<a></a>', {'href': '/rse?rse=' + item['rse']}).text(item['rse'])).html(),
                    'rse_type': $('<div>').text(item.rse_type).html(),
                    'city': $('<div>').text(item.city).html(),
                    'region_code': $('<div>').text(item.region_code).html(),
                    'country_name': $('<div>').text(item.country_name).html(),
                    'ISP': $('<div>').text(item.ISP).html(),
                    'time_zone': $('<div>').text(item.time_zone).html(),
                    'deterministic': $('<div>').text(item.deterministic).html(),
                    'volatile': $('<div>').text(item.volatile).html(),
                    'staging_area': $('<div>').text(item.staging_area).html(),
                };
            });
            var dt = $('#resulttable').DataTable({
                data: sanitisedData,
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
