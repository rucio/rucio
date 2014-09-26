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
    var usage_data = [];

    $('#gridview').highcharts({
        plotOptions: { series: { animation: false } },
        credits: false,
        title: { text: 'Files in Rucio' },
        subtitle: { text: 'Worldwide' },
        series: [{
            name: 'Files',
            data: [7.0, 6.9, 9.5, 14.5, 18.2, 21.5, 25.2, 26.5, 23.3, 18.3, 13.9, 9.6]
        }]
    });
/*
    r.list_rse_usage_history({
        account: account,
        rse: 'RUCIO',
        source: 'rucio',
        success: function(data) {
            $.each(data, function(index, value) {
                var date = Date.parse(value.updated_at);
                usage_data.push([date, value.free, value.used]);
            })
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $('#gridview').html(errorThrown);
        }
    });
    */
});
