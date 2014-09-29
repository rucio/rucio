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

    jQuery.ajax({url: '//rucio-hadoop.cern.ch/dump_overview.lst',
                 success: function(data) {

                     data = data.split('\n');
                     data.pop()

                     var bytes = [];
                     var previous = 0;
                     var tmp_v = 0;

                     data.forEach(function(e) {
                         e = e.split('\t');
                         tmp_v = parseInt(e[0], 10);

                         if (tmp_v > 9000000000000000000) {
                             bytes.push([new Date(e[2]), previous]);
                         } else {
                             previous = tmp_v;
                             bytes.push([new Date(e[2]), tmp_v]);
                         }

                     });

                     $('#gridview').highcharts({
                         yAxis: {
                             title: {
                                 text: 'Bytes'
                             },
                             min: 0
                         },
                         xAxis: {
                             type: 'datetime',
                             title: {
                                 text: 'Date'
                             }
                         },
                         credits: false,
                         title: { text: 'ATLAS Data Overview' },
                         subtitle: { text: 'Worldwide' },
                         series: [{name: 'Bytes', data: bytes}]
                     });
                 },
                 error: function() {
                     usage_data = [];
                 }
                });
});
