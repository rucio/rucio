/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Ralph Vigne <ralph.vigne@cern.ch> 2015
 * - Thomas Beermann <thomas.beermann@cern.ch> 2015
 */

var oTable = undefined;

function loadData(date) {
  $.ajax({
    url: "/http-monitoring/data?report=per_apiclass&date="+date,
    crossDomain: true,
    success: function(csv) {
      drawDoubleChart('#apiclasses > .chart.hits', "Requests per API Class/HTTP Verb",
                      {name: 'API Class', pattern: /^(.*\..*)\..*$/},
                      {name: 'HTTP Verb', pattern: /(.*)/},
                      csv2chart(csv, 2, 4, undefined, true)); /// aggregated is true due cover different client versions
      drawDoubleChart('#apiclasses > .chart.mb', "Bandwidth (MB) per API Class/HTTP Verb",
                      {name: 'API Class', pattern: /^(.*\..*)\..*$/},
                      {name: 'HTTP Verb', pattern: /(.*)/},
                      csv2chart(csv, 2, 5, undefined, true, (1/(1024*1024)))); /// aggregated is true due cover different client versions
      drawDoubleChart('#apiclasses > .chart.sec', "Response time (Sec) per API Class/HTTP Verb",
                      {name: 'API Class', pattern: /^(.*\..*)\..*$/},
                      {name: 'HTTP Verb', pattern: /(.*)/},
                      csv2chart(csv, 2, 6, undefined, true, (1/1000000))); /// aggregated is true due cover different client versions
      fillTable(csv, date);
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#apiclasses > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));
      $('#apiclasses > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));
      $('#apiclasses > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));
    }
  });
}

function fillTable(csv,date) {
  var tbl_data = [],
      cols = undefined,
      classID = undefined,
      splitted = csv.split('\n'),
      aggregatedData = {};
  for(var i=0; i < splitted.length; i++) {
    if (splitted == '') continue;
    cols = splitted[i].split('\t');
    if((cols.length < 7) || (isNaN(cols[4])) || (isNaN(cols[5])) || (isNaN(cols[6])))
      continue;
    classID = cols[2].match(/^(\w+\.\w+)/)[1];
    if (aggregatedData[classID] == undefined)  aggregatedData[classID] = {'hits': 0, 'mb': 0, 'sec': 0};
    aggregatedData[classID].hits += Number(cols[4]);
    aggregatedData[classID].mb += Number(cols[5]);
    aggregatedData[classID].sec += Number(cols[6]);
  }
  for(var classID in aggregatedData) {
    tbl_data.push(["<a href=\"/webstats/apiclasses/"+classID+"?date="+date+"\">"+classID+"</a>",
                    aggregatedData[classID].hits,
                    (aggregatedData[classID].mb/1024/1024).toFixed(2),
                    (aggregatedData[classID].sec/1000000).toFixed(2)]);
  }
  $('#apiclass_activity').DataTable().destroy();
  $('#apiclass_activity').DataTable({
    data: tbl_data,
    aoColumns: [
      {'width': '35%'},
      {'class': 'align-right'},
      {'class': 'align-right'},
      {'class': 'align-right'}
    ],
    "order": [[ 3, "desc" ]],
    "bFilter": false,
    "bLengthChange": false,
    "bAutoWidth": true,
    "iDisplayLength": 10
  });
}

$(document).ready(function() {
  initDatePicker(dateChange);
  dateChange($('.datepicker-tab').first().val());
});


function dateChange(reportDate) {
  loadData(reportDate);
  $('.datepicker-tab').each(function () { $(this).datepicker("setDate", reportDate) });
  window.history.replaceState(undefined, "API Classes " + reportDate , "/webstats/apiclasses?date="+reportDate);
}
