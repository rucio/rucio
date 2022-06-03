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
    url: "/http-monitoring/data?report=per_scriptid&date="+date,
    crossDomain: true,
    success: function(csv) {
      drawChartV('#scriptids > .chart.hits', 'Requests per Script', csv2chart(csv, 3, 4, 20, true));
      drawChartV('#scriptids > .chart.mb', 'Bandwidth per Script (MB)', csv2chart(csv, 3, 5, 20, true, (1/(1024*1024))));
      drawChartV('#scriptids > .chart.sec', 'Response time per Script (Sec)', csv2chart(csv, 3, 6, 20, true, (1/10000)));
      fillTable(csv,date);
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#scriptids > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));
      $('#scriptids > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));
      $('#scriptids > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));
    }
  });
}

function fillTable(csv,date) {
  var tbl_data = [],
      cols = undefined,
      scriptID = undefined,
      splitted = csv.split('\n'),
      aggregatedData = {};
  for(var i=0; i < splitted.length; i++) {
    if (splitted == '') continue;
    cols = splitted[i].split('\t');
    if((cols.length < 7) || (isNaN(cols[4])) || (isNaN(cols[5])) || (isNaN(cols[6])))
      continue;
    scriptID = cols[3];
    if (aggregatedData[scriptID] == undefined)  aggregatedData[scriptID] = {'hits': 0, 'mb': 0, 'sec': 0};
    aggregatedData[scriptID].hits += Number(cols[4]);
    aggregatedData[scriptID].mb += Number(cols[5]);
    aggregatedData[scriptID].sec += Number(cols[6]);
  }
  for(var scriptID in aggregatedData) {
    tbl_data.push(["<a href=\"/webstats/scriptids/"+scriptID+"?date="+date+"\">"+scriptID+"</a>",
                    aggregatedData[scriptID].hits,
                    (aggregatedData[scriptID].mb/1024/1024).toFixed(2),
                    (aggregatedData[scriptID].sec/10000).toFixed(2)]);
  }
  $('#script_activity').DataTable().destroy();
  $('#script_activity').DataTable({
    data: tbl_data,
    aoColumns: [
      {'width': '35%'},
      {'class': 'align-right'},
      {'class': 'align-right'},
      {'class': 'align-right'}
    ],
    "order": [[ 3, "desc" ]],
    "bFilter": true,
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
  window.history.replaceState(undefined, "Scripts  " + reportDate , "/webstats/scriptids?date="+reportDate);
}
