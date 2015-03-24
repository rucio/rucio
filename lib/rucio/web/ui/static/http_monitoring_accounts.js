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
    url: "/http-monitoring/data?report=per_account&date="+date,
    crossDomain: true,
    success: function(csv) {
      drawChartV('#accounts > .chart.hits', 'Requests per Account', csv2chart(csv, 1, 2, 10));
      drawChartV('#accounts > .chart.mb', 'Bandwidth per Account (MB)', csv2chart(csv, 1, 3, 10, undefined, (1/(1024*1024))));
      drawChartV('#accounts > .chart.sec', 'Response time per Account (Sec)', csv2chart(csv, 1, 4, 10, undefined, (1/1000000)));
      fillTable(csv,date);
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#accounts > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#accounts > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#accounts > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));  
    }
  });
  $.ajax({
    url: "/http-monitoring/data?report=per_country&date="+date,
    crossDomain: true,
    success: function(csv) {
      drawChartV('#accounts2 > .chart.hits', 'Requests per Country', csv2chart(csv, 2, 4, 10, true));
      drawChartV('#accounts2 > .chart.mb', 'Bandwidth per Country (MB)', csv2chart(csv, 2, 5, 10, true, (1/(1024*1024))));
      drawChartV('#accounts2 > .chart.sec', 'Response time per Country (Sec)', csv2chart(csv, 2, 5, 10, true, (1/1000000)));
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#accounts2 > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#accounts2 > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#accounts2 > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));  
    }
  });
}

function fillTable(csv,date) {
  var tbl_data = [],
      splitted = csv.split('\n');
  for(var i=0; i < splitted.length; i++) {
    cols = splitted[i].split('\t');
    if((cols.length < 5) || (isNaN(cols[2])) || (isNaN(cols[3])) || (isNaN(cols[4])))
      continue;
    if(cols[0] == "") continue;
    tbl_data.push(["<a href=\"/webstats/accounts/"+cols[1]+"?date="+date+"\">"+cols[1]+"</a>",
                  Number(cols[2]),
                  (Number(cols[3])/1024/1024).toFixed(2),
                  (Number(cols[4])/1000000).toFixed(2)]);
  }
  if (oTable != undefined) {
    oTable.clear();
    oTable.rows.add(tbl_data);
    oTable.order([3, "desc"]).draw();
  } else {
    oTable = $('#account_activity').DataTable({
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
}

$(document).ready(function() {
  initDatePicker(dateChange);
  dateChange($('.datepicker-tab').first().val());
});


function dateChange(reportDate) {
  loadData(reportDate);
  $('.datepicker-tab').each(function () { $(this).datepicker("setDate", reportDate) });
  window.history.replaceState(undefined, "Accounts " + reportDate , "/webstats/accounts?date="+reportDate);
}
