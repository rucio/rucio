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
    url: "/http-monitoring/data?report=per_resource&date="+date+"&top=10001",
    crossDomain: true,
    success: function(csv) {
      drawChartV('#resources > .chart.hits', 'Requests per Resource', csv2chart(csv, 1, 2, 20));
      drawChartV('#resources > .chart.mb', 'Bandwidth per Resource (MB)', csv2chart(csv, 1, 3, 20, false, (1/(1024*1024))));
      drawChartV('#resources > .chart.sec', 'Response time per Resource (Sec)', csv2chart(csv, 1, 4, 20, false, (1/1000000)));
      fillTable(csv,date);
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#resources > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#resources > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#resources > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));  
    }
  });
}

function fillTable(csv,date) {
  var tbl_data = [],
      splitted = csv.split('\n');
  for(var i=0; i < splitted.length; i++) {
    cols = splitted[i].split('\t');
    if((cols.length < 5) || (isNaN(cols[2])) || (isNaN(cols[3])) || (isNaN(cols[4])))
      continue
    var caption = '';
    if (/^\w+\s+\/(dids|replicas)\/\S+?\/.+$/.test(cols[1])) {
      caption = '<a target="_blank" href="/search?scope='+cols[1].match(/^\w+\s+\/(dids|replicas)\/(.*?)\/.*$/)[2]+'&name='+cols[1].match(/^\w+\s+\/(dids|replicas)\/.*?\/(.*?)(\?.*)?$/)[2]+'">'+cols[1]+'</a>';
    } else if (/^PUT\s\/rules\/\w+$/.test(cols[1])) {
      caption = '<a target="_blank" href="/rule?rule_id='+cols[1].match(/^PUT\s\/rules\/(\w+)$/)[1]+'">'+cols[1]+'</a>';
    } else {
      caption = cols[1];
    }
    tbl_data.push([caption,
                  Number(cols[2]), 
                  (Number(cols[3])/1024/1024).toFixed(2), 
                  (Number(cols[4])/1000000).toFixed(2)]);
  }
  $('#account_activity').DataTable({
    data: tbl_data,
    aoColumns: [
      {'width': '35%'},
      {'class': 'align-right', 'searchable': false},
      {'class': 'align-right', 'searchable': false},
      {'class': 'align-right', 'searchable': false}
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
  window.history.replaceState(undefined, "Resources " + reportDate , "/webstats/resources?date="+reportDate);
}
