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

function loadData(date, apiclass) {
  $.ajax({
    url: "/http-monitoring/data?report=per_apiclass&date="+date,
    crossDomain: true,
    success: function(csv) {
      fillTableAPIClassList(csv,date);
      csv = filterByAPIClass(csv, apiclass);
      drawChartV('#accounts > .chart.hits', 'Requests per Account', csv2chart(csv, 1, 4, 20, true));
      drawChartV('#accounts > .chart.mb', 'Bandwidth per Account (MB)', csv2chart(csv, 1, 5, 20, true, (1/(1024*1024))));
      drawChartV('#accounts > .chart.sec', 'Response time per Account (Sec)', csv2chart(csv, 1, 6, 20, true, (1/1000000)));

      fillTable(csv, date);
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#apiclasses > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#apiclasses > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#apiclasses > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#apiclasses2 > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#apiclasses2 > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#apiclasses2 > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#accounts > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#accounts > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#accounts > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));  
    }
  });
}

function filterByAPIClass(csv, apiclass) {
  var data = [],
      lines = csv.split('\n');
  for(var i=0; i < lines.length; i++) {
    if(lines[i].match(apiclass))
      data.push(lines[i]);
  }
  return data.join('\n');
}

function fillTable(csv,date) {
  var tbl_data = [],
      splitted = csv.split('\n');
  for(var i=0; i < splitted.length; i++) {
    cols = splitted[i].split('\t');
    if((cols.length < 7) || (isNaN(cols[4])) || (isNaN(cols[5])) || (isNaN(cols[6])))
      continue;
    tbl_data.push([
      '<a href ="/webstats/accounts/'+cols[1]+'?date='+date+'">'+cols[1]+'</a>', 
      //'<a href ="/webstats/useragents/'+cols[2]+'?date='+date+'">'+cols[2]+'</a>', 
      cols[3], 
      Number(cols[4]), 
      (Number(cols[5])/1024/1024).toFixed(2), 
      (Number(cols[6])/1000000).toFixed(2)]);
  }
  $('#apiclass_activity').DataTable().destroy();
  $('#apiclass_activity').DataTable({
    data: tbl_data,
    aoColumns: [
      {'class': '', 'width': '35%'},
      {'class': '', 'width': '35%'},
      {'class': 'align-right', 'width': '10%'},
      {'class': 'align-right', 'width': '10%'},
      {'class': 'align-right', 'width': '10%'}
    ],
    "order": [[ 3, "desc" ]],
    "bFilter": true,
    "bLengthChange": true,
     "bAutoWidth": true,
    "iDisplayLength": 12
  });
}

function fillTableAPIClassList(csv, date) {
  var tblData = [],
      aggregatedData = {},
      totals = {'hits': 0, 'mb': 0, 'sec': 0};
  csv = csv.split("\n"); // for now
  for(var i=0; i < csv.length; i++) {
    var c = csv[i].split('\t');
    if((c.length < 7) || (isNaN(c[4])) || (isNaN(c[5])) || (isNaN(c[6])))
      continue;
    if (aggregatedData[c[2]] == undefined) {
      aggregatedData[c[2]] = {'hits': 0, 'mb': 0, 'sec': 0};
    }
    aggregatedData[c[2]].hits += Number(c[4]);
    aggregatedData[c[2]].mb += Number(c[5]);
    aggregatedData[c[2]].sec += Number(c[6]);
    totals.hits += Number(c[4]);
    totals.mb += Number(c[5]);
    totals.sec += Number(c[6]);
  }
  for(var apiclass in aggregatedData) {
    tblData.push(["<a href=\"/webstats/apiclasses/"+apiclass+"?date="+date+"\">"+apiclass+"</a>",
                  (100.0/totals.hits*Number(aggregatedData[apiclass].hits)).toFixed(2),
                  (100.0/totals.mb*Number(aggregatedData[apiclass].mb)).toFixed(2),
                  (100.0/totals.sec*Number(aggregatedData[apiclass].sec)).toFixed(2)]);
  }
  $('#apiclass_list').DataTable().destroy();
  $('#apiclass_list').DataTable({
    data: tblData,
    aoColumns: [
      undefined,
      {'class': 'align-right', 'searchable': false},
      {'class': 'align-right', 'visible': false, 'searchable': false},
      {'class': 'align-right', 'visible': false, 'searchable': false},
    ],
    "order": [[ 1, "desc" ]],
    "scrollY": "200px",
    "dom": "frtiS",
    "deferRender": true,
    "bFilter": true,
    "bLengthChange": false,
    "bAutoWidth": true,
    "iDisplayLength": -1
  });
}

$(document).ready(function() {
  initDatePicker(dateChange);
  dateChange($('.datepicker-tab').first().val());
  syncTabs('#apiclass_list');
});


function dateChange(reportDate) {
  var apiclass = /\S+\/(.*)$/g.exec(window.location.pathname)[1];
  loadData(reportDate, apiclass);
  $('.datepicker-tab').each(function () { $(this).datepicker("setDate", reportDate) });
  window.history.replaceState(undefined, "apiclasss " + reportDate , "/webstats/apiclasses/"+apiclass+"?date="+reportDate);
}
