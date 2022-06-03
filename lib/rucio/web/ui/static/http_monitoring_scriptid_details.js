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

function loadData(date, scriptID) {
  $.ajax({
    url: "/http-monitoring/data?report=per_scriptid&date="+date,
    crossDomain: true,
    success: function(csv) {
      fillTableScriptList(csv,date);
      csv = filterByScript(csv, scriptID);
      drawDoubleChart('#apiclasses > .chart.hits', "Requests per API Class/HTTP Verb",
                      {name: 'API Class', pattern: /^(.*\..*)\..*$/},
                      {name: 'HTTP Verb', pattern: /^.*\..*\.(.*)$/},
                      csv2chart(csv, 2, 4, undefined, true)); /// aggregated is true due cover different client versions
      drawDoubleChart('#apiclasses > .chart.mb', "Bandwidth (MB) per API Class/HTTP Verb",
                      {name: 'API Class', pattern: /^(.*\..*)\..*$/},
                      {name: 'HTTP Verb', pattern: /^.*\..*\.(.*)$/},
                      csv2chart(csv, 2, 5, undefined, true, (1/(1024*1024)))); /// aggregated is true due cover different client versions
      drawDoubleChart('#apiclasses > .chart.sec', "Response time (Sec) per API Class/HTTP Verb",
                      {name: 'API Class', pattern: /^(.*\..*)\..*$/},
                      {name: 'HTTP Verb', pattern: /^.*\..*\.(.*)$/},
                      csv2chart(csv, 2, 6, undefined, true, (1/1000000))); /// aggregated is true due cover different client versions

      drawDoubleChart('#apiclasses2 > .chart.hits', "Requests per API Class/Account",
                      {name: 'API Class', pattern: /^.*?\s(.*\..*)\..*$/},
                      {name: 'Account', pattern: /^(.*)\s.*$/},
                      csv2chart(csv, [1,2], 4, undefined, true), 10); /// aggregated is true due cover different client versions
      drawDoubleChart('#apiclasses2 > .chart.mb', "Bandwidth (MB) per API Class/Account",
                      {name: 'API Class', pattern: /^.*?\s(.*\..*)\..*$/},
                      {name: 'Account', pattern: /^(.*)\s.*$/},
                      csv2chart(csv, [1,2], 5, undefined, true, (1/(1024*1024))), 10); /// aggregated is true due cover different client versions
      drawDoubleChart('#apiclasses2 > .chart.sec', "Response time (Sec) per API Class/Account",
                      {name: 'API Class', pattern: /^.*?\s(.*\..*)\..*$/},
                      {name: 'Account', pattern: /^(.*)\s.*$/},
                      csv2chart(csv, [1,2], 6, undefined, true, (1/1000000)), 10); /// aggregated is true due cover different client versions

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
  $.ajax({
    url: "/http-monitoring/data?report=per_country&date="+date,
    crossDomain: true,
    success: function(csv) {
      csv = filterByScript(csv, scriptID);
      drawDoubleChart('#accounts2 > .chart.hits', "Requests per Account/Country",
                      {name: 'Account', pattern: /^.*?\s(.*)$/},
                      {name: 'Country', pattern: /^(.*)\s.*$/},
                      csv2chart(csv, [1,2], 4, undefined, true), 10);
      drawDoubleChart('#accounts2 > .chart.mb', "Bandwidth (MB) per Account/Country",
                      {name: 'Account', pattern: /^.*?\s(.*)$/},
                      {name: 'Country', pattern: /^(.*)\s.*$/},
                      csv2chart(csv, [1,2], 5, undefined, true, (1/(1024*1024))), 10);
      drawDoubleChart('#accounts2 > .chart.sec', "Response time (Sec) per Account/Country",
                      {name: 'Account', pattern: /^.*?\s(.*)$/},
                      {name: 'Country', pattern: /^(.*)\s.*$/},
                      csv2chart(csv, [1,2], 6, undefined, true, (1/1000000)), 10);
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#accounts2 > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));
      $('#accounts2 > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));
      $('#accounts2 > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));
    }
  });
}

function filterByScript(csv, scriptID) {
  var data = [],
      lines = csv.split('\n');
  data.push(lines[0]); // Copy CSV header
  for(var i=1; i < lines.length; i++) {
    if(lines[i].match(scriptID))
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
      '<a href ="/webstats/apiclasses/'+cols[2]+'?date='+date+'">'+cols[2]+'</a>',
      Number(cols[4]),
      (Number(cols[5])/1024/1024).toFixed(2),
      (Number(cols[6])/1000000).toFixed(2)]);
  }
  $('#script_activity').DataTable().destroy();
  $('#script_activity').DataTable({
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

function fillTableScriptList(csv, date) {
  var tblData = [],
      aggregatedData = {},
      totals = {'hits': 0, 'mb': 0, 'sec': 0};
  csv = csv.split("\n"); // for now
  for(var i=0; i < csv.length; i++) {
    var c = csv[i].split('\t');
    if((c.length < 7) || (isNaN(c[4])) || (isNaN(c[5])) || (isNaN(c[6])))
      continue;
    if (aggregatedData[c[3]] == undefined) {
      aggregatedData[c[3]] = {'hits': 0, 'mb': 0, 'sec': 0};
    }
    aggregatedData[c[3]].hits += Number(c[4]);
    aggregatedData[c[3]].mb += Number(c[5]);
    aggregatedData[c[3]].sec += Number(c[6]);
    totals.hits += Number(c[4]);
    totals.mb += Number(c[5]);
    totals.sec += Number(c[6]);
  }
  for(var scriptID in aggregatedData) {
    tblData.push(["<a href=\"/webstats/scriptids/"+scriptID+"?date="+date+"\">"+scriptID+"</a>",
                  (100.0/totals.hits*Number(aggregatedData[scriptID].hits)).toFixed(2),
                  (100.0/totals.mb*Number(aggregatedData[scriptID].mb)).toFixed(2),
                  (100.0/totals.sec*Number(aggregatedData[scriptID].sec)).toFixed(2)]);
  }
  $('#script_list').DataTable().destroy();
  $('#script_list').DataTable({
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
  syncTabs('#script_list');
});


function dateChange(reportDate) {
  var script = /\S+\/(.*)$/g.exec(window.location.pathname)[1];
  loadData(reportDate, script);
  $('.datepicker-tab').each(function () { $(this).datepicker("setDate", reportDate) });
  window.history.replaceState(undefined, "Scripts " + reportDate , "/webstats/scriptids/"+script+"?date="+reportDate);
}
