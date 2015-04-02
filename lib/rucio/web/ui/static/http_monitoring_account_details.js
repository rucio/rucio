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

function loadData(date, account) {
  $.ajax({
    url: "/http-monitoring/data?report=per_account&date="+date,
    crossDomain: true,
    success: function(csv) {
      fillTableAccountList(csv,date);
    },
    error: function(jqXHR, textStatus, errorThrown) {
      alert("Failed filling account list");
    }
  });
  $.ajax({
    url: "/http-monitoring/data?report=per_apiclass&date="+date+"&account="+account,
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

      drawDoubleChart('#useragents > .chart.hits', "Requests per User Agent/API Class",
                      {name: 'User Agent', pattern: /^([\S+ ]+)/},
                      {name: 'API Class', pattern: /.*?\t(.*)/},
                      csv2chart(csv, [3,2], 4, undefined, true)); /// aggregated is true due cover different client versions
      drawDoubleChart('#useragents > .chart.mb', "Bandwidth (MB) per User Agent/API Class",
                      {name: 'User Agent', pattern: /^([\S+ ]+)/},
                      {name: 'API Class', pattern: /.*?\t(.*)/},
                      csv2chart(csv, [3,2], 5, undefined, true, (1/(1024*1024)))); /// aggregated is true due cover different client versions
      drawDoubleChart('#useragents > .chart.sec', "Response time (Sec) per User Agent/API Class",
                      {name: 'User Agent', pattern: /^([\S+ ]+)/},
                      {name: 'API Class', pattern: /.*?\t(.*)/},
                      csv2chart(csv, [3,2], 6, undefined, true, (1/1000000))); /// aggregated is true due cover different client versions

      drawDoubleChart('#apiclasses2 > .chart.hits', 'Requests per API Class/User Agent',
                      {name: 'API Class', pattern: /^([\S+ ]+)/},
                      {name: 'User Agent', pattern: /.*?\t(.*)/},
                      csv2chart(csv, [2,3], 4, undefined, true)); /// aggregated is true due cover different client versions
      drawDoubleChart('#apiclasses2 > .chart.mb', 'Bandwidth (MB) per API Class/User Agent',
                      {name: 'API Class', pattern: /^([\S+ ]+)/},
                      {name: 'User Agent', pattern: /.*?\t(.*)/},
                      csv2chart(csv, [2,3], 5, undefined, true, (1/(1024*1024)))); /// aggregated is true due cover different client versions
      drawDoubleChart('#apiclasses2 > .chart.sec', "Response time (Sec) per API Class/User Agent",
                      {name: 'API Class', pattern: /^([\S+ ]+)/},
                      {name: 'User Agent', pattern: /.*?\t(.*)/},
                      csv2chart(csv, [2,3], 6, undefined, true, (1/1000000))); /// aggregated is true due cover different client versions
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#apiclasses > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#apiclasses > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#apiclasses > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#useragents > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#useragents > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#useragents > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#apiclasses2 > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#apiclasses2 > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#apiclasses2 > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));  
    }
  });
  $.ajax({
    url: "/http-monitoring/data?report=per_scriptid&date="+date+"&account="+account,
    crossDomain: true,
    success: function(csv) {
      drawChartH('#scriptids1 > .chart.hits', "Requests per ScriptID", csv2chart(csv, 3, 4, undefined, true));
      drawChartH('#scriptids1 > .chart.mb', "Bandwidth (MB) per ScriptID", csv2chart(csv, 3, 5, undefined, true));
      drawChartH('#scriptids1 > .chart.sec', "Response time (Sec) per ScriptID", csv2chart(csv, 3, 6, undefined, true));

      drawDoubleChart('#scriptids > .chart.hits', "Requests per ScriptID/API Class",
                      {name: 'Script ID', pattern: /^([\S+ ]+)/},
                      {name: 'API Class', pattern: /.*?\t(.*)/},
                      csv2chart(csv, [3,2], 4, undefined, true)); /// aggregated is true due cover different client versions
      drawDoubleChart('#scriptids > .chart.mb', "Bandwidth (MB) per ScriptID/API Class",
                      {name: 'Script ID', pattern: /^([\S+ ]+)/},
                      {name: 'API Class', pattern: /.*?\t(.*)/},
                      csv2chart(csv, [3,2], 5, undefined, true, (1/(1024*1024)))); /// aggregated is true due cover different client versions
      drawDoubleChart('#scriptids > .chart.sec', "Response time (Sec) per ScriptID/API Class",
                      {name: 'Script ID', pattern: /^([\S+ ]+)/},
                      {name: 'API Class', pattern: /.*?\t(.*)/},
                      csv2chart(csv, [3,2], 6, undefined, true, (1/1000000))); /// aggregated is true due cover different client versions

      drawDoubleChart('#scriptids2 > .chart.hits', "Requests per API Class/ScriptID",
                      {name: 'API Class', pattern: /^([\S+ ]+)/},
                      {name: 'Script ID', pattern: /.*?\t(.*)/},
                      csv2chart(csv, [2,3], 4, undefined, true)); /// aggregated is true due cover different client versions
      drawDoubleChart('#scriptids2 > .chart.mb', "Bandwidth (MB) per API Class/ScriptID",
                      {name: 'API Class', pattern: /^([\S+ ]+)/},
                      {name: 'Script ID', pattern: /.*?\t(.*)/},
                      csv2chart(csv, [2,3], 5, undefined, true, (1/(1024*1024)))); /// aggregated is true due cover different client versions
      drawDoubleChart('#scriptids2 > .chart.sec', "Response time (Sec) per API Class/ScriptID",
                      {name: 'API Class', pattern: /^([\S+ ]+)/},
                      {name: 'Script ID', pattern: /.*?\t(.*)/},
                      csv2chart(csv, [2,3], 6, undefined, true, (1/1000000))); /// aggregated is true due cover different client versions
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#scriptids > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#scriptids > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#scriptids > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#scriptids1 > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#scriptids1 > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#scriptids1 > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#scriptids2 > .chart.hits').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#scriptids2 > .chart.mb').html($('<img/>').attr('src','/media/error.jpg'));  
      $('#scriptids2 > .chart.sec').html($('<img/>').attr('src','/media/error.jpg'));  
    }
  });
  $.ajax({
    url: "/http-monitoring/data?report=account_details&date="+date+"&account="+account+"&top=1001",
    crossDomain: true,
    success: function(csv) {
      fillTable(csv,date);
      drawChartV('#resources > .chart.hits', 'Requests per Resource', csv2chart(csv, 2, 3, 20));
      drawChartV('#resources > .chart.mb', 'Bandwidth (MB) per Resource', csv2chart(csv, 2, 4, 20, undefined, (1/(1024*1024))));
      drawChartV('#resources > .chart.sec', 'Response time (Sec) per Resource', csv2chart(csv, 2, 5, 20, undefined, (1/1000000)));
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
    if(cols[0] == "") continue;
    var caption = '';
    if (/^\w+\s+\/(dids|replicas)\/\S+?\/.+$/.test(cols[2])) {
      caption = '<a target="_blank" href="/search?scope='+cols[2].match(/^\w+\s+\/(dids|replicas)\/(.*?)\/.*$/)[2]+'&name='+cols[2].match(/^\w+\s+\/(dids|replicas)\/.*?\/(.*?)(\?.*)?$/)[2]+'">'+cols[2]+'</a>';
    } else if (/^PUT\s\/rules\/\w+$/.test(cols[2])) {
      caption = '<a target="_blank" href="/rule?rule_id='+cols[2].match(/^PUT\s\/rules\/(\w+)$/)[2]+'">'+cols[2]+'</a>';
    } else {
      caption = cols[2];
    }
    tbl_data.push([caption,
      Number(cols[3]),
      (Number(cols[4])/1024/1024).toFixed(2),
      (Number(cols[5])/1000000).toFixed(2)]);
  }
  $('#account_activity').DataTable().destroy();
  $('#account_activity').DataTable({
    data: tbl_data,
    aoColumns: [
      {'width': '79%'},
      {'class': 'align-right', 'width': '7%'},
      {'class': 'align-right', 'width': '7%'},
      {'class': 'align-right', 'width': '7%'}
    ],
    "order": [[ 3, "desc" ]],
    "bFilter": true,
    "bLengthChange": true,
     "bAutoWidth": true,
    "iDisplayLength": 10
  });
}

function fillTableAccountList(csv, date) {
  var tblData = [],
      data = [],
      totals = {'hits': 0, 'mb': 0, 'sec': 0};
  csv = csv.split("\n"); // for now
  for(var i=0; i < csv.length; i++) {
    var c = csv[i].split('\t');
    if((c.length < 5) || (isNaN(c[2])) || (isNaN(c[3])) || (isNaN(c[4])))
      continue;
    data.push(c); 
    totals.hits += Number(c[2]);
    totals.mb += Number(c[3]);
    totals.sec += Number(c[4]);
  }
  for(var i in data) {
    tblData.push(["<a href=\"/webstats/accounts/"+data[i][1]+"?date="+date+"\">"+data[i][1]+"</a>",
                  (100.0/totals.hits*Number(data[i][2])).toFixed(2),
                  (100.0/totals.mb*Number(data[i][3])).toFixed(2),
                  (100.0/totals.sec*Number(data[i][4])).toFixed(2)]);
  }
  $('#account_list').DataTable().destroy();
  $('#account_list').DataTable({
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
  syncTabs('#account_list');
});


function dateChange(reportDate) {
  var account = /\S+\/(.*)$/g.exec(window.location.pathname)[1];
  loadData(reportDate, account);
  $('.datepicker-tab').each(function () { $(this).datepicker("setDate", reportDate) });
  window.history.replaceState(undefined, "Accounts " + reportDate , "/webstats/accounts/"+account+"?date="+reportDate);
}
