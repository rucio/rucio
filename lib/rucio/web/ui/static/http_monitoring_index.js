/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Ralph Vigne <ralph.vigne@cern.ch> 2015
 */

function loadData(type) {
  var reportDate = url_param('date');
  $.ajax({
    url: "/http-monitoring/data?report=per_account&date="+reportDate+"&top=23",
    crossDomain: true,
    success: function(csv) {
      var title = 'Top 20 Accounts';
      $('#accounts .chart.hits').empty();
      drawChart('#accounts .chart.hits', title, csv2chart(csv, 1, 2));
      $('#accounts .chart.mb').empty();
      drawChart('#accounts .chart.mb', title+' (MB)', csv2chart(csv, 1, 3, undefined, undefined, (1/(10124*10214))));
      $('#accounts .chart.sec').empty();
      drawChart('#accounts .chart.sec', title+' (Sec)', csv2chart(csv, 1, 4, undefined, undefined, (1/10000)));
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#accounts div.img-wrapper').html($('<img/>').attr('src','/media/error.jpg'));
    }
  });
  $.ajax({
    url: "/http-monitoring/data?report=per_resource&date="+reportDate+"&top=23",
    crossDomain: true,
    success: function(csv) {
      var title = 'Top 20 Resources';
      $('#resources .chart.hits').empty();
      drawChart('#resources .chart.hits', title, csv2chart(csv, 1, 2));
      $('#resources .chart.mb').empty();
      drawChart('#resources .chart.mb', title+' (MB)', csv2chart(csv, 1, 3, undefined, undefined, (1/(10124*10214))));
      $('#resource .chart.sec').empty();
      drawChart('#resources .chart.sec', title+' (Sec)', csv2chart(csv, 1, 4, undefined, undefined, (1/10000)));
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#resources div.img-wrapper').html($('<img/>').attr('src','/media/error.jpg'));
    }
  });
  $.ajax({
    url: "/http-monitoring/data?report=per_apiclass&date="+reportDate,
    crossDomain: true,
    success: function(csv) {
      var title = 'Top 20 API Classes';
      $('#apiclasses .chart.hits').empty();
      drawChart('#apiclasses .chart.hits', title, csv2chart(csv, 2, 4, 20, true));
      $('#apiclasses .chart.mb').empty();
      drawChart('#apiclasses .chart.mb', title+' (MB)', csv2chart(csv, 2, 5, 20, true, (1/(10124*10214))));
      $('#apiclasses .chart.sec').empty();
      drawChart('#apiclasses .chart.sec', title+' (Sec)', csv2chart(csv, 2, 6, 20, true, (1/10000)));
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#apiclasses div.img-wrapper').html($('<img/>').attr('src','/media/error.jpg'));
    }
  });
}

$(document).ready(function() {
  window.location.href = "/webstats/accounts";
  return;



  var reportDate = url_param('date');
  if ((reportDate == undefined) || (reportDate == '')) {
    var yesterday = new Date((new Date()).setDate((new Date).getDate() -1));
    reportDate = yesterday.getFullYear() + '-' +
      ((yesterday.getMonth()+1) < 10 ? ('0'+(yesterday.getMonth()+1)) : (yesterday.getMonth()+1)) + '-' +
      ((yesterday.getDate()) < 10 ? '0'+yesterday.getDate() : yesterday.getDate());
  }
  window.history.replaceState(undefined, "Overview " + reportDate , "/webstats?date="+reportDate);
  $('.rucio-slider-header').each(function(index) {
    $(this).html($(this).html()+'('+reportDate+')');
  });
  loadData();
  $('.show-details').each(function() { $(this).attr('href', $(this).attr('href')+'?date='+reportDate); });
});
