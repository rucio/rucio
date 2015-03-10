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

var report_date = undefined;

function loadData(type) {
  $.ajax({
    url: "/http-monitoring/data?report=per_account&date="+report_date+"&top=23",
    crossDomain: true,
    success: function(csv) {
      var title = 'Top 20 Accounts';
      $('#accounts .chart.hits').empty();
      drawChart('#accounts .chart.hits', title, csv2chart(csv, 1, 2));
      $('#accounts .chart.mb').empty();
      drawChart('#accounts .chart.mb', title, csv2chart(csv, 1, 3));
      $('#accounts .chart.sec').empty();
      drawChart('#accounts .chart.sec', title, csv2chart(csv, 1, 4));
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#accounts div.img-wrapper').html($('<img/>').attr('src','/media/error.jpg'));

    }
  });
  $.ajax({
    url: "/http-monitoring/data?report=per_resource&date="+report_date+"&top=23",
    crossDomain: true,
    success: function(csv) {
      var title = 'Top 20 Resources';
      $('#resources .chart.hits').empty();
      drawChart('#resources .chart.hits', title, csv2chart(csv, 1, 2));
      $('#resources .chart.mb').empty();
      drawChart('#resources .chart.mb', title, csv2chart(csv, 1, 3));
      $('#resource .chart.sec').empty();
      drawChart('#resources .chart.sec', title, csv2chart(csv, 1, 4));
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#resources div.img-wrapper').html($('<img/>').attr('src','/media/error.jpg'));

    }
  });
  $.ajax({
    url: "/http-monitoring/data?report=per_apiclass&date="+report_date,
    crossDomain: true,
    success: function(csv) {
      var title = 'Top 20 API Classes';
      $('#apiclasses .chart.hits').empty();
      drawChart('#apiclasses .chart.hits', title, csv2chart(csv, 2, 4, 20, true));
      $('#apiclasses .chart.mb').empty();
      drawChart('#apiclasses .chart.mb', title, csv2chart(csv, 2, 5, 20, true));
      $('#apiclasses .chart.sec').empty();
      drawChart('#apiclasses .chart.sec', title, csv2chart(csv, 2, 6, 20, true));
    },
    error: function(jqXHR, textStatus, errorThrown) {
      $('#apiclasses div.img-wrapper').html($('<img/>').attr('src','/media/error.jpg'));
    }
  });
}


function csv2chart(csv, legendColumn, dataColumn, top, aggregate) {
  var data = [],
      dataMatrix = [],
      lines = csv.split('\n'),
      sum = 0;

  if(aggregate == true) {
    var aData = {};
    for(var i=1; i < lines.length; i++) {
      var cols = lines[i].split('\t');
      if(cols[0] != '') {
        aData[cols[legendColumn]] = (aData[cols[legendColumn]] == undefined) ? Number(cols[dataColumn]) : aData[cols[legendColumn]] + Number(cols[dataColumn]);
      }
    }
    for(var item in aData) {
      dataMatrix.push([item, aData[item]]);
    }
  } else {
    for(var i=1; i < lines.length; i++) {
      var cols = lines[i].split('\t');
      if(cols.length > 1)
        dataMatrix.push([cols[legendColumn], Number(cols[dataColumn])]);
    }
  }

  for(var i=1; i < dataMatrix.length; i++) {
    var cols = dataMatrix[i];
    if (top == undefined || i <= top) { data.push([cols[0], cols[1]]); }
    else { sum += cols[1]; }
  }
  data.sort(function(a,b) { return (b[1] - a[1]);});
  if (sum != 0) data.push(["Others (Pos: "+top+" - "+dataMatrix.length+")", sum]);;
  return data;
}


function drawChart(target, title, series) {
  $(target).highcharts({
    chart: {
      plotBackgroundColor: null,
      plotBorderWidth: null,
      spacingLeft: 30,
      spacingRight: 30,
      plotShadow: false
    },
    title: {
      text: title
    },
    tooltip: {
      pointFormat: '{point.y:.1f} ({point.percentage:.1f}%)'
    },
    plotOptions: {
      pie: {
        allowPointSelect: true,
        cursor: 'pointer',
        dataLabels: { enabled: false },
        showInLegend: true
      }
    },
    legend: {
      layout: 'vertical',
      align: 'left',
      useHTML: true,
      verticalAlign: 'bottom',
      labelFormatter: function() {
        var text = this.name;
        var formatted = text.length > 30 ? text.substring(0, 20) + '...' : text;
        return '<div style="width:; overflow:hidden" title="' + text + ' (Num. Hits: ' + this.y + ')">' + formatted + '</div>';
      }
    },
    series: [{ type: 'pie', data: series, animation: false }]
  });
}

$(document).ready(function() {
  report_date = url_param('date');
  if ((report_date == undefined) || (report_date == '')) {
    var now = new Date();
    report_date = now.getFullYear() + '-' +
      ((now.getMonth()+1) < 10 ? ('0'+(now.getMonth()+1)) : (now.getMonth()+1)) + '-' +
      ((now.getDate()) < 10 ? '0'+now.getDate() : now.getDate());
  }
  $('.rucio-slider-header').each(function(index) {
    $(this).html($(this).html()+'('+report_date+')');
  });
  loadData();
});
