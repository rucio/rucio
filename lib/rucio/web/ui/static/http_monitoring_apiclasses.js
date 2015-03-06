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

var oTable = null;

function load_data(date) {
  $('#load').show();
  $.ajax({
    url: "/http-monitoring/data?report=per_apiclass&date="+date,
    crossDomain: true,
    success: function(csv) {
      fill_table(csv,date);
      $('#load').hide();
    },
    error: function(jqXHR, textStatus, errorThrown) {
      alert("Unable to request data from the server.");
      $('#load').hide();
    }
  });
}

function fill_table(csv,date) {
  var tbl_data = []; var splitted = csv.split('\n'); var aggr_data = {};
  for(var i=1; i < splitted.length; i++) { // Aggreagte per API class (i.e. remove user agent)
    // group.time group.account group.api group.useragent hits  sum_resp_bytes  sum_resp_time
    var cols = splitted[i].split('\t');
    if (cols[0] == "") continue;
    var api = cols[2].split(":")[0];
    if (aggr_data[cols[1]+':'+api] == undefined) aggr_data[cols[1]+':'+api] = {'hits': 0, 'mb': 0, 'sec': 0} 
    aggr_data[cols[1]+':'+api]['hits'] += Number(cols[4]);
    aggr_data[cols[1]+':'+api]['mb'] += Number(cols[5]);
    aggr_data[cols[1]+':'+api]['sec'] += Number(cols[6]);
  }
  for(var key in aggr_data) {
    var clAccount = key.split(':')[0];
    var clName = key.split(':')[1];
    //tbl_data.push(["<a href=\"/webstats/accounts/"+cols[1]+"?date="+date+"\">"+cols[1]+"</a>", Number(cols[2]), (Number(cols[3])/1024/1024).toFixed(2), (Number(cols[4])/10000).toFixed(2)]);
    tbl_data.push([
              "<a href=\"/webstats/apiclasses/"+clName+"?date="+date+"\">"+clName+"</a>",
              "<a href=\"/webstats/accounts/"+clAccount+"?date="+date+"\">"+clAccount+"</a>",
              aggr_data[key]['hits'],
              (aggr_data[key]['mb']/1024/1024).toFixed(2),
              (aggr_data[key]['sec']/10000).toFixed(2)
    ]);
  }
  if (oTable != null) {
    oTable.clear();
    oTable.rows.add(tbl_data);
    oTable.order([4, "desc"]).draw();
  } else {
    oTable = $('#api_activity').DataTable({
      data: tbl_data,
      aoColumns: [
        {'width': '30%'},
        {'width': '18%'},
        {'class': 'align-right'},
        {'class': 'align-right'},
        {'class': 'align-right'}
      ],
      fnDrawCallback: update_chart,
      order: [[ 3, "desc" ]],
      iDisplayLength: 25
    });
  }
}


function update_chart(oSettings) {
    var no_shows = Number($('select[name="api_activity_length"]').val()),
        t = $("#api_activity").dataTable(),
        // tblData: [class.httpverb, account, hits, mb, sec]
        tblData = t._('tr', {"filter": "applied"}),
        aggr_data = {'api': {}, 'account': {}},
        chart_data = {};

    for (var i = 0; i < tblData.length; i++) {
      for(var f in aggr_data) {
        // var name = (i < no_shows) ? ((f == 'api') ? $(tblData[i][0]).text() : $(tblData[i][1]).text()) : "Others",
        var name = (f == 'api') ? $(tblData[i][0]).text() : $(tblData[i][1]).text(),
            j = 2;
        if (aggr_data[f][name] == undefined) aggr_data[f][name] = {'hits': 0, 'mb': 0, 'sec': 0};
        for(var m in aggr_data[f][name]) {
          aggr_data[f][name][m] += Number(tblData[i][j]);
          j++;
        }
      }
    }

    // Traferese dict to Array
    for(var type in aggr_data) {
      chart_data[type] = {'hits': [], 'mb': [], 'sec': []};
      for(var label in aggr_data[type]) {
        for(var metric in aggr_data[type][label]) {
          chart_data[type][metric].push([label, aggr_data[type][label][metric]]);
        }
      }
    }

    // Draw charts
      for(var metric in chart_data['account']) {
        draw_chart('#account_'+metric, chart_data['account'][metric]);
      }
      for(var metric in chart_data['api']) {
        draw_double_pi('api', metric, aggr_data);
      }
}


function draw_chart(id, data) {
    var title = $(id).attr('title'),
        total = 0;
    for(var i in data) total += Number(data[i][1]);
    $(id).highcharts({
        chart: {
            plotBackgroundColor: null,
            plotBorderWidth: null,
            plotShadow: false,
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
                dataLabels: {
                    enabled: false,
                },
            }
        },
        legend: {
          useHTML: true,
          verticalAlign: 'bottom',
        },
        series: [{ type: 'pie',
                    data: data,
                    animation: false,
                    showInLegend: true }]
    });
}

$(document).ready(function() {
  var report_date = url_param('date');
  $("#datepicker").datepicker({
    onSelect: function() {
      report_date = $("#datepicker").val();
      $("#datepicker").datepicker("setDate", report_date);
      load_data(report_date);
      window.history.replaceState(undefined, "Accounts " + report_date , "/webstats/apiclasses?date="+report_date);
    },
    dateFormat: "yy-mm-dd",
    maxDate: new Date(),
    numberOfMonths: 2
  });

  if (report_date != '') { $("#datepicker").datepicker("setDate", report_date); } 
  else {
    $("#datepicker").datepicker('setDate', new Date());
    report_date = $("#datepicker").val();
  }
  window.history.replaceState(undefined, "Accounts " + report_date , "/webstats/apiclasses?date="+report_date);
  load_data(report_date);
});


function draw_double_pi(main, sub, tblData) {
    var colors = Highcharts.getOptions().colors,
        title = $('#'+main+"_"+sub).attr('title'),
        data = {},
        apiClasses = [],
        httpVerbs = [],
        i = 0,
        j,
        total = 0,
        drillDataLen,
        brightness;

    for(var mainEntry in tblData[main]) {  // i.e. api
      var apiClass = mainEntry.match(/(\w+\.?\w+).*/)[1];
      var entryData = tblData[main][mainEntry];
      if (data[apiClass] == undefined) data[apiClass] = { y: 0,
                                                          color: colors[i],
                                                          drilldown: { name: 'HTTP Verbs of ' + apiClass,
                                                                       categories: [],
                                                                       data: [],
                                                                       color: colors[i++],
                                                                     }
                                                        };           

      data[apiClass].y += Number(entryData[sub]);
      data[apiClass].drilldown.categories.push(mainEntry);
      data[apiClass].drilldown.data.push(entryData[sub]);
      total += Number(entryData[sub]);
    }

    for (var chartEntryName in data) {
        var chartEntry = data[chartEntryName];
        apiClasses.push({
            name: chartEntryName,
            y: chartEntry.y,
            color: chartEntry.color
        });

        subCategoriesLength = chartEntry.drilldown.data.length;
        for (j = 0; j < subCategoriesLength; j += 1) {
            brightness = 0.2 - (j / subCategoriesLength) / 5;
            httpVerbs.push({
                name: chartEntry.drilldown.categories[j],
                y: chartEntry.drilldown.data[j],
                color: Highcharts.Color(chartEntry.color).brighten(brightness).get()
            });
        }
    }

    // Create the chart
    $('#'+main+"_"+sub).highcharts({
        chart: {
            type: 'pie'
        },
        title: {
            text: title
        },
        yAxis: {
            title: {
                text: 'Total percent market share'
            }
        },
        plotOptions: {
            pie: {
                shadow: false,
                center: ['50%', '50%']
            }
        },
        series: [{
            name: 'API Classes',
            data: apiClasses,
            animation: false,
            size: '50%',
            dataLabels: {
                formatter: function () {
                    return (100/total*this.y) > 10 ? this.point.name : null;
                },
                color: 'white',
                distance: -20
            }
        }, {
            name: 'HTTP Verbs',
            data: httpVerbs,
            size: '50%',
            innerSize: '75%',
            animation: false,
            dataLabels: {
                formatter: function () {
                    // display only if larger than 1
                    return (100/total*this.y) > 1 ? '<b>' + this.point.name + ':</b> ' + (100/total*this.y).toFixed(2) + '%'  : null;
                }
            }
        }]
    });
}
