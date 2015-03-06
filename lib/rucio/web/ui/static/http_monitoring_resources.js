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
var loading_count = 0;

function load_data(date) {
    loading_count++;
    $('#load').show();
    $.ajax({
        url: "/http-monitoring/data?report=per_resource&date="+date+"&top=20000",
        crossDomain: true,
        success: function(csv) {
            fill_table(csv);
            loading_count--;
            if (loading_count == 0) $('#load').hide();
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert('Failed loading data from server.');
            loading_count--;
            if (loading_count == 0) $('#load').hide();
        }
    });
    loading_count++;
    $.ajax({
        url: "/http-monitoring/data?report=per_apiclass&date="+date+"&top=20000",
        crossDomain: true,
        success: function(csv) {
            draw_apiclass_chart(csv);
            loading_count--;
            if (loading_count == 0) $('#load').hide();
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert('Failed loading data from server.');
            loading_count--;
            if (loading_count == 0) $('#load').hide();
        }
    });
}

function parse_csv(csv) {
  var dict = {}; var splitted = csv.split('\n'); var data = [];

  for(var i=1; i < splitted.length; i++) {
    var cols = splitted[i].split('\t');
    if (cols.length < 5) continue;
    var grp = String(cols[2]).split(':')[0];
    if (grp == undefined) continue;
    if (dict[grp] == undefined) dict[grp] = 0;
    dict[grp] +=  Number(cols[4]);
  }
  for (var c in dict) 
    data.push([c, dict[c]])
  return data;
}

function draw_apiclass_chart(csv) {
  $('#apiclass').highcharts({
    chart: {
      plotBackgroundColor: null,
      plotBorderWidth: null,
      plotShadow: false,
      height: 600
    },
    title: {
      text: 'Hits per API Class'
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
    series: [{ type: 'pie', data: parse_csv(csv), animation: false }]
  });
}

function draw_chart(showData) {
    $('#hits').highcharts({
        chart: {
            plotBackgroundColor: null,
            plotBorderWidth: null,
            plotShadow: false,
            height: 750
        },
        title: {
            text: "Hits per Resource"
        },
        tooltip: {
            pointFormat: '{point.y:.1f} ({point.percentage:.1f}%)'
        },
        plotOptions: {
            pie: {
                allowPointSelect: true,
                cursor: 'pointer',
                dataLabels: {
                    enabled: false
                },
                showInLegend: true
            }
        },
        legend: {
          layout: 'vertical',
          useHTML: true,
          verticalAlign: 'bottom',
          labelFormatter: function() {
            var text = this.name;
            var formatted = text.length > 60 ? text.substring(0, 60) + '...' : text;
            return '<div style="width:; overflow:hidden" title="' + text + ' (Num. Hits: ' + this.y + ')">' + formatted + '</div>';
          }
        },
        series: [{ type: 'pie', data: showData, animation: false }]
    });
}

function fill_table(csv) {
    var tbl_data = [];
    var splitted = csv.split('\n');
    for(var i=1; i < splitted.length; i++) {
        cols = splitted[i].split('\t');
        if(cols[0] == "") continue;
        tbl_data.push([cols[1], Number(cols[2]), (Number(cols[3])/1024/1024).toFixed(2), (Number(cols[4])/10000).toFixed(2)]);
    }
    if (oTable != null) {
        oTable.clear();
        oTable.rows.add(tbl_data);
        oTable.order([3, 'desc']).draw();
    } else {
        oTable = $('#table_resources').DataTable({
            data: tbl_data,
            aoColumns: [
              {'width': '55%'},
              {'class': 'align-right'},
              {'class': 'align-right'},
              {'class': 'align-right'}
            ],
            order: [[ 3, "desc" ]],
            fnDrawCallback: update_chart,
            iDisplayLength: 20,
            aLengthMenu: [[10, 20, 50, 100, 200, -1], [10, 20, 50, 100, 200, "All"]],
        });
    }
}

function update_chart(oSettings) {
    var t = $("#table_resources").dataTable();
    var tblData = t._('tr', {"filter":"applied"});
    var data = [];

    for (var i = 0; i < 20; ++i) {
        data.push(tblData[i]);
    }
    draw_chart(data);
}

$(document).ready(function() {
    var report_date = url_param('date');
    $("#datepicker").datepicker({
        onSelect: function() {
            report_date = $("#datepicker").val();
            load_data(report_date);
            window.history.replaceState(undefined, "Resources " + report_date , "/webstats/resources?date="+report_date);
        },
        dateFormat: "yy-mm-dd",
        maxDate: new Date(),
        numberOfMonths: 2
    });

    if (report_date != '') {
      $("#datepicker").datepicker('setDate', report_date);
    } else {
      $("#datepicker").datepicker('setDate', new Date());
      report_date = $( "#datepicker" ).val();
      window.history.replaceState(undefined, "Resources " + report_date , "/webstats/resources?date="+report_date);
    }
    load_data(report_date);
});
