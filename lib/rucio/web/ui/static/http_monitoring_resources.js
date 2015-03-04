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
    $('#resource_details').hide();
    $.ajax({
        url: "/http-monitoring/data?report=per_resource&date="+date+"&top=20000",
        crossDomain: true,
        success: function(csv) {
            fill_table(csv);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert(textStatus);
        }
    });
}

function draw_chart(showData) {
    $('#chart').highcharts({
        chart: {
            plotBackgroundColor: null,
            plotBorderWidth: null,
            plotShadow: false
        },
        title: {
            text: "Resources"
        },
        tooltip: {
            pointFormat: '{series.name}: <b>{point.y:.1f} ({point.percentage:.1f}%)</b>'
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
        series: [{ type: 'pie', data: showData }]
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
    console.log(oTable);
    if (oTable != null) {
        oTable.clear();
        oTable.rows.add(tbl_data);
        oTable.order([3, 'desc']).draw();
    } else {
        oTable = $('#table_resources').DataTable({
            data: tbl_data,
            "order": [[ 3, "desc" ]],
            "fnDrawCallback": update_chart
        });
    }
}

function update_chart(oSettings) {
    var t = $("#table_resources").dataTable();
    var tblData = t._('tr', {"filter":"applied"});
    var data = [];

    for (var i = 0; i < 20; ++i) {
        console.log(tblData[i]);
        data.push(tblData[i]);
    }
    draw_chart(data);
}

$(document).ready(function() {
    $( "#datepicker" ).datepicker({
        onSelect: function() {
            report_date = $("#datepicker").val();
            load_data(report_date);
            window.history.replaceState(undefined, "Resources " + report_date , "/webstats/resources?date="+report_date);
        }
    });
    $( "#datepicker" ).datepicker("option", "dateFormat", "yy-mm-dd");

    var report_date = url_param('date');
    if (report_date != '') {
      $( "#datepicker" ).val(report_date);
    } else {
      $( "#datepicker" ).datepicker('setDate', new Date());
      report_date = $( "#datepicker" ).val();
      window.history.replaceState(undefined, "Resources " + report_date , "/webstats/resources?date="+report_date);
    }
    load_data(report_date);
});
