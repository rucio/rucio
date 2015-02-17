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

function load_data(date) {
	$('#resource_details').hide();	
	$.ajax({	url: "/http-monitoring/data?report=per_resource&date="+date+"&top=20000",
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
            showInLegend: true,
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
	var t = $('#table_resources').DataTable({
					data: tbl_data,
					"order": [[ 3, "desc" ]],
					"fnDrawCallback": update_chart
	});
}

function update_chart(oSettings) {
	var oTable = $("#table_resources").dataTable();
	var tblData = oTable._('tr', {"filter":"applied"});
	var data = [];
 
	for (var i = 0; i < 20; ++i) {
		console.log(tblData[i]);
		data.push(tblData[i]);
	}
	draw_chart(data);
}


$(document).ready(function() {
  report_date = /^.*?date=([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]).*$/g.exec(window.location.search)[1]
  load_data(report_date);
});
