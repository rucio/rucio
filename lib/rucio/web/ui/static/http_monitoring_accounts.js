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
	$.ajax({	url: "/http-monitoring/data?report=per_account&date="+date,
			crossDomain: true,
			success: function(csv) {
				draw_chart('hits', csv);
				draw_chart('bandwidth', csv);
				draw_chart('duration', csv);
				fill_table(csv,date);
			},
			error: function(jqXHR, textStatus, errorThrown) {
				alert(jqXHR, textStatus, errorThrown);
			}
	});
}

function fill_table(csv,date) {
	var tbl_data = [];
	var splitted = csv.split('\n');
	for(var i=1; i < splitted.length; i++) {
		cols = splitted[i].split('\t');
		if(cols[0] == "") continue;
		tbl_data.push(["<a href=\"/ui/http-monitoring/accounts/"+cols[1]+"?date="+date+"\">"+cols[1]+"</a>", Number(cols[2]), (Number(cols[3])/1024/1024).toFixed(2), (Number(cols[4])/10000).toFixed(2)]);
	}
	var t = $('#account_activity').DataTable({data: tbl_data,	"order": [[ 3, "desc" ]]});
}

function draw_chart(type, csv) {
	var title; var index; var id;
	switch(type) {
		case 'hits': index = 2; title = "Requests per Account"; id = "#hits"; break;
		case 'bandwidth': index = 3; title = "Bandwidth per Account"; id = "#bandwidth"; break;
		case 'duration': index = 4; title = "Duration per Account"; id = "#duration"; break;
	}
	$(id).highcharts({
	    chart: { plotBackgroundColor: null, plotBorderWidth: null, plotShadow: false },
	    title: { text: title  },
	    tooltip: {pointFormat: '{series.name}: <b>{point.y:.1f} ({point.percentage:.1f}%)</b>'},
	    plotOptions: { pie: { allowPointSelect: true,
                            cursor: 'pointer',
                            dataLabels: { enabled: false },
                            showInLegend: true }
	    },
	    series: [{ type: 'pie', 	data: parse_csv(csv, index, 20) }]
	});
}

function parse_csv(csv, index, top) {
	var data = []; var splitted = csv.split('\n'); var sum = 0;
	for(var i=1; i < splitted.length; i++) {
		cols = splitted[i].split('\t');
		if(cols[0] == "") continue;
		if (typeof top == 'undefined' || i <= top) {
			data.push([cols[1], Number(cols[index])]);
		} else {
			sum += Number(cols[index]);
		}
	}
	if (sum != 0) { data.push(["Others", sum]); }
	return data;
}

$(document).ready(function() {
  report_date = /^.*?date=([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]).*$/g.exec(window.location.search)[1]
  load_data(report_date);
  $('#resources').attr('href','/ui/http-monitoring/resources?date='+report_date);
});
