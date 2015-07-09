/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2015
 */


function draw_pie(data) {
    plot = chart = $('#results_pie').highcharts({
        chart: {
            plotBackgroundColor: null,
            plotBorderWidth: null,
            plotShadow: false,
        },
        title: {
            text: "Number of bad replicas (suspicious not included) by states"
        },
        tooltip: {
            pointFormat: '{series.name}: <b>{point.percentage:.1f}%</b>'
        },
        plotOptions: {
            pie: {
                allowPointSelect: true,
                cursor: 'pointer',
                dataLabels: {
                    enabled: true,
                    format: '<b>{point.name}</b>: {point.percentage:.1f} %',
                    style: {
                        color: (Highcharts.theme && Highcharts.theme.contrastTextColor) || 'black'
                    }
                },
                showInLegend: true
            }
        },
        series: [{ type: 'pie', name: "Percent", data: data, animation: false }]
    });
    if (data[0].y == 0 && data[1].y == 0 && data[2].y == 0){
        plot.hide();
    }
    else{
        plot.show();
    }
}



$(document).ready(function(){

    dt = $('#badreplicasummary').DataTable();
    var today = new Date();
    var ms = today.getTime() + 86400000;
    var to_date = new Date(ms);
    var ms = to_date.getTime() - 86400000 * 7;
    var from_date = new Date(ms);
    $("#datepicker1").datepicker({
                                      defaultDate: from_date,
                                      minDate: new Date(2015, 0, 1),
                                      onSelect: function(){
                                          from_date = $("#datepicker1").val();
                                          $("#datepicker2").datepicker('setDate', from_date).datepicker('option', 'minDate', from_date);
                                      }
                                 });
    $("#datepicker2").datepicker({
                                      defaultDate: to_date,
                                      minDate: from_date,
                                      onSelect: function(){
                                          to_date = $("#datepicker2").val();
                                      }
                                 });
    $("#submit_button").click(function(){
        if (typeof from_date == "undefined"){
            alert('Please select a start date');
            return
        }
        else if (typeof to_date == "undefined"){
                alert('Please select an end date');
                return
            }
        var date_array = from_date.toString().split('/');
        if (date_array.length == 3){
            from_date = date_array[2] + '-' + date_array[0] + '-' + date_array[1];
        }
        else if (typeof from_date != 'string'){
                 from_date = from_date.toISOString().slice(0, 10);
             }
        date_array = to_date.toString().split('/');
        if (date_array.length == 3){
            to_date = date_array[2] + '-' + date_array[0] + '-' + date_array[1];
        }
        else if (typeof to_date != 'string'){
                 to_date = to_date.toISOString().slice(0, 10);
             }

        dt.destroy();
        r.get_bad_replicas_summary({rse_expression: url_param('rse_expression'), from_date: from_date, to_date: to_date, success: function(data) {
             var res = [];
             var key = '';
             var dict = {};
             var pie_data = [];
             for (var i = 0; i < data.length; i++){
                 key = data[i]['rse'] + "|" + data[i]['created_at'] + "|" + data[i]['reason']
                 if (!(key in dict)){
                     dict[key] = {};
                     dict[key]['BAD'] = 0;
                     dict[key]['DELETED'] = 0;
                     dict[key]['LOST'] = 0;
                     dict[key]['RECOVERED'] = 0;
                     dict[key]['SUSPICIOUS'] = 0;
                 }
                 if ('BAD' in data[i]){
                     dict[key]['BAD'] = data[i]['BAD'];
                 }
                 if ('DELETED' in data[i]){
                     dict[key]['DELETED'] = data[i]['DELETED'];
                 }
                 if ('LOST' in data[i]){
                     dict[key]['LOST'] = data[i]['LOST'];
                 }
                 if ('RECOVERED' in data[i]){
                     dict[key]['RECOVERED'] = data[i]['RECOVERED'];
                 }
                 if ('SUSPICIOUS' in data[i]){
                     dict[key]['SUSPICIOUS'] = data[i]['SUSPICIOUS'];
                 }
             }
             var tmp = [];
             var tmp_dict = {};
             for (var k in dict){
                 tmp = k.split('|');
                 tmp_dict = {};
                 tmp_dict['rse'] = tmp[0];
                 var tmp_date = tmp[1].split(' ');
                 tmp_dict['created_at'] = tmp_date[1] + ' ' + tmp_date[2] + ' ' + tmp_date[3];
                 tmp_dict['reason'] = tmp[2];
                 var isURL = tmp[2].indexOf("http") == 0;
                 if (isURL){
                     tmp_dict['reason'] = '<a href="' + tmp[2] + '">' + tmp[2] + '</a>';
                 }
                 tmp_dict['BAD'] = dict[k]['BAD'];
                 if  (dict[k]['BAD'] != 0){
                     tmp_dict['BAD'] = '<a href="/bad_replicas?rse=' + tmp[0] + '&state=BAD">' + dict[k]['BAD'] + '</a>';
                 }
                 tmp_dict['DELETED'] = dict[k]['DELETED'];
                 if  (dict[k]['DELETED'] != 0){
                     tmp_dict['DELETED'] = '<a href="/bad_replicas?rse=' + tmp[0] + '&state=DELETED">' + dict[k]['DELETED'] + '</a>';
                 }
                 tmp_dict['LOST'] = dict[k]['LOST'];
                 if  (dict[k]['LOST'] != 0){
                     tmp_dict['LOST'] = '<a href="/bad_replicas?rse=' + tmp[0] + '&state=LOST">' + dict[k]['LOST'] + '</a>';
                 }
                 tmp_dict['RECOVERED'] = dict[k]['RECOVERED'];
                 if  (dict[k]['RECOVERED'] != 0){
                     tmp_dict['RECOVERED'] = '<a href="/bad_replicas?rse=' + tmp[0] + '&state=RECOVERED">' + dict[k]['RECOVERED'] + '</a>';
                 }
                 tmp_dict['SUSPICIOUS'] = dict[k]['SUSPICIOUS'];
                 if  (dict[k]['SUSPICIOUS'] != 0){
                     tmp_dict['SUSPICIOUS'] = '<a href="/bad_replicas?rse=' + tmp[0] + '&state=SUSPICIOUS">' + dict[k]['SUSPICIOUS'] + '</a>';
                 }
                 res.push(tmp_dict)
             }
             var download = '<a href="data:application/octet-stream;base64,' + btoa(JSON.stringify(res)) + '" download="dump.json">download as JSON</a>';
             $('#downloader').html(download);
             dt = $('#badreplicasummary').DataTable( {
                 retrieve: true,
                 data: res,
                 columns: [{'data': 'rse'},
                           {'data': 'reason'},
                           {'data': 'created_at'},
                           {'data': 'BAD'},
                           {'data': 'DELETED'},
                           {'data': 'LOST'},
                           {'data': 'RECOVERED'},
                           {'data': 'SUSPICIOUS'}],
                 footerCallback: function (row, data, start, end, display) {
                    var api = this.api(), data;
                    var total_bad = 0;
                    $.each(api.column(3, {page: 'current'}).data(), function(index, value) {
                        html = $.parseHTML(value)
                        var num = 0;
                        if (html != null){
                            num = parseInt(html[0].text);
                        }
                        total_bad += num
                    });

                    var total_deleted = 0;
                    $.each(api.column(4, {page: 'current'}).data(), function(index, value) {
                        html = $.parseHTML(value)
                        var num = 0;
                        if (html != null){
                            num = parseInt(html[0].text);
                        }
                        total_deleted += num

                    });

                    var total_lost = 0;
                    $.each(api.column(5, {page: 'current'}).data(), function(index, value) {
                        html = $.parseHTML(value)
                        var num = 0;
                        if (html != null){
                            num = parseInt(html[0].text);
                        }
                        total_lost += num

                    });

                    var total_recovered = 0;
                    $.each(api.column(6, {page: 'current'}).data(), function(index, value) {
                        html = $.parseHTML(value)
                        var num = 0;
                        if (html != null){
                            num = parseInt(html[0].text);
                        }
                        total_recovered += num

                    });

                    var total_suspicious = 0;
                    $.each(api.column(7, {page: 'current'}).data(), function(index, value) {
                        html = $.parseHTML(value)
                        var num = 0;
                        if (html != null){
                            num = parseInt(html[0].text);
                        }
                        total_suspicious += num

                    });

                    $(api.column(0).footer()).html('Total');
                    $(api.column(1).footer()).html('');
                    $(api.column(2).footer()).html('');
                    $(api.column(3).footer()).html(total_bad);
                    $(api.column(4).footer()).html(total_deleted);
                    $(api.column(5).footer()).html(total_lost);
                    $(api.column(6).footer()).html(total_recovered);
                    $(api.column(7).footer()).html(total_suspicious);
                    pie_data = [['Bad replicas (transient state)', total_bad], ['Deleted replicas', total_deleted], ['Lost replicas', total_lost], ['Recovered replicas', total_recovered]];
                    draw_pie(pie_data);
                 }
             });
             dt.order([2, 'asc']).draw();
            }
        });
    });
 });
