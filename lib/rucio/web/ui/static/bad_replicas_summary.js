/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2015-2018
 */

function draw_pie(data) {
    plot = chart = $('#results_pie').highcharts({
        chart: {
            plotBackgroundColor: null,
            plotBorderWidth: null,
            plotShadow: false,
        },
        title: {
            text: "Number of bad replicas by states"
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
    const ms_per_day = 60 * 60 * 24 * 1000;
    var show_suspicious = false;
    $("#datepicker1").datepicker({
                                      defaultDate: '-6d',
                                      minDate: new Date(2015, 0, 1),
                                      dateFormat: $.datepicker.ISO_8601,
                                      onSelect: function(new_from_date) {
                                          const new_min_to_date = new Date(new Date(new_from_date).getTime() + ms_per_day);
                                          $('#datepicker2').datepicker('option', 'minDate', new_min_to_date);
                                      }
                                 });
    $("#datepicker2").datepicker({
                                      defaultDate: '+1d',
                                      minDate: '-5d',
                                      dateFormat: $.datepicker.ISO_8601,
                                 });
    $("#submit_button").click(function(){
        $('#show_suspicious').click(function() {
            show_suspicious = true;
        });

        dt.destroy();
        $('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
        r.get_bad_replicas_summary({rse_expression: url_param('rse_expression'),
                                    from_date: $('#datepicker1').val(),
                                    to_date: $('#datepicker2').val(),
                                    success: function(data) {
             $('#loader').html('');

             var tbl_head = '<thead><tr><th>RSE</th><th>Reason</th><th>Created_at</th><th>Bad (transient)</th><th>Deleted</th><th>Lost</th><th>Recovered</th>';
             if  (show_suspicious){
                 tbl_head +='<th>Suspicious</th>';
             }
             tbl_head += '</tr></thead>'

             var tbl_foot = '<tfoot><tr><th>RSE</th><th>Reason</th><th>Created_at</th><th>Bad (transient)</th><th>Deleted</th><th>Lost</th><th>Recovered</th>';
             if  (show_suspicious){
                 tbl_foot +='<th>Suspicious</th>';
             }
             tbl_foot += '</tr></foot>'
             $("#badreplicasummary").remove();
             $("#badreplicasummary2").append('<table id="badreplicasummary" style="word-wrap: break-word;">'+tbl_head+tbl_foot+'</table>');

             var res = [];
             var list_result = [];
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
                 if  (show_suspicious && dict[k]['SUSPICIOUS'] != 0){
                     tmp_dict['SUSPICIOUS'] = '<a href="/bad_replicas?rse=' + tmp[0] + '&state=SUSPICIOUS">' + dict[k]['SUSPICIOUS'] + '</a>';
                 }
                 var res_list = [];
                 res_list.push(tmp_dict['rse']);
                 res_list.push(tmp_dict['reason']);
                 res_list.push(tmp_dict['created_at']);
                 res_list.push(tmp_dict['BAD']);
                 res_list.push(tmp_dict['DELETED']);
                 res_list.push(tmp_dict['LOST']);
                 res_list.push(tmp_dict['RECOVERED']);
                 if (show_suspicious){
                     res_list.push(tmp_dict['SUSPICIOUS'])
                     list_result.push(res_list);
                 }
                 else{
                     if (tmp_dict['BAD'] != 0 || tmp_dict['LOST'] != 0 || tmp_dict['RECOVERED'] !=0){
                         list_result.push(res_list);
                     }
                 }
                 res.push(tmp_dict);
             }
             var download = '<a href="data:application/octet-stream;base64,' + btoa(JSON.stringify(res)) + '" download="dump.json">download as JSON</a>';
             $('#downloader').html(download);
             dt = $('#badreplicasummary').DataTable( {
                 retrieve: true,
                 data: list_result,
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

                    pie_data = [['Bad replicas (transient state)', total_bad], ['Deleted replicas', total_deleted], ['Lost replicas', total_lost], ['Recovered replicas', total_recovered]];
                    var total_suspicious = 0;
                    var colCount = data[0].length;
                    if (colCount > 7){
                        $.each(api.column(7, {page: 'current'}).data(), function(index, value) {
                            html = $.parseHTML(value)
                            var num = 0;
                            if (html != null){
                                num = parseInt(html[0].text);
                            }
                            total_suspicious += num

                        });
                        $(api.column(7).footer()).html(total_suspicious);
                        pie_data.push(['Suspicious replicas', total_suspicious])
                    }
                    $(api.column(0).footer()).html('Total');
                    $(api.column(1).footer()).html('');
                    $(api.column(2).footer()).html('');
                    $(api.column(3).footer()).html(total_bad);
                    $(api.column(4).footer()).html(total_deleted);
                    $(api.column(5).footer()).html(total_lost);
                    $(api.column(6).footer()).html(total_recovered);
                    draw_pie(pie_data);
                 }
             });
             dt.order([2, 'asc']).draw();
            }
        });
    });
 });
