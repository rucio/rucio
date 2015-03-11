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
    $('#results_pie').highcharts({
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
        series: [{ type: 'pie', data: data, animation: false }]
    });
}



$(document).ready(function(){

    r.get_bad_replicas_summary({rse_expression: url_param('rse_expression'), from_date: url_param('from_date'), to_date: url_param('to_date'), success: function(data) {
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
                 dict[key]['RECOVERED'] = 0;
                 dict[key]['SUSPICIOUS'] = 0;
             }
             if ('BAD' in data[i]){
                 dict[key]['BAD'] = data[i]['BAD'];
             }
             if ('DELETED' in data[i]){
                 dict[key]['DELETED'] = data[i]['DELETED'];
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
             tmp_dict['created_at'] = tmp_date[1] + ' ' + tmp_date[2] + ' ' +  tmp_date[3];
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

                var total_recovered = 0;
                $.each(api.column(5, {page: 'current'}).data(), function(index, value) {
                    html = $.parseHTML(value)
                    var num = 0;
                    if (html != null){
                        num = parseInt(html[0].text);
                    }
                    total_recovered += num

                });

                var total_suspicious = 0;
                $.each(api.column(6, {page: 'current'}).data(), function(index, value) {
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
                $(api.column(5).footer()).html(total_recovered);
                $(api.column(6).footer()).html(total_suspicious);
                pie_data = [['Bad replicas (transient state)', total_bad], ['Deleted replicas', total_deleted], ['Recovered replicas', total_recovered]];
         draw_pie(pie_data);
             }

         });
         dt.order([2, 'asc']).draw();
       }
    });
 });
