/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2019
 */


create_link = function(chart) {
    var min = chart.xAxis[0].getExtremes().userMin;
    var max = chart.xAxis[0].getExtremes().userMax;
    var rses = "";
    $('#rseselect').multipleSelect('getSelects').forEach(function(rse) {
        rses += rse + ',';
    })

    var params = "?rses=" + rses.slice(0,-1);
    if (min != undefined && max != undefined) {
        params += "&min=" + Math.floor(min) + "&max=" + Math.floor(max);
    }
    var link = window.location.href.split('?')[0] + params;
    $("#copyurl").html("<a href=" + link + ">" + link + "</a>");
    $('#myModal').foundation('reveal', 'open');
}

$(document).ready(function(){
    var chart = $("#rseplot").highcharts( {
        plotOptions: { area: { stacking: 'normal' } },
        chart: { type: 'area',
                 zoomType: 'x' },
        yAxis: { title: { text: 'Bytes' },
                 min: 0 },
        xAxis: { type: 'datetime',
                 title: { text: 'Day' }, },
        credits: false,
        title: { text: 'No RSE loaded yet' },
        series: []
    });
    var rse_dict = Object();
    r.list_accounts({
        success: function(data) {
            $.each(data, function(index, value) {
                $("#accountselect").append($('<option>').attr('value', value['account']).text(value['account']));
            });
            $("#accountselect").removeAttr('multiple');
            $("#accountselect").chosen();
            $("#accountselect").chosen().change(function() {
                $('#rseselect').val('Please Select');
                $('#rseselect').trigger("chosen:updated");
                rse_dict = {};
    var chart = $("#rseplot").highcharts( {
        plotOptions: { area: { stacking: 'normal' } },
        chart: { type: 'area', 
                 zoomType: 'x' },
        yAxis: { title: { text: 'Bytes' },
                 min: 0 },
        xAxis: { type: 'datetime',
                 title: { text: 'Day' }, },
        credits: false,
        title: { text: 'No RSE loaded yet' },
        series: []
    });
            });
        },
        error: function(jqXHR, textStatus, errorThrown) {
        }
    });
    var series = Array();
    r.list_rses({
        success: function(data) {
            $.each(data, function(index, value) {
                $("#rseselect").append($('<option>').attr('value', value.rse).text(value.rse));
            });
            $("#rseselect").chosen();
            var start_date = new Date(1547078400000);
            $("#rseselect").chosen().change(function() {
                 var rses = $("#rseselect").val();
                 var today = new Date().getTime();
                 series = [];
                 if (rses && rses != []){
                     $.each(rses, function(index, rse) {
                          if (rse in rse_dict){
                              series.push({'name': rse, 'data': rse_dict[rse]});
                          }
                     });
                     $.each(rses, function(index, rse) {
                         if (!(rse in rse_dict)) {
                             r.list_account_usage_history({
                                 account: $("#accountselect").val(),
                                 rse: rse,
                                 success: function(data) {
                                     entries = [];
                                     var bytes = -1;
                                     var latest_date = -1;
                                     var yesterday = -1;
                                     data.forEach(function(entry) {
                                         bytes = entry["bytes"];
                                         date = entry["updated_at"];
                                         latest_date = new Date(date.split('T')[0]).getTime();
                                         if (yesterday > 0){
                                             var current_date = yesterday;
                                             while (current_date + 86400000 < latest_date) {
                                                 current_date += 86400000;
                                                 if (current_date > start_date) {
                                                     entries.push([current_date, bytes]);
                                                 }
                                             }
                                         }
                                         if (latest_date > start_date) {
                                             entries.push([latest_date, bytes]);
                                         }
                                         yesterday = latest_date;
                                     });
                                     // Complete till today
                                     if (latest_date > 0) {
                                         var current_date = latest_date;
                                         while (current_date + 86400000 < today){
                                             current_date += 86400000;
                                             if (current_date > start_date) {
                                                  entries.push([current_date, bytes]);
                                             }
                                         }

                                     }
                                     rse_dict[rse] = entries;
                                     series.push({'name': rse, 'data': entries});
                                     var chart = $("#rseplot").highcharts( {
                                         plotOptions: { area: { stacking: 'normal' } },
                                         chart: { type: 'area',
                                                  zoomType: 'x' },
                                         yAxis: { title: { text: 'Bytes' },
                                                  min: 0 },
                                         xAxis: { type: 'datetime',
                                                  title: { text: 'Day' }, },
                                         credits: false,
                                         title: { text: 'Space used by RSEs' },
                                         series: series
                                     });
                                 },
                                 error: function(jqXHR, textStatus, errorThrown) {
                                 }
                             });
                         }
                    });
                 }
                 var chart = $("#rseplot").highcharts( {
                     plotOptions: { area: { stacking: 'normal' } },
                     chart: { type: 'area',
                              zoomType: 'x' },
                     yAxis: { title: { text: 'Bytes' },
                              min: 0 },
                     xAxis: { type: 'datetime',
                              title: { text: 'Day' }, },
                     credits: false,
                     title: { text: 'Space used by RSEs' },
                     series: series
                 });
            });
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log('Could not list RSEs: ' + textStatus);
        }
    });
});
