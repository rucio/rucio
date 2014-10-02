/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
 */

var usage_options = {
    chart: {
        type: 'area',
        zoomType: 'x',
    },
    title: {
        text: '',
    },
    subtitle: {
        text: '',
    },
    credits: false,
    xAxis: {
        categories: [],
        type: 'datetime',
        tickInterval: 10,
        title: {
            text: 'Date'
        },
        dateTimeLabelFormats: {
            second: '%d.%m'
        },
        labels: {
            formatter: function() {
                return Highcharts.dateFormat('%d.%m', this.value);
            },
        }
    },
    yAxis: {
        min: 0,
        title: {
            text: 'Bytes'
        }
    },
    plotOptions: {
        area: {
            stacking: 'normal'
        }
    },
    series: []
};

function create_plot(usage_data) {
    usage_options.series = []
    var cat = [];
    var free = [];
    var used = [];

    data = usage_data.split('\n');

    $.each(data, function(index, line) {
            values = line.split('\t');
            cat.push(Date.parse(values[3]));
            free.push(parseInt(values[1]));
            used.push(parseInt(values[2]));
        });

    usage_options.xAxis.categories = cat;
    usage_options.series.push({'name': 'free', data: free, animation:false});
    usage_options.series.push({'name': 'used', data: used, animation:false});
    $("#rseplot").highcharts(usage_options);
};

function read_data() {
    var rse = $("#rseselect option:selected").text();
    var today = new Date();
    var yyyy = today.getFullYear().toString();
    var mm = (today.getMonth()+1).toString();
    var dd  = today.getDate().toString();
    var date = yyyy + '-' + (mm[1]?mm:"0"+mm[0]) + '-' + (dd[1]?dd:"0"+dd[0]);
    r.list_rse_usage_history_from_dumps({
            account: account,
            date: date,
            rse: rse,
            success: function(data) {
                create_plot(data);
            },
            error: function(jqXHR, textStatus, errorThrown) {
                if (errorThrown == "Not Found") {
                    $('#problem').html("No data found for chosen RSE");
                }
            }
        });
};

$(document).ready(function(){
        r.list_rses({
                account: account,
                success: function(data) {
                    $.each(data, function(index, value) {
                            $("#rseselect").append($("<option/>").attr("value", value.rse).text(value.rse));
                        })
                        },
                error: function(jqXHR, textStatus, errorThrown) {
                    console.log(textStatus);
                }
            });
    });
