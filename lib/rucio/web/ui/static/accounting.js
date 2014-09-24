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
        backgroundColor:'rgba(255, 255, 255, 0.1)'
    },
    title: {
        text: '',
        x: -20
    },
    subtitle: {
        text: '',
        x: -20
    },
    xAxis: {
        categories: [],
        type: 'datetime',
        tickInterval: 4,
        title: {
            text: 'Date'
        },
        dateTimeLabelFormats: {
            second: '%H:%M:%S'
        },
        labels: {
            formatter: function() {
                return Highcharts.dateFormat('%H:%M:%S', this.value);
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

function create_plot(rse, intval, usage_data) {
    usage_options.series = []
    var cat = [];
    var free = [];
    var used = [];

    usage_options.title.text = rse;

    for(var i=usage_data.length-1; i != 0; i--){
        cat.push(usage_data[i][0] - (usage_data[i][0] % 3600000));
            free.push(usage_data[i][1]);
            used.push(usage_data[i][2]);
        }
    usage_options.xAxis.categories = cat;
    usage_options.series.push({'name': 'free', data: free});
    usage_options.series.push({'name': 'used', data: used});
    if (intval == 1) {
        usage_options.xAxis.labels.formatter = function() {
                return Highcharts.dateFormat('%H:%M', this.value);
        };
        usage_options.subtitle.text = "One Day";
    } else if (intval == 2) {
        usage_options.xAxis.labels.formatter = function() {
                return Highcharts.dateFormat('%d.%m', this.value);
        };
        usage_options.subtitle.text = "One Week";
    } else {
        usage_options.xAxis.labels.formatter = function() {
                return Highcharts.dateFormat('%d.%m.', this.value);
        };
        usage_options.subtitle.text = "One Month";
        usage_options.xAxis.tickInterval = 10;
    }
    $("#usageplot").highcharts(usage_options);
};

function read_data(rse, intval) {
    var usage_data = [];
    var today = new Date();
    var threshold = today.setDate(today.getDate()-1);
    var mod = 1;
    if (intval == 2) {
        var threshold = today.setDate(today.getDate()-7);
        mod = 48;
    } else if (intval == 3) {
        var threshold = today.setMonth(today.getMonth - 1);
        mod = 48;
    }
    r.list_rse_usage_history({
            account: account,
                async: false,
            rse: rse,
            source: 'rucio',
            success: function(data) {
                $.each(data, function(index, value) {
                        var date = Date.parse(value.updated_at);
                        if (date < threshold) {
                            return false;
                        }
                        if (index % mod == 0) {
                            usage_data.push([date, value.free, value.used]);
                        }
                    })
                    },
            error: function(jqXHR, textStatus, errorThrown) {
                if (errorThrown == "Not Found") {
                    $('#problem').html("No data found for chosen RSE");
                }
            }
        });
    return usage_data;
};

$(document).ready(function(){
        var rse = "";
        $("#rseselect").selectmenu();

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

        $("#intvalselect").selectmenu();
        $("#intvalselect").append($("<option/>").attr("value", 1).text("Daily"));
        $("#intvalselect").append($("<option/>").attr("value", 2).text("Weekly"));
        $("#intvalselect").append($("<option/>").attr("value", 3).text("Monthly"));
        //$("#intvalselect").val("1").selectmenu('refresh');
        $("#update").button().click(function( event ) {
                var rse = $("#rseselect option:selected").text();
                var intval = $("#intvalselect option:selected").val();
                var intval_text = $("#intvalselect option:selected").text();
                usage_data = read_data(rse, intval);
                create_plot(rse, intval, usage_data);
            });
    });
