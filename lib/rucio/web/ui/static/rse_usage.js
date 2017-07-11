/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2015, 2017
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 */

var check_checkAll = false;

function update_chart(chart, min, max) {
    while(chart.series.length > 0) {
        chart.series[0].remove(false);
    }
    chart.showLoading();
    chart.redraw();

    if ($('#rseselect').multipleSelect('getSelects').length == 1) {
        chart.setTitle({text: 'Single RSE Usage'}, {}, false);
    } else {
        chart.setTitle({text: 'Stacked RSE Usage'}, {}, false);
    }

    $('#rseselect').multipleSelect('getSelects').forEach(function(rse) {

        r.list_rse_usage_history_from_dumps({
            rse: rse,
            success: function(data) {
                data = data.split('\n');
                data.pop()

                var bytes = [];
                var previous = 0;
                var tmp_v = 0;

                var date = 0;
                data.forEach(function(e) {
                    e = e.split('\t');
                    tmp_v = parseInt(e[1], 10);
                    date = new Date(e[3]).getTime();

                    /* fix for Joaquin's exabyte file,
                     *  just keep the previous value
                     */
                    if (tmp_v > 9000000000000000000) {
                        bytes.push([date, previous]);
                    } else {
                        previous = tmp_v;
                        bytes.push([date, tmp_v]);
                    }
                });

                /* if the series is not complete to the
                 *  current day, fill it up with the
                 * last reported value
                 */
                var today = new Date().getTime();
                while (date < today) {
                    date += 86400 * 1000;
                    console.log(date, tmp_v);
                    bytes.push([date, tmp_v]);
                }

                chart.addSeries( {
                    animation: false,
                    name: rse,
                    data: bytes,
                    redraw: false
                });
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.log('Ignoring missing RSE usage data');
            }

        });
    });

    chart.yAxis[0].removePlotLine("limit_line");
    chart.yAxis[0].removePlotLine("quota_line");
    if ($('#rseselect').multipleSelect('getSelects').length == 1) {
        var rse = $('#rseselect').multipleSelect('getSelects')[0];
        if ((rse.indexOf('DATADISK') > -1) || (rse.indexOf('PRODDISK') > -1) || (rse.indexOf('SCRATCHDISK') > -1)) {
            r.get_rse_usage({
                rse: rse,
                success: function(usages) {
                    minfreespace = 0;
                    srm = 0;
                    $.each(usages, function(index, usage) {
                        if (usage['source'] == 'min_free_space') {
                            minfreespace = usage['total'];
                        } else if (usage['source'] == 'srm') {
                            srm = usage['total'];
                        }
                    });
                    var uspacelimit = srm - minfreespace;
                    var limit_text = parseInt(uspacelimit / (1000*1000*1000*1000));
                    var yesterday = new Date();
                    yesterday.setDate(yesterday.getDate() - 1);
                    // little trick to include the quota line in auto scaling
                    chart.addSeries( {
                        animation: false,
                        name: 'usage_limit',
                        type: 'scatter',
                        marker: {
                            enabled: false
                        },
                        data: [[yesterday.getTime(), uspacelimit]]
                    });
                    chart.yAxis[0].addPlotLine({
                        color: '#FF0000',
                        width: 2,
                        value: uspacelimit,
                        id: "limit_line",
                        label: {
                            text: "Used space limit: " + limit_text + "TB"
                        },
                        zIndex: 10
                    });

                }, error: function(jqXHR, textStatus, errorThrown) {
                    console.log('Ignoring missing RSE usage data');
                }
            });
        } else {
            r.list_rse_attributes({
                rse: rse,
                success: function(attr) {
                    var physgroup = attr[0]["physgroup"];
                    if (physgroup != 'None') {
                        r.get_account_limits({
                            account: physgroup,
                            success:function(limits) {
                                if (limits[rse] != undefined) {
                                    var rse_limit = limits[rse];
                                    var quota_text = parseInt(limits[rse] / (1000*1000*1000*1000));
                                    var yesterday = new Date();
                                    yesterday.setDate(yesterday.getDate() - 1);
                                    // little trick to include the quota line in auto scaling
                                    chart.addSeries( {
                                        animation: false,
                                        name: 'limit',
                                        type: 'scatter',
                                        marker: {
                                            enabled: false
                                        },
                                        data: [[yesterday.getTime(), rse_limit]]
                                    });
                                    chart.yAxis[0].addPlotLine({
                                        color: '#FF0000',
                                        width: 2,
                                        value: rse_limit,
                                        id: "quota_line",
                                        label: {
                                            text: "Quota (" + physgroup + "): " + quota_text + "TB"
                                        },
                                        zIndex: 10
                                    });
                                }
                            },
                            error: function(jqXHR, textStatus, errorThrown) {
                            }
                        });
                    }
                },
                error: function(jqXHR, textStatus, errorThrown) {
                }
            });
        }
    }

    chart.hideLoading();
    if (min > 0 && max > 0) {
        chart.xAxis[0].setExtremes(min, max);
        chart.renderer.button('Reset zoom', null, null, function() {
            chart.xAxis[0].setExtremes(null, null);
            $("#resetButton").remove();
        }, {
            zIndex: 100
        }).attr({
            align: 'right',
            title: 'Reset zoom level 1:1',
            id: 'resetButton'
        }).add(chart.zoomGroupButton).align({
            align: 'right',
            x: -20,
            y: 57
        }, false, null);
    }
    chart.redraw();
};

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
    r.list_rses({
        account: account,
        success: function(data) {
            $("#rseselect").multipleSelect({
                filter: true,
                isOpen: true,
                keepOpen: true,
                maxHeight: 280,
                minimumCountSelected: 1,
                placeholder: 'Select RSEs...',
                onOptgroupClick: function() {
                    update_chart(chart.highcharts(), 0, 0);
                },
                onCheckAll: function() {
                    if (!check_checkAll) {
                        update_chart(chart.highcharts(), 0, 0);
                    }
                    check_checkAll = false;
                },
                onUncheckAll: function() {
                    update_chart(chart.highcharts(), 0, 0);
                    check_checkAll = false;
                },
                onClick: function() {
                    update_chart(chart.highcharts(), 0, 0);
                    check_checkAll = true;
                }
            });
            $.each(data, function(index, value) {
                $("#rseselect").append($('<option>').attr('value', value.rse).text(value.rse));
            });
            $("#rseselect").multipleSelect('refresh');

            $("#clear_selection").click(function(){$("#rseselect").multipleSelect('uncheckAll')});
            $("#redraw_chart").click(function(){$("#rseplot").highcharts().redraw()});
            $("#get_link").click(function() { create_link(chart.highcharts()); });
            var rse_string = url_param('rses');
            var rses;
            if (rse_string != '') {
                rses = rse_string.split(',');
            }

            $("#rseselect").multipleSelect('setSelects', rses);
            var min = 0;
            var max = 0;
            var s_min = url_param('min');
            var s_max = url_param('max');
            if (s_min != '') {
                min = parseInt(s_min);
            }
            if (s_max != '') {
                max = parseInt(s_max);
            }
            update_chart(chart.highcharts(), min, max);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log('Could not list RSEs: ' + textStatus);
        }
    });

});
