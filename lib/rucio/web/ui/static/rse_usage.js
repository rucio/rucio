/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 */

var check_checkAll = false;

function update_chart(chart) {

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

                data.forEach(function(e) {
                    e = e.split('\t');
                    tmp_v = parseInt(e[1], 10);

                    /* fix for Joaquin's exabyte file,
                     *  just keep the previous value
                     */
                    if (tmp_v > 9000000000000000000) {
                        bytes.push([new Date(e[3]).getTime(), previous]);
                    } else {
                        previous = tmp_v;
                        bytes.push([new Date(e[3]).getTime(), tmp_v]);
                    }
                });
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

    chart.hideLoading();
    chart.redraw();
};

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
                    update_chart(chart.highcharts());
                },
                onCheckAll: function() {
                    if (!check_checkAll) {
                        update_chart(chart.highcharts());
                    }
                    check_checkAll = false;
                },
                onUncheckAll: function() {
                    update_chart(chart.highcharts());
                    check_checkAll = false;
                },
                onClick: function() {
                    update_chart(chart.highcharts());
                    check_checkAll = true;
                }
            });
            $.each(data, function(index, value) {
                $("#rseselect").append($('<option>').attr('value', value.rse).text(value.rse));
            });
            $("#rseselect").multipleSelect('refresh');


            $("#clear_selection").click(function(){$("#rseselect").multipleSelect('uncheckAll')});
            $("#redraw_chart").click(function(){$("#rseplot").highcharts().redraw()});

        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log('Could not list RSEs: ' + textStatus);
        }
    });

});
