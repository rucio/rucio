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

var chart = null;
var check_checkAll = false;
var lock_states = {};
var expression = '';
var rses = '';


function handle_params() {
    expression = url_param('expression');
    if (expression != ''){
        $('#rse_expr_box').val(expression);
        eval_rse_expression();
        return;
    }

    rses = url_param('rses');
    if (rses != '') {
        rses = rses.split(',');
        $("#rseselect").multipleSelect('setSelects', rses);
        update_chart(chart.highcharts());
    }
}

function eval_rse_expression() {
    var expr = $("#rse_expr_box").val();
    $("#problem").html("");
    r.list_rses({
        account: account,
        expression: expr,
        success: function(data) {
            var selects = [];
            $.each(data, function(index, value) {
                selects.push(value['rse']);
            });
            $("#rseselect").multipleSelect('setSelects', selects);
            update_chart(chart.highcharts());
            insertParam('expression', expr);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (jqXHR.responseText.indexOf("RSE Expression resulted in an empty set") > -1) {
                $("#problem").html("<font color=\"red\">No RSEs matching the expression</font>");
            } else if (jqXHR.responseText.indexOf("Expression does not comply to RSE Expression syntax") > -1) {
                $("#problem").html("<font color=\"red\">Invalid Syntax</font>");
            }
        }
    });
}

function update_chart(chart) {
    while(chart.series.length > 0) {
        chart.series[0].remove(false);
    }
    chart.showLoading();
    chart.redraw();

    chart.setTitle({text: 'Lock States per RSE'}, {}, false);

    var ok = [];
    var replicating = [];
    var stuck = [];
    var categories = [];
    var rses = "";
    $('#rseselect').multipleSelect('getSelects').forEach(function(rse) {
        categories.push(rse);
        ok.push(lock_states[rse]['O']);
        replicating.push(lock_states[rse]['R']);
        stuck.push(lock_states[rse]['S']);
        rses += rse + ",";
    });
    rses = rses.substring(0, rses.length-1);
    if (rses != '') {
        insertParam('rses', rses);
    } else {
        clearParams();
    }
    chart.addSeries( {
        animation: false,
        name: 'Ok',
        data: ok,
        redraw: false,
        color: 'green'
    });
    chart.addSeries( {
        animation: false,
        name: 'Replicating',
        data: replicating,
        redraw: false,
        color: 'orange'
    });
    chart.addSeries( {
        animation: false,
        name: 'Stuck',
        data: stuck,
        redraw: false,
        color: 'red'
    });
    chart.xAxis[0].setCategories(categories);
    chart.hideLoading();
    chart.redraw();
};

$(document).ready(function(){
    chart = $("#rseplot").highcharts( {
        plotOptions: { column: { stacking: 'normal' }
                       },
        chart: { type: 'column' },
        yAxis: { title: { text: 'Locks' },
                 min: 0
                 },
        xAxis: { title: { text: 'RSE' },
                 categories: [],
               labels: {rotation:-45}},
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
                $("#rseselect").append($('<option>').attr('id', value.rse).attr('value', value.rse).text(value.rse));
            });
            $("#rseselect").multipleSelect('refresh');

            $("#clear_selection").click(function(){$("#rseselect").multipleSelect('uncheckAll');});
            $("#redraw_chart").click(function(){$("#rseplot").highcharts().redraw();});
            handle_params();
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log('Could not list RSEs: ' + textStatus);
        }
    });

    var now = new Date();
    now.setHours(now.getHours() - 1);

    var date = now.getFullYear() + '-';
    if ((now.getMonth() + 1) < 10) {
        date += '0' + (now.getMonth() + 1);
    } else {
        date += (now.getMonth() + 1);
    }
    date += '-';
    if (now.getDate() < 10) {
        date += '0' + now.getDate();
    } else {
        date += now.getDate();
    }
    var hour = now.getHours();
    if (hour < 10) {
        hour = '0' + hour;
    }

    r.get_rse_lock_states_from_dumps({
        date: date,
        hour: hour,
        success: function(data) {
            data = data.split('\n');
            $.each(data, function(index, value) {
                values = value.split('\t');
                if (!(values[0] in lock_states)) {
                    lock_states[values[0]] = {};
                }
                lock_states[values[0]][values[1]] = parseInt(values[2]);
            });
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log('Ignoring missing RSE usage data');
        }
    });

    $("#rse_expr_eval").click(function() {eval_rse_expression();});
    $("#rse_expr_box").keypress(function(event) {
        if (event.which == 13) {
            eval_rse_expression();
        }
    });
});
