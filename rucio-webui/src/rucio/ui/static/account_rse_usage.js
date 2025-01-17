/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2015
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2019
 */

var result_html = '<table id="resulttable" class="compact stripe order-column" style="word-wrap: break-word;"><thead><tr><th>RSE</th><th>Quota</th><th>Used</th><th>Available</th><th>Files</th></tr></thead><tfoot><tr><th>RSE</th><th>Quota</th><th>Used</th><th>Available</th><th>Files</th></tr></tfoot></table>'

load_data = function(account_chosen) {
    $('#results').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    $('#rseplot').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    if (account_chosen == undefined) {
        var account_chosen = $("#account_input")[0].value;
    }
    r.get_account_limits({
        account: account_chosen,
        success: function(data) {
            new_data = {};
            $.each(data, function(index, limit) {
                new_data[index] = {'bytes': 0, 'bytes_limit': limit, 'files': 0};
            });
            r.get_account_usage({
                account: account_chosen,
                success: function(data) {
                    table_data = [];
                    var rse_dict = Object();
                    var start_date = new Date(1547078400000);
                    var today = new Date().getTime();
                    var series = Array();
                    var show_history = $('#show_history').is(":checked")
                    var nb_rses = data.length;
                    $.each(data, function(index, value) {
                        new_data[value['rse']] = {'bytes': value['bytes'], 'bytes_limit': value['bytes_limit'], 'files': value['files']}
                        if (show_history){
                             r.list_account_usage_history({
                                 account: account_chosen,
                                 rse: value['rse'],
                                 success: function(data1) {
                                     entries = [];
                                     var bytes = -1;
                                     var latest_date = -1;
                                     var yesterday = -1;
                                     data1.forEach(function(entry) {
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
                                     rse_dict[value['rse']] = entries;
                                     series.push({'name': value['rse'], 'data': entries});
                                     if (index == nb_rses - 1){
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
                                     }
                                 },
                                 error: function(jqXHR, textStatus, errorThrown) {
                                 }
                             });
                         }
                         else {
                             $('#rseplot').html('');
                         }
                    });
                    $('#results').html(result_html);
                    $.each(new_data, function(rse, value) {
                        value['rse'] = rse;
                        if (value['bytes_limit'] <= 0) {
                            value['difference'] = value['bytes_limit'];
                        } else {
                            value['difference'] = value['bytes_limit'] - value['bytes'];
                        }
                        value['bytes'] = filesize(value['bytes'], {'base': 10});
                        value['bytes_limit'] = filesize(value['bytes_limit'], {'base': 10});
                        value['difference'] = filesize(value['difference'], {'base': 10});
                        table_data.push(value);
                    });
                    var dt = $("#resulttable").DataTable( {
                        data: table_data,
                        bAutoWidth: false,
                        paging: false,
                        destroy: true,
                        columns: [{'data': 'rse'},
                                  {'data': 'bytes_limit'},
                                  {'data': 'bytes'},
                                  {'data': 'difference'},
                                  {'data': 'files'}],
                    });
                    dt.order([0, 'asc']).draw();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    $("#results").html('<font color="red">' + jqXHR['responseText'] + '</font>');
                    $('#rseplot').html('');
                }
            });
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $("#results").html('<font color="red">' + jqXHR['responseText'] + '</font>');
            $('#rseplot').html('');
        }
    });
};

$(document).ready(function(){
    account_chosen = url_param('account') || r.account;

    if (account_chosen != "") {
        $("#account_input").val(account_chosen);
        load_data(account_chosen);
    }

    $("#account_input").keydown(function(e) {
        if (e.keyCode == 13) {
            load_data();
        }
    });

    $("#select_account").on('click', function() {
        load_data();
    });
});
