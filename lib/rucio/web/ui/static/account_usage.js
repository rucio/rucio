/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2015
 */

value_to_color = function(value) {
    if (value < 0) {
        return '<font color="red">' + value.toFixed(2) + '</font>';
    } else if (value > 0) {
        return '<font color="green">' + value.toFixed(2) + '</font>';
    } else {
        return value.toFixed(2);
    }
}

$(document).ready(function(){
    var accounts = [];
    r.list_accounts({
        'account_type': 'GROUP',
        async: false,
        success: function(accs) {
            $.each(accs, function(i, acc) {
                accounts.push(acc['account']);
            });
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });

    r.get_account_usage_from_dumps({
        success: function(ret_data) {
            var str_data = ret_data.split('\n');
            var data = [];
            var disk_overview = {};
            var tape_overview = {};

            $.each(str_data, function(index, value) {
                if (value == "") {
                    return;
                }
                values = value.split('\t');
                var tmp = {};
                var tmp_overview = {};
                var to_tb = 1000*1000*1000*1000;

                if (accounts.indexOf(values[0]) == -1) {
                    return;
                }
                if (values[1].indexOf("SCRATCHDISK") > -1) {
                    return;
                }
                if (values[1].indexOf("USERDISK") > -1) {
                    return;
                }

                tmp['account'] = values[0];
                tmp['rse'] = values[1];
                tmp['quota'] = (parseInt(values[2]) / to_tb);
                tmp['usage'] = (parseInt(values[3]) / to_tb);
                tmp['difference'] = (parseInt(values[4]) / to_tb);
                tmp['total_quota'] = (parseInt(values[5]) / to_tb).toFixed(2);
                tmp['total_used'] = (parseInt(values[6]) / to_tb).toFixed(2);
                tmp['total_difference'] = (tmp['total_quota'] - tmp['total_used']).toFixed(2);

                data.push(tmp);
                if (tmp['rse'].indexOf('TAPE') > -1) {
                    if (tape_overview[values[0]] == undefined) {
                        tape_overview[values[0]] = {'account': values[0], 'quota': 0, 'usage': 0, 'difference': 0};
                    }
                    tape_overview[values[0]]['quota'] += tmp['quota'];
                    tape_overview[values[0]]['usage'] += tmp['usage'];
                    tape_overview[values[0]]['difference'] += tmp['difference'];
                } else {
                    if (disk_overview[values[0]] == undefined) {
                        disk_overview[values[0]] = {'account': values[0], 'quota': 0, 'usage': 0, 'difference': 0};
                    }
                    disk_overview[values[0]]['quota'] += tmp['quota'];
                    disk_overview[values[0]]['usage'] += tmp['usage'];
                    disk_overview[values[0]]['difference'] += tmp['difference'];
                }
            });

            var data_overview = [];
            var categories = [];
            var used = [];
            var quota = [];
            var difference = [];
            $.each(disk_overview, function(key, value) {
                data_overview.push(value);
                if (value['account'].indexOf('phys') == 0 || value['account'].indexOf('perf') == 0) {
                    categories.push(value['account']);
                    used.push(parseInt(value['usage']));
                    quota.push(parseInt(value['quota']));
                    if (parseInt(value['difference']) < 0) {
                        difference.push(0);
                    } else {
                        difference.push(parseInt(value['difference']));
                    }
                }
            });

            var tape_data_overview = [];
            var tape_categories = [];
            var tape_used = [];
            var tape_quota = [];
            var tape_difference = [];
            $.each(tape_overview, function(key, value) {
                tape_data_overview.push(value);
                    tape_categories.push(value['account']);
                    tape_used.push(parseInt(value['usage']));
                    tape_quota.push(parseInt(value['quota']));
                    if (parseInt(value['difference']) < 0) {
                        tape_difference.push(0);
                    } else {
                        tape_difference.push(parseInt(value['difference']));
                    }
            });

            $("#quotaplot").highcharts({
                chart: {
                    type: 'bar',
                    height: 800,
                },
                title: {
                    text: ''
                },
                xAxis: {
                    categories: categories,
                    title: { text: '' }
                },
                yAxis: {
                    title: { text: '' }
                },
                plotOptions: {
                    bar: {
                        dataLabels: {
                            enabled: true
                        }
                    },
                    series: {
                        pointPadding: 0.1,
                        groupPadding: 0.1
                    }
                },
                credits: false,
                series: [ {
                    name: 'Available Quota',
                    data: quota,
                    color: 'blue',
                    animation: false
                } , {
                    name: 'Used Space',
                    data: used,
                    color: 'red',
                    animation: false
                },  {
                    name: 'Free Space',
                    data: difference,
                    color: 'green',
                    animation: false
                }]
            });

            $.each(data_overview, function(index, d) {
                d['usage'] = d['usage'].toFixed(2);
                d['quota'] = d['quota'].toFixed(2);
                d['difference'] = value_to_color(d['difference']);
            });

            $.each(tape_data_overview, function(index, d) {
                d['usage'] = d['usage'].toFixed(2);
                d['quota'] = d['quota'].toFixed(2);
                d['difference'] = value_to_color(d['difference']);
            });

            $.each(data, function(index, d) {
                d['usage'] = d['usage'].toFixed(2);
                d['quota'] = d['quota'].toFixed(2);
                d['difference'] = value_to_color(d['difference']);
            });

            var dt_overview = $('#resulttable_overview').DataTable( {
                data: data_overview,
                bAutoWidth: false,
                paging: false,
                columns: [{'data': 'account'},
                          {'data': 'quota'},
                          {'data': 'usage'},
                          {'data': 'difference'}],
                footerCallback: function (row, data, start, end, display) {
                    var api = this.api(), data;

                    var total_quota = 0;
                    $.each(api.column(1, {page: 'current'}).data(), function(index, value) {
                        total_quota += parseFloat(value);
                    });

                    var total_used = 0;
                    $.each(api.column(2, {page: 'current'}).data(), function(index, value) {
                        total_used += parseFloat(value);
                    });

                    var total_difference = 0;
                    $.each(api.column(3, {page: 'current'}).data(), function(index, value) {
                        value = $(value).text();
                        total_difference += parseFloat(value);
                    });

                    $(api.column(0).footer()).html('Total');
                    $(api.column(1).footer()).html(total_quota.toFixed(2));
                    $(api.column(2).footer()).html(total_used.toFixed(2));
                    $(api.column(3).footer()).html(total_difference.toFixed(2));
                }
            });
            dt_overview.order([0, 'asc']).draw();

            var dt_overview_tape = $('#resulttable_tape_overview').DataTable( {
                data: tape_data_overview,
                bAutoWidth: false,
                paging: false,
                columns: [{'data': 'account'},
                          {'data': 'quota'},
                          {'data': 'usage'},
                          {'data': 'difference'}],
                footerCallback: function (row, data, start, end, display) {
                    var api = this.api(), data;

                    var total_quota = 0;
                    $.each(api.column(1, {page: 'current'}).data(), function(index, value) {
                        total_quota += parseFloat(value);
                    });

                    var total_used = 0;
                    $.each(api.column(2, {page: 'current'}).data(), function(index, value) {
                        total_used += parseFloat(value);
                    });

                    var total_difference = 0;
                    $.each(api.column(3, {page: 'current'}).data(), function(index, value) {
                        value = $(value).text();
                        total_difference += parseFloat(value);
                    });

                    $(api.column(0).footer()).html('Total');
                    $(api.column(1).footer()).html(total_quota.toFixed(2));
                    $(api.column(2).footer()).html(total_used.toFixed(2));
                    $(api.column(3).footer()).html(total_difference.toFixed(2));
                }
            });
            dt_overview_tape.order([0, 'asc']).draw();

            var dt = $('#resulttable_details').DataTable( {
                data: data,
                bAutoWidth: false,
                paging: false,
                columns: [{'data': 'account', 'width': '25%'},
                          {'data': 'rse', 'width': '25%'},
                          {'data': 'quota'},
                          {'data': 'usage'},
                          {'data': 'difference'}]
            });
            dt.order([0, 'asc']).draw();
            $('#loader').html('');
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (errorThrown == "Not Found") {
                $('#problem').html("Cannot load account usage");
                $('#loader').html('');
            }
        }
    });
});
