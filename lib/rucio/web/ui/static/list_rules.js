/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2015
 */

var dt = null;

delete_rule = function(id) {
    r.delete_replication_rule({
        rule_id: id,
        success: function(data) {
            dt.row('.selected').remove().draw(false);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert(jqXHR['responseText']);
        }
    });
}

age_to_date = function(age) {
    var type = age.slice(-1);
    if (type != 'd' && type != 'h') {
        return new Date();
    }
    var interval = parseInt(age.slice(0,-1));
    var today = new Date();
    if (type == 'h') {
        return new Date(today.getTime() - (interval*1000*60*60));
    } else {
        return new Date(today.getTime() - (interval*1000*60*60*24));
    }
}

$(document).ready(function(){
    $('#subbar-details').html('[' + url_param('account') + ', ' + url_param('name') + ', ' + url_param('state') + ', ' + url_param('rse_expression')+ ']');

    $('#loader').html('<b>loading data .... please wait, this may take some time...</b><p>');
    var state = url_param('state');
    var age = '0d';
    if (url_param('age') != undefined) {
        age = url_param('age');
    }

    var download_name = "rules_" + url_param('account');
    if (state != "") {
        download_name += "_" + state;
    }
    if (age != "") {
        download_name += "_" + age;
    }
    if (url_param('activity') != "") {
        download_name += "_" + url_param('activity');
    }
    download_name += ".json";

    if (state.toLowerCase() == 'replicating') {
        state = 'R';
    } else if (state.toLowerCase() == 'ok') {
        state = 'O';
    } else if (state.toLowerCase() == 'stuck') {
        state = 'S';
    } else {
        state = '';
    }
    r.list_account_rules({
        account: url_param('account'),
        activity: url_param('activity'),
        state: state,
        rse_expression: url_param('rse_expression'),
        success: function(data) {
            var filtered_data = [];
            var threshold = age_to_date(age);
            $.each(data, function(index, value) {
                var created_at = Date.parse(value.created_at);
                if (created_at > threshold) {
                    return;
                }
                value.link = '<a href="/rule?rule_id=' + value.id + '">' + value.name + '</a>';
                if (value.locks_ok_cnt > 0) {
                    value.locks_ok_cnt = '<font color="green">' + value.locks_ok_cnt + '</font>';
                }
                if (value.locks_replicating_cnt > 0) {
                    value.locks_replicating_cnt = '<font color="orange">' + value.locks_replicating_cnt + '</font>';
                }
                if (value.locks_stuck_cnt > 0) {
                    value.locks_stuck_cnt = '<font color="red">' + value.locks_stuck_cnt + '</font>';
                }
                filtered_data.push(value);
            });

            var download = '<a href="data:application/octet-stream;base64,' + btoa(JSON.stringify(filtered_data)) + '" download="' + download_name + '">download as JSON</a>';
            $('#downloader').html(download);

            dt = $('#resulttable').DataTable( {
                data: filtered_data,
                bAutoWidth: false,
                pageLength: 100,
                "oLanguage": {
                        "sProcessing": "test..."
                    },
                columns: [{'data': 'link', width: '30%'},
                          {'data': 'rse_expression', width: '20%'},
                          {'data': 'created_at', width: '20%'},
                          {'data': 'state', width: '12%'},
                          {'data': 'locks_ok_cnt', width: '5%'},
                          {'data': 'locks_replicating_cnt', width: '7%'},
                          {'data': 'locks_stuck_cnt', width: '6%'}]
            });
            $("#delete").html("<a class=\"button tiny\" id=\"delete_button\">delete rule</a>");
            $("#resulttable").on('click', 'tr', function() {
                if ( $(this).hasClass('selected') ) {
                    $(this).removeClass('selected');
                }
                else {
                    dt.$('tr.selected').removeClass('selected');
                    $(this).addClass('selected');
                }
            });

            $('#delete_button').click( function () {
                if ( dt.rows('.selected').data().length == 0) {
                    alert("you have to select a rule first");
                    return;
                }
                var name = dt.row('.selected').data()['name'];
                var rse = dt.row('.selected').data()['rse_expression'];
                var ok = confirm("This will delete the rule for " + name + " at " + rse + ", are you sure?");
                if (ok) {
                    var id = dt.row('.selected').data()['id'];
                    delete_rule(id);
                }

            } );
            $('#resulttable_length').find('select').attr('style', 'width: 4em;');
            $('#resulttable_filter').find('input').attr('style', 'width: 10em; display: inline');
            dt.order([0, 'asc']).draw();
            $('#loader').html('');
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (errorThrown == "Not Found") {
                $('#problem').html("No rules found");
            }
        }
    });
});
