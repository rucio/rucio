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

var html_result = '<table id="resulttable" class="compact stripe order-column" style="word-wrap: break-word;"><thead><tr><th>Account</th><th>Quota</th><th>Used</th><th>Available</th><th>Files</th></tr></thead><tfoot><tr><th>Account</th><th>Quota</th><th>Used</th><th>Available</th><th>Files</th></tr></tfoot></table>';

load_data = function(rse) {
    $('#results').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    if (rse == undefined) {
        var rse = $("#rse_input")[0].value;
    }
    r.get_rse_account_usage({
        rse: rse,
        success: function(data) {
            $("#results").html(html_result);
            table_data = [];
            $.each(data, function(index, value) {
                if (value['used_bytes'] < 0) {
                    value['difference'] = value['quota_bytes'];
                } else {
                    value['difference'] = value['quota_bytes'] - value['used_bytes'];
                }
                value['used_bytes'] = filesize(value['used_bytes']);
                value['quota_bytes'] = filesize(value['quota_bytes']);
                value['difference'] = filesize(value['difference']);
                table_data.push(value);
            });
            var dt = $("#resulttable").DataTable( {
                data: table_data,
                bAutoWidth: false,
                paging: false,
                destroy: true,
                columns: [{'data': 'account'},
                          {'data': 'quota_bytes'},
                          {'data': 'used_bytes'},
                          {'data': 'difference'},
                          {'data': 'used_files'}],
            });
            dt.order([0, 'asc']).draw();
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $("#results").html('<font color="red">' + jqXHR['responseText'] + '</font>');
        }
    });
};

$(document).ready(function(){
    rse = url_param('rse');
    if (rse != "") {
        $("#rse_input").val(rse);
        load_data(rse);
    }

    r.list_rses({
        success: function(data) {
            rses = [];
            $.each(data, function(index, value) {
                rses.push(value['rse']);
            });
            $("#rse_input").autocomplete({
                source: rses
            });
        }
    });

    $("#rse_input").keydown(function(e) {
        if (e.keyCode == 13) {
            load_data();
        }
    });

    $("#select_rse").on('click', function() {
        load_data();
    });
});
