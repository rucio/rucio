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



$(document).ready(function(){
        console.log(url_param('account'));
        r.list_replication_rules({
                account: url_param('account'),
                    name: url_param('name'),
                    state: url_param('state'),
                success: function(data) {
                    $.each(data, function(index, value) {
                            value.name = '<a href=../rule?rule_id=' + value.id + '>' + value.name + '</a>';
                            console.log(value);
                        });
                    var table = $('<table id="resulttable" class="compact stripe order-column" style="word-wrap: break-word;"><thead><tr><th>Name</th><th>Scope</th><th>RSE Expression</th></tr></thead><tfoot><tr><th>Name</th><th>Scope</th><th>RSE Expression</th></tr></tfoot></table>');

                    $('#results').html(table);

                    var dt = $('#resulttable').DataTable( {
                            data: data,
                            bAutoWidth: false,
                            columns: [{'data': 'name', 'width': '30em'},
                                        {'data': 'scope'},
                                        {'data': 'rse_expression'}]
                          });
                    dt.order([0, 'asc']).draw();
                          
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    if (errorThrown == "Not Found") {
                        $('#problem').html("No rules found");
                    }
                }
            });
    });


