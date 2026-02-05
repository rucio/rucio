/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2015
 */


extract_scope = function(name) {
    if (name.indexOf(':') > -1) {
        return name.split(':');
    }
    var items = name.split('.')

    if (items[0] == 'user' || items[0] == 'group') {
        if (items.length <= 2) {
            return false;
        }
    } else if (items.length <= 1) {
        return false;
    }

    var scope = items[0];
    if (name.indexOf('user') === 0 || name.indexOf('group') === 0) {
        scope = items[0] + '.' + items[1];
    }
    return [scope, name];
};


did_details = function(tr, row, scope) {
    r.did_get_metadata({
        'scope': scope,
        'name': row.data()['$name'],
        async: false,
        success: function(data){
            html_table = $('<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">');
            if (data['bytes'] != undefined) {
                data['filesize'] = filesize(data['bytes'], {'base': 10});
                delete data['bytes'];
            }
            var sorted_keys = Object.keys(data).sort();
            for(var i=0; i<sorted_keys.length; ++i) {
                if (data[sorted_keys[i]] != undefined) {
                    let row = $('<tr></tr>');
                    row.append($('<td></td>').text(sorted_keys[i]))
                    let data_col = $('<td></td>');
                    row.append(data_col);
                    html_table.append(row);
                    if (typeof data[sorted_keys[i]] === 'boolean'){
                        data_col.text(data[sorted_keys[i]]);
                        if (data[sorted_keys[i]]) {
                            data_col.attr('style', 'color: green;');
                        } else {
                            data_col.attr('style', 'color: red;');
                        }
                    } else {
                        if (sorted_keys[i] == 'scope') {
                            data_col.append($('<a></a>', {'href': '/search?scope=' + data['scope'] + '&name=undefined'}).text(data['scope']));
                        } else {
                            data_col.text(data[sorted_keys[i]]);
                        }
                    }
                }
            }
            row.child($('<div>').append(html_table).html()).show();
            tr.addClass('shown');
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });
};


search_dids = function(scope, name, type) {
    var html_table = '<table id="resulttable" class="compact stripe order-column" style="word-wrap: break-word;">      <thead><tr><th>DID</th><th></th></tr></thead>      <tfoot><tr><th>DID</th><th></th></tr></tfoot>    </table>';
    r.list_dids({
        'scope': scope,
        'name': name,
        'type': type,
        success: function(dids) {
            if (dids.length == 0) {
                $('#results').html('Found nothing');
                return;
            }
            var data = [];
            $.each(dids, function(index, name) {
                data.push({
                    'link': $('<div>').append($('<a></a>', {'id': name, 'href': '/did?scope=' + scope + '&name=' + name}).text(scope + ':' + name)).html(),
                    '$name': name, // used in API call
                    'selected': $('<div>').append($('<input>', {'type': 'checkbox', 'class': 'inline', 'name': 'checkbox_' + name})).html(),
                });
            });
            $("#results").html(html_table);
            dt_dids = $("#resulttable").DataTable( {
                data: data,
                bAutoWidth: false,
                pageLength: 100,
                columns: [{'data': 'link',
                           'width': '97%',
                           'className': 'name'},
                          {"className": 'details-control',
                           "orderable": false,
                           "data": null,
                           "defaultContent": '',
                           "width": "3%"}
                         ]
            });
            $('#resulttable tbody').on('click', 'td.details-control', function () {
                var tr = $(this).closest('tr');
                var row = dt_dids.row( tr );
                if ( row.child.isShown() ) {
                    row.child.hide();
                    tr.removeClass('shown');
                }
                else {
                    did_details(tr, row, scope);
                }
            });
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });
};


resolve_pattern_and_search = function(pattern, type) {
    $("#results").html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');

    scope_name = extract_scope(pattern);

    if (!scope_name) {
        r.list_scopes({
            success: function(scopes) {
                if (scopes.indexOf(pattern) != -1) {
                    search_dids(pattern, '', type) ;
                } else {
                    $('#results').html('Your input doesn\'t match any scope.');
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.log(error);
            }
        });
    } else {
        search_dids(scope_name[0], scope_name[1], type) ;
    }
};


click_search = function() {
    var pattern = $('#pattern_input').val().trim();
    var type = $('input[name=didtype]:checked', '#did_form').val();
    resolve_pattern_and_search(pattern, type);
};


$(document).ready(function(){
    var pattern = url_param('pattern');
    if (pattern != "") {
        $('#pattern_input').val(pattern)
        resolve_pattern_and_search(pattern, 'collection');
    }

    $('#search_did_button').click(click_search);

    $("#did_form").submit(function(event) {
        event.preventDefault();
        click_search();
    });
});
