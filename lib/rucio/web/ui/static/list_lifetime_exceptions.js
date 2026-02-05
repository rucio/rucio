/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2018
 */

function format ( d ) {
    let table_elem = $('<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;"></table>');
    table_elem.append($('<tr></tr>').append('<td>Reason:</td>').append($('<td></td>').text(d['$reason'])));
    for (var cnt=0; cnt<d['$datasets'].length;cnt++){
        let row = $('<tr></tr>');
        if(cnt == 0){
            row.append('<td width="200">Dataset list:</td>');
        }
        else{
            row.append('<td width="200"></td>');
        }
        var scope = d['$datasets'][cnt].split(':')[0];
        var name = d['$datasets'][cnt].split(':')[1];
        row.append($('<td></td>').append($('<a></a>', {'href': '/did?scope=' + scope + '&name=' + name}).text(d['$datasets'][cnt])));
    }
    return $('<div>').append(table_elem).html();
}

$(document).ready(function(){
    $('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    r.list_lifetime_exceptions({
         success: function(data) {
            var dict = {};
            $.each(data, function(index, res) {
                if (!(res.id in dict)){
                    dict[res.id] = {'created_at': res.created_at, 'account': res.account, 'nb_datasets': 0, 'expires_at': res.expires_at, 'state': res.state, 'reason': res.comments, 'datasets': []};
                }
                dict[res.id]['nb_datasets'] += 1;
                dict[res.id]['datasets'].push(res.scope+':'+res.name)
                if ((dict['state'] == 'APPROVED' && res.state == 'WAITING') || (dict['state'] == 'WAITING' && res.state == 'APPROVED')){
                    dict['state'] = 'PARTIALLY APPROVED';
                }
            });
            result = [];
            $.each(dict, function(key, value) {
                result.push({
                    'created_at': $('<div>').text(value['created_at']).html(),
                    'expires_at': $('<div>').text(value['expires_at']).html(),
                    'id': $('<div>').text(key).html(),
                    'account': $('<div>').text(value['account']).html(),
                    'nbdatasets': $('<div>').text(value['nb_datasets']).html(),
                    'state': $('<div>').text(value['state']).html(),
                    '$reason': value['reason'], // used in detail view
                    '$datasets': value['datasets'], // used in detail view
                });
            });

            var dt = $('#resulttable').DataTable({
                data: result,
                bAutoWidth: false,
                pageLength: 100,
                columns: [{
                               'className': 'details-control2',
                               'orderable': false,
                               'data': null,
                               'defaultContent': ''
                          },
                          {'data': 'created_at'},
                          {'data': 'expires_at'},
                          {'data': 'id'},
                          {'data': 'account'},
                          {'data': 'nbdatasets'},
                          {'data': 'state'}]
            });
            $('#resulttable tbody').on('click', 'td.details-control2', function () {
                var tr = $(this).closest('tr');
                var row = dt.row( tr );
                if ( row.child.isShown() ) {
                    // This row is already open - close it
                   row.child.hide();
                   tr.removeClass('shown');
                }
                else {
                   // Open this row
                   row.child( format(row.data()) ).show();
                   tr.addClass('shown');
                }
            });
            $('#resulttable_filter').find('input').attr('style', 'width: 10em; display: inline');
            dt.order([1, 'asc']).draw();

            $('#loader').html('');
            $('#last_update').text('Last Update: ' + date + " " + hour + ":" + minutes);
         },
         error: function(jqXHR, textStatus, errorThrown) {
            console.log(textStatus);
            console.log(errorThrown);
            $('#loader').html('');

        }
    });
});
