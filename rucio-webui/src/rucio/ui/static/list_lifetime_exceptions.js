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
    str = '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">';
    str +=  '<tr><td>Reason:</td><td>'+d.reason+'</td></tr>'
    for (var cnt=0; cnt<d.datasets.length;cnt++){
        str += '<tr>';
        if(cnt == 0){
            str += '<td width="200">Dataset list:</td>';
        }
        else{
            str += '<td width="200"></td>';
        }
        var scope = d.datasets[cnt].split(':')[0];
        var name = d.datasets[cnt].split(':')[1];
        str += '<td><a href="/did?scope=' + scope + '&name=' + name + '">' + d.datasets[cnt] + '</a></td>';
        str += '</tr>';
    }
    str += '</table>';
    return str
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
                result.push({'created_at': value['created_at'], 'expires_at': value['expires_at'], 'id': key, 'account': value['account'], 'nbdatasets': value['nb_datasets'], 'state': value['state'], 'reason': value['reason'], 'datasets': value['datasets']});
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
            $('#last_update').html('Last Update: ' + date + " " + hour + ":" + minutes);
         },
         error: function(jqXHR, textStatus, errorThrown) {
            console.log(textStatus);
            console.log(errorThrown);
            $('#loader').html('');

        }
    });
});
