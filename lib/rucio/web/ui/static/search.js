/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 */

$(document).ready(function(){
    $('#subbar-details').html('[All DIDs in scope ' + url_param('scope') + ']');
    r.scope_list({'scope': url_param('scope'),
                  success: function(data) {
                      if (data == '') {
                          $('#result').html('Could not find scope ' + url_param('scope'));
                      } else {
                          data.forEach(function(e) {
                              e.did = '<a href="did?scope=' + e.scope + '&name=' + e.name + '">' + e.scope + ':' + e.name + '</a>';
                          });
                          var table = $('<table id="resulttable" class="compact stripe order-column" style="word-wrap: break-word;"><thead><tr><th>Type</th><th>DID</th><th>Parent</th></tr></thead><tfoot><tr><th>Type</th><th>DID</th><th>Parent</th></tr></tfoot></table>');
                          $('#result').html(table)
                          var dt = $('#resulttable').DataTable( {
                              data: data,
                              bAutoWidth: false,
                              columns: [{'data': 'type', 'width': '8em'},
                                        {'data': 'did'},
                                        {'data': 'parent'}]
                          });
                          dt.order([1, 'asc']).draw();
                      }
                  },
                  error: function(jqXHR, textStatus, errorThrown) {
                      $('#result').html('Could not find the scope.');
                  }});
});
