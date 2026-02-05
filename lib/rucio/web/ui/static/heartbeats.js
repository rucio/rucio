/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2015
 */

$(document).ready(function(){
    r.list_heartbeats({
        success: function(data) {
            var dt = $('#dt_data').DataTable( {
                bAutoWidth: false,
                columns: [{'data': 'Executable'},
                          {'data': 'Hostname'},
                          {'data': 'PID'},
                          {'data': 'Thread'},
                          {'data': 'Updated'},
                          {'data': 'Created'}]
            });
            $('#dt_data_length').find('select').attr('style', 'width: 4em;');
            $('#dt_data_filter').find('input').attr('style', 'width: 10em; display: inline');
            data.forEach(function(d) {
                dt.row.add({'Executable': $('<div>').text(d[0]).html(),
                            'Hostname': $('<div>').text(d[1]).html(),
                            'PID': $('<div>').text(d[2]).html(),
                            'Thread': $('<div>').text(d[3]).html(),
                            'Updated': $('<div>').text(d[4]).html(),
                            'Created': $('<div>').text(d[5]).html()});
            });
            dt.draw();
        }
    });
});
