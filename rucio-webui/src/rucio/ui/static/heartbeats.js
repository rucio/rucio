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
                dt.row.add({'Executable': d[0],
                            'Hostname': d[1],
                            'PID': d[2],
                            'Thread': d[3],
                            'Updated': d[4],
                            'Created': d[5]}); });
            dt.draw();
        }
    });
});
