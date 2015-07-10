/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2015
 */


$(document).ready(function(){

    r.get_bad_replicas({state: 'SUSPICIOUS', rse: url_param('rse'), list_pfns: 'True', success: function(data) {
         console.log(data)
         var download = '<a href="data:application/octet-stream;base64,' + btoa(JSON.stringify(data)) + '" download="dump.json">download as JSON</a>';
         $('#downloader').html(download);
         dt = $('#suspiciousreplicas').DataTable( {
             data: data,
             columns: [{'data': 'scope'},
                       {'data': 'name'},
                       {'data': 'rse'},
                       {'data': 'pfn'},
                       {'data': 'created_at'},
                       {'data': 'updated_at'}]

         });
       }
    });
 });
