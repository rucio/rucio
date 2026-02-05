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

    r.get_bad_replicas({state: url_param('state'), rse: url_param('rse'), success: function(data) {
         $('#downloader').empty().append($('<a></a>', {'href': 'data:application/octet-stream;base64,' + btoa(JSON.stringify(data)), 'download': 'dump.json'}).text("download as JSON"));

        let sanitisedData = Array();
        $.each(data, function(index, value) {
            sanitisedData[index] = {
                'scope': $('<div>').text(String(value.scope)).html(),
                'name': $('<div>').text(String(value.name)).html(),
                'state': $('<div>').text(String(value.state)).html(),
                'rse': $('<div>').text(String(value.rse)).html(),
                'created_at': $('<div>').text(String(value.created_at)).html(),
                'updated_at': $('<div>').text(String(value.updated_at)).html(),
            };
        });
         dt = $('#badreplicastates').DataTable( {
             data: sanitisedData,
             columns: [{'data': 'scope'},
                       {'data': 'name'},
                       {'data': 'state'},
                       {'data': 'rse'},
                       {'data': 'created_at'},
                       {'data': 'updated_at'}]
         });
       }
    });
 });
