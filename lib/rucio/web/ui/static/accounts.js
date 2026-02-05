/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2017
 */

list_accounts = function() {
    r.list_accounts({
        success: function(data) {
            $('#loader').html("");
            let sanitisedData = Array();
            $.each(data, function(index, item) {
                sanitisedData[index] = {
                    'link': $('<div>').append($('<a></a>', {'href': '/account?account=' + item.account}).text(String(item.account))).html(),
                    'email': $('<div>').text(String(item.email)).html(),
                    'type': $('<div>').text(String(item.type)).html(),
                };
            });
            var dt = $('#resulttable').DataTable({
                data: sanitisedData,
                bAutoWidth: false,
                pageLength: 100,
                columns: [{'data': 'link'},
                          {'data': 'email'},
                          {'data': 'type'}]
            });
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (errorThrown == "Not Found") {
                $('#loader').html("No accounts found");
            }
        }
    })
};

$(document).ready(function(){
    $('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div><br>');
    list_accounts()
});
