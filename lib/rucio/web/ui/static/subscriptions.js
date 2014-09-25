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
    r.list_subscriptions({
        account: account,
        success: function(data) {
            $.each(data, function(index, value) {
                $('#subscriptions').append('<li>' + value.name + '</li>');
            })},
        error: function(jqXHR, textStatus, errorThrown) {
            if (errorThrown == "Not Found") {
                $('#problem').html("No subscriptions found");
            }
        }
    });

});
