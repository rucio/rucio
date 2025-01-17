/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Martin Barisits, <martin.barisits@cern.ch>, 2014
 */


$(document).ready(function(){
    $("#ruleSubmit").button().click(function( event ) {
        r.create_rule({scope: $("#scope").val(),
                       name: $("#name").val(),
                       rse_expression: $("#rse_expression").val(),
                       copies: $("#copies").val(),
                       grouping: $("#grouping").val(),
                       weight: $("#weight").val(),
                       lifetime: $("#lifetime").val(),
                       source_replica_expression: $("#source_replica_expression").val(),
                       success: function(data) {
                           $('#result').html("Replication rule with id \"" + data + "\" created.");
                       },
                       error: function(jqXHR, textStatus, errorThrown) {
                           $('#result').html("Could not create the replication rule. (Error thrown: \"" + jqXHR['responseText'] + "\")");
                       }});
    });
});
