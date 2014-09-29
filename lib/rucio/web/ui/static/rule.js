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
    $('#subbar-details').html('[' + url_param('scope') + ':' + url_param('name') + ']');

    r.list_replication_rule({'rule_id': url_param('rule_id'),
                        success: function(data) {
                            if (data == '') {
                                $('#result').html('Could not find scope ' + url_param('scope'));
                            } else {
                                for (key in data) {
                                    if (data[key] != undefined) {
                                        $('#t_metadata').append($('<tr><th>' + key + '</th><td>' + data[key] + '</td></tr>'));
                                    }
                                }
                            }
                        },
                        error: function(jqXHR, textStatus, errorThrown) {
                            $('#result').html('Could not find the rule.');
                        }});
});
