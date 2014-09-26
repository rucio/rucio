/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
 */

$(document).ready(function(){
    r.did_get_metadata({'scope': url_param('scope'),
                        'name': url_param('name'),
                        success: function(data) {
                            $('#result').html(data);
                        },
                        error: function(jqXHR, textStatus, errorThrown) {
                            $('#result').html("Could not find the DID.");
                        }});
});
