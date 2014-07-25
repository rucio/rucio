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

/* --- base --- */
function rucio() {};
rucio.url = 'https://tbeerman-uidev.cern.ch:443';

/* --- rucio methods --- */

/* get the server version */
rucio.ping = function(target) {
    jQuery.ajax({url: rucio.url + '/ping',
                 crossDomain: true,
                 success: function(data) { rucio.ping.s(data, target); }});};
rucio.ping.s = function(data, target) { $(target).html(data.version); };


/* list all scopes */
rucio.scopes = function(token, account, target) {
    jQuery.ajax({url: rucio.url + '/scopes/',
                 crossDomain: true,
                 headers: {'X-Rucio-Auth-Token': token,
                           'X-Rucio-Account': account },
                 success: function(data) { rucio.scopes.s(data, target); }});};
rucio.scopes.s = function(data, target) { console.log(data); $(target).html(data); };
