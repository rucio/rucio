/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 */

if ('x-rucio-auth-token' in $.cookie()) {
    token = $.cookie('x-rucio-auth-token');
}
if ('rucio-selected-account' in $.cookie()) {
    account = $.cookie('rucio-selected-account');
} else {
    $.cookie('rucio-selected-account', account, { path: '/' });
}
var available_accounts = $.cookie('rucio-available-accounts').split(' ');

var r = new RucioClient(token, account);
r.ping({success: function(data) { $('#rucio_server_version').html(data.version);}});

$(document).ready(function(){
        $("#accountselect").selectmenu({
                change: function(event, data) {
                    account = data.item.value;
                    $.cookie('rucio-selected-account', account, { path: '/' });
                }
            });
        $.each(available_accounts, function( index, value ) {
                $('#accountselect').append($("<option></option>").attr("value", value).text(value));
            });

        $("#accountselect").val(account).selectmenu('refresh');

        $("#logout").button().click(function( event ) {
                $.removeCookie('rucio-selected-account', { path: '/' });
                $.removeCookie('rucio-available-accounts', { path: '/' });
                $.removeCookie('x-rucio-auth-token', { path: '/' });
                $(location).attr('href', 'static/logout.html');
            });
});
