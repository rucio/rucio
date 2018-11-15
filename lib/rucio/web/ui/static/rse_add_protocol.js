/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018
 */

show_number_error = function (selector) {
    $(selector).after('<span class="error">Please only use numbers.</span>')
}

show_required_error = function (selector) {
    $(selector).after('<span class="error">This field is required.</span>')
}

check_only_numbers = function (input) {
    var onlyNumbers = RegExp('^[0-9]+$');
    return onlyNumbers.test(input);
}

add_protocol = function () {
    $('.error').hide();

    var lan_delete = $('#lan_delete').val();
    var lan_read = $('#lan_read').val();
    var lan_write = $('#lan_write').val();
    var wan_delete = $('#wan_delete').val();
    var wan_read = $('#wan_read').val();
    var wan_write = $('#wan_write').val();
    var wan_third_party_copy = $('#wan_third_party_copy').val();
    var web_service_path = $('#web_service_path').val();
    var hostname = $('#hostname').val();
    var port = $('#port').val();
    var scheme = $('#scheme').val();
    var implementation = $('#implementation').val();
    var prefix = $('#prefix').val();

    if (!hostname) show_required_error('#hostname');
    if (!scheme) show_required_error('#scheme');
    if (!port) show_required_error('#port');
    if (!implementation) show_required_error('#implementation');
    if (!prefix) show_required_error('#prefix');

    if (!lan_delete) show_required_error('#lan_delete');
    else if (!check_only_numbers(lan_delete)) show_number_error('#lan_delete');

    if (!lan_read) show_required_error('#lan_read');
    else if (!check_only_numbers(lan_read)) show_number_error('#lan_read');

    if (!lan_write) show_required_error('#lan_write');
    else if (!check_only_numbers(lan_write)) show_number_error('#lan_write');

    if (!wan_delete) show_required_error('#wan_delete');
    else if (!check_only_numbers(wan_delete)) show_number_error('#wan_delete');

    if (!wan_read) show_required_error('#wan_read');
    else if (!check_only_numbers(wan_read)) show_number_error('#wan_read');

    if (!wan_third_party_copy) show_required_error('#wan_third_party_copy');
    else if (!check_only_numbers(wan_third_party_copy)) show_number_error('#wan_third_party_copy');

    if (!wan_write) show_required_error('#wan_write');
    else if (!check_only_numbers(wan_write)) show_number_error('#wan_write');

    var input_is_valid = prefix && implementation && scheme && port && hostname && check_only_numbers(lan_delete) && check_only_numbers(lan_read) && check_only_numbers(lan_write) &&
        check_only_numbers(wan_delete) && check_only_numbers(wan_read) && check_only_numbers(wan_third_party_copy) && check_only_numbers(wan_write);

    if (scheme == 'srm') {
        if (!web_service_path) show_required_error('#web_service_path');
        input_is_valid = input_is_valid && web_service_path;
    }

    if (input_is_valid) {
        $('#loader').show();

        if (scheme == "srm") {
            r.add_rse_protocol({
                'rse': url_param('rse'),
                'scheme': scheme,
                'hostname': hostname,
                'port': parseInt(port),
                'implementation': implementation,
                'prefix': prefix,
                'domains': {
                    'lan': {
                        'read': parseInt(lan_read),
                        'write': parseInt(lan_write),
                        'delete': parseInt(lan_delete)
                    },
                    'wan': {
                        'read': parseInt(wan_read),
                        'write': parseInt(wan_write),
                        'delete': parseInt(wan_delete),
                        'third_party_copy': parseInt(wan_third_party_copy)
                    }
                },
                'extended_attributes': {
                    'web_service_path': web_service_path
                },
                success: handle_success,
                error: handle_error
            })
        } else {
            r.add_rse_protocol({
                'rse': url_param('rse'),
                'scheme': scheme,
                'hostname': hostname,
                'port': parseInt(port),
                'implementation': implementation,
                'prefix': prefix,
                'domains': {
                    'lan': {
                        'read': parseInt(lan_read),
                        'write': parseInt(lan_write),
                        'delete': parseInt(lan_delete)
                    },
                    'wan': {
                        'read': parseInt(wan_read),
                        'write': parseInt(wan_write),
                        'delete': parseInt(wan_delete),
                        'third_party_copy': parseInt(wan_third_party_copy)
                    }
                },
                success: handle_success,
                error: handle_error
            })
        }
    }
};

handle_error = function (jqXHR, textStatus, errorThrown) {
    if (errorThrown == 'Internal Server Error') {
        $('#result').text('Protocol could not be added. There was an Internal Server Error.');
    } else if (errorThrown == "Not Found") {
        $('#result').text('RSE not found.');
    } else if (errorThrown == "Bad Request") {
        $('#result').text('Protocol could not be added. There was problem with decoding your input.');
    } else if (errorThrown == "Conflict") {
        $('#result').text('Protocol could not be added. There was a RSE protocol priority error.');
    }
    $('#result').after(jqXHR['responseJSON']['ExceptionMessage']);
    $('#loader').hide();
}

handle_success = function (data) {
    $('#result').text('Protocol was successfully added.');
    $('#loader').hide();
    window.location.href = window.location.origin = "/rse?rse=" + url_param('rse');
}

$(document).ready(function () {
    $('#loader').hide();
    $('#extended_attributes').hide();
    $('#addProtocol').on('click', function () {
        add_protocol();
    });
    $('#scheme').on('input', function (data) {
        if ($('#scheme').val() == 'srm') {
            $('#extended_attributes').show();
        } else {
            $('#extended_attributes').hide();
        }
    })
});
