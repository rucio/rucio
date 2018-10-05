/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018
 */

create_info_table = function(data, tableIdentifier, counter) {
    var sorted_keys = Object.keys(data).sort();
    for (var i = 0; i < sorted_keys.length; ++i) {
        // If attribute is a nested object and not null, create a sub table
        if(typeof(data[sorted_keys[i]]) == 'object' && data[sorted_keys[i]]) {
            var newTableIdentifier = 'subtable_' + sorted_keys[i] + counter + i;
            $(tableIdentifier).append($('<tr><th width="200">' + sorted_keys[i] + '</th><td><table id="' + newTableIdentifier + '"></table></td></tr>'));
            counter++;
            create_info_table(data[sorted_keys[i]], '#' + newTableIdentifier, counter)
        } else if (data[sorted_keys[i]] == null) {
            $(tableIdentifier).append($('<tr><th>' + sorted_keys[i] + '</th><td>-</td></tr>'));
        } else {
            $(tableIdentifier).append($('<tr><th width=200>' + sorted_keys[i] + '</th><td>' + data[sorted_keys[i]] + '</td></tr>'));
        } 
    }
}

create_attributes_table = function(data) {
    var keys = Object.keys(data[0]).sort();
    $.each(keys,function(index, item) {
        $('#t_rse_attributes').append($('<tr><th>' + item + '</th><td>' + data[0][item] + '</td><td>\
        <a class="button deleteAttribute postfix" style="margin: 0" data-key="' + item + '">Delete</a></td></tr>'));
    })
}

create_protocol_table = function(data) {
    $.each(data,function(index, item) {
        $('#t_rse_protocols').append($('<tr><th>' + item['scheme'] + '</th><td>' + item['hostname'] + '</td><td>' + item['port'] + '<td>\
        <a class="button deleteProtocol postfix" style="margin: 0" data-port="' + item['port'] + '" data-hostname="' + item['hostname'] + '" data-scheme="' + item['scheme'] + '">Delete</a></td></tr>'));
    })
}

get_rse_attributes = function(rse) {
    r.list_rse_attributes({
        'rse': rse,
        success: function (data) {
            $('#loadingAttributes').html('');
            if (data == '') {
                $('#errorLoadingAttributes').html('Could not find RSE' + rse);
            } else {
                create_attributes_table(data)
            }
        },
        error: function (jqXHR, textStatus, errorThrown) {
            if (errorThrown == 'Not Found') {
                $('#loadingAttributes').html('');
                $('#errorLoadingAttributes').html('No matching RSE found');
            }
        }
    })
}

get_rse_info = function (rse) {
    r.get_rse({
        'rse': rse,
        success: function (data) {
            $('#loadingInfo').html('');
            $('#loadingProtocols').html('');
            if (data == '') {
                $('#errorLoadingInfo').html('Could not find RSE ' + rse);
            } else {
                create_info_table(data, '#t_metadata', 0)
                create_protocol_table(data['protocols'])
            }
        },
        error: function (jqXHR, textStatus, errorThrown) {
            if (errorThrown == 'Not Found') {
                $('#loadingInfo').html('');
                $('#loadingProtocols').html('');
                $('#errorLoadingInfo').html('No matching RSE found');
            }
        }
    })
};

delete_rse = function (rse) {
    $('#loaderDeleteRSE').show();

    r.delete_rse({
        'rse': rse,
        success: function (data) {
            $('#resultDeleteRSE').html('RSE was successfully deleted');
            $('#loaderDeleteRSE').hide();
            window.location.href = window.location.origin = '/rses';
        },
        error: function (jqXHR, textStatus, errorThrown) {
            $('#resultDeleteRSE').html('RSE could not be deleted');
            $('#loaderDeleteRSE').hide();
        }
    })
}

add_attribute = function (rse) {
    $('#loaderAddAttribute').show();

    var key = $('#newAttributeKey').val();
    var value = $('#newAttributeValue').val();
    var type = $('#newAttributeType').val();

    if(type == 'boolean') value = (value === 'true');
    else if(type == 'integer') value = parseInt(value);
    else if(type == 'float') value = parseFloat(value);

    r.add_rse_attribute({
        'rse': rse,
        'key': key,
        'value': value,
        success: function (data) {
            $('#resultAddAttribute').html('Attribute was successfully added');
            $('#loaderAddAttribute').hide();
            window.location.reload();
        },
        error: function (jqXHR, textStatus, errorThrown) {
            $('#resultAddAttribute').html('Attribute could not be added');
            $('#loaderAddAttribute').hide();
        }
    })
}

delete_protocol = function(rse, selector) {
    $('#loaderDeleteProtocol').show();

    var port = $(selector).attr('data-port');
    var hostname = $(selector).attr('data-hostname');
    var scheme = $(selector).attr('data-scheme');

    r.delete_rse_protocol({
        'rse': rse,
        'port': port,
        'hostname': hostname,
        'scheme': scheme,
        success: function (data) {
            $('#resultDeleteProtocol').html('Protocol was successfully deleted');
            $('#loaderDeleteProtocol').hide();
            window.location.reload();
        },
        error: function (jqXHR, textStatus, errorThrown) {
            $('#resultDeleteProtocol').html('Protocol could not be deleted');
            $('#loaderDeleteProtocol').hide();
        }
    })
}

delete_attribute = function (rse, selector) {
    $('#loaderDeleteAttribute').show();
    var key = $(selector).attr('data-key');

    r.delete_rse_attribute({
        'rse': rse,
        'key': key,
        success: function (data) {
            $('#resultDeleteAttribute').html('Attribute was successfully deleted');
            $('#loaderDeleteAttribute').hide();
            window.location.reload();
        },
        error: function (jqXHR, textStatus, errorThrown) {
            $('#resultDeleteAttribute').html('Attribute could not be deleted');
            $('#loaderDeleteAttribute').hide();
        }
    })
}

$(document).ready(function () {
    $('#loaderDeleteProtocol').hide();
    $('#loaderDeleteAttribute').hide();
    $('#loaderAddAttribute').hide();
    $('#loaderDeleteRSE').hide();
    var rse = url_param('rse');
    get_rse_info(rse);
    get_rse_attributes(rse);
    $('#deleteRSE').on('click', function () {
        delete_rse(rse);
    });
    $('#addAttribute').on('click', function () {
        add_attribute(rse);
    });
    $(document).on('click', '.deleteAttribute', function () {
        delete_attribute(rse, this);
    });
    $(document).on('click', '.deleteProtocol', function () {
        delete_protocol(rse, this);
    });
    $('#addProtocol').on('click', function () {
        window.location = window.origin + '/rse/protocol/add?rse=' + rse;
    });
}) 
