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

var dt_ids = null;
var dt_attr = null;


function load_info() {
    r.get_account_info({
        'account': url_param('account'),
        success: function(data) {
            $("#loading").html("");
            if (data == '') {
                $('#result').html('Could not find account ' + url_param('account'));
            } else {
                var sorted_keys = Object.keys(data).sort();

                for(var i=0; i<sorted_keys.length; ++i) {
                    if (data[sorted_keys[i]]) {
                        $('#t_metadata').append($('<tr><th>' + sorted_keys[i] + '</th><td>' + data[sorted_keys[i]] + '</td></tr>'));
                    } else {
                        $('#t_metadata').append($('<tr><th>' + sorted_keys[i] + '</th><td>-</td></tr>'));
                    }
                }
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $('#loading').html('<font color="red">Could not find the account.</font>');
        }
    });
};

function load_attributes() {
    if (dt_attr != null ) {
        dt_attr.destroy();
    } else {
        $("#attr_table").on('click', 'tr', function() {
            $(this).toggleClass('selected');
        });
    }

    r.list_account_attributes({
        'account': url_param('account'),
        success: function(data) {
            $("#loading_attr").html("");
            if (data != '') {
                dt_attr = $('#attr_table').DataTable( {
                    data: data,
                    bAutoWidth: false,
                    "oLanguage": {
                        "sProcessing": "test..."
                    },
                    columns: [{'data': 'key', width: '50%'},
                              {'data': 'value', width: '50%'}]
                });
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $("#loading_attr").html("");
        }
    });
};

function add_attr() {
    var key = $("#key_input")[0].value.trim();
    var value = $("#value_input")[0].value.trim();

    r.add_account_attribute({
        'account': url_param('account'),
        'key': key,
        'value': value,
        success: function(data) {
            load_attributes();
            $("#attr_notify").html('<font color="green">Successfully added new attribute</font>')
        },
        error: function(jqXHR, textStatus, errorThrown) {
            error_detail = jqXHR.responseText;
            console.log(error_detail);
            $("#attr_notify").html('<font color="red">Could not add attribute: ' + String(error_detail) + '</font>')
        }
    });
};

function del_attr() {
    info_text = "This will deleted the following keys:\n"
    delete_keys = []
    $.each(dt_attr.rows('.selected').data(), function(index, selected){
        delete_keys.push(selected['key']);
        info_text += "\n" + selected['key'];
    });

    info_text += "\n\nAre you sure?";

    ok = confirm(info_text);

    if (!ok) {
        return;
    }
    $.each(delete_keys, function(index, key) {
        r.delete_account_attribute({
            'account': url_param('account'),
            'key': key,
            success: function(data) {
                load_attributes();
            },
            error: function(jqXHR, textStatus, errorThrown) {
            }
        });
    });
};

function load_identities() {
    if (dt_ids != null ) {
        dt_ids.destroy();
    } else {
        $("#identities_table").on('click', 'tr', function() {
            $(this).toggleClass('selected');
        });
    }
    r.list_identities({
        'account': url_param('account'),
        success: function(data) {
            $("#loading_id").html("");
            if (data == '') {
                $('#result').html('Could not find account ' + url_param('account'));
            } else {
                dt_ids = $('#identities_table').DataTable( {
                    data: data,
                    bAutoWidth: false,
                    "oLanguage": {
                        "sProcessing": "test..."
                    },
                    columns: [{'data': 'identity', width: '50%'},
                              {'data': 'type', width: '50%'}]
                });
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $("#loading_id").html("");
        }
    });
};

function add_identity() {
    var identity = $("#identity_input")[0].value.trim();
    var type = $("#type_input")[0].value.trim();
    var email = $("#email_input")[0].value.trim();

    r.add_identity({
        'account': url_param('account'),
        'identity': identity,
        'authtype': type,
        'email': email,
        success: function(data) {
            load_identities();
            $("#identity_notify").html('<font color="green">Successfully added new identity</font>')
        },
        error: function(jqXHR, textStatus, errorThrown) {
            error_detail = jqXHR.responseText;
            console.log(error_detail);
            $("#identity_notify").html('<font color="red">Could not add identity: ' + String(error_detail) + '</font>')
        }
    });
    console.log(identity, type, email);
};

function del_identity() {
    info_text = "This will deleted the following identities:\n"
    delete_ids = []
    $.each(dt_ids.rows('.selected').data(), function(index, selected){
        delete_ids.push({'identity': selected['identity'], 'type': selected['type']});
        info_text += "\n" + selected['identity'] + ' / ' + selected['type'];
    });

    info_text += "\n\nAre you sure?";

    ok = confirm(info_text);

    if (!ok) {
        return;
    }

    $.each(delete_ids, function(index, selected){
        r.del_identity({
            'account': url_param('account'),
            'authtype': selected['type'],
            'identity': selected['identity'],
            'default': false,
            success: function(data) {
                console.log('done');
            },
            error: function(jqXHR, textStatus, errorThrown) {
            }
        });
    });
}

$(document).ready(function(){
    $('#subbar-details').html('[' + url_param('account') + ']');

    $("#add_attr").click(add_attr);
    $("#del_attr").click(del_attr);

    $("#add_identity").click(add_identity);
    $("#del_identity").click(del_identity);

    load_info();
    load_attributes();
    load_identities();
});
