/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2015
 */

var selected_dids = [];
var selected_rse = "";
var selected_options = {};

extract_scope = function(name) {
    if (name.indexOf(':') > -1) {
        return name.split(':');
    }
    var items = name.split('.')
    if (items.length <= 1) {
        return false;
    }
    var scope = items[0];
    if (name.indexOf('user') === 0 || name.indexOf('group') === 0) {
        scope = items[0] + '.' + items[1];
    }
    return [scope, name];
};

did_details = function(tr, row, scope) {
    r.did_get_metadata({
        'scope': scope,
        'name': row.data()['name'],
        async: false,
        success: function(data){
            html_table = '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">';
            var sorted_keys = Object.keys(data).sort();
            for(var i=0; i<sorted_keys.length; ++i) {
                if (data[sorted_keys[i]] != undefined) {
                    html_table += '<tr>'
                    if (typeof data[sorted_keys[i]] === 'boolean'){
                        if (data[sorted_keys[i]]) {
                            html_table += '<td>' + sorted_keys[i] + '</td><td style="color: green;">' + data[sorted_keys[i]] + '</td>';
                        } else {
                            html_table += '<td>' + sorted_keys[i] + '</td><td style="color: red;">' + data[sorted_keys[i]] + '</td>';
                        }
                    } else {
                        if (sorted_keys[i] == 'scope') {
                            data[sorted_keys[i]] = "<a href=/search?scope=" + data['scope'] + "&name=undefined>" + data['scope'] + "</a>";
                        }
                        html_table += '<td>' + sorted_keys[i] + '</td><td>' + data[sorted_keys[i]] + '</td>';
                    }
                    html_table += '</tr>';
                }
            }
            html_table += '</table>';
            row.child(html_table  ).show();
            tr.addClass('shown');
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });
};

create_did_list = function(scope, dids) {
    var html = '<div class="row">'+
                   '<div id="did_table" class="large-12 columns">'+
                       '<div>'+
                       '<table id="dt_list_dids" class="compact stripe order-column" style="word-wrap: break-word;">'+
                       '<thead>'+
                           '<th>Name</th>'+
                           '<th></th>'+
                       '</thead>'+
                       '<tfoot>'+
                           '<th>Name</th>'+
                           '<th></th>'+
                       '</tfoot>'+
                       '</table>'+
                       '</div>'+
                   '</div>'+
               '</div>'+
               '<div class="row">'+
                   '<div class="large-2 columns">'+
                       '<a class="button postfix" id="continue_button">Continue</a>'+
                   '</div>'+
                   '<div class="large-2 columns">'+
                       '<a class="button postfix" id="selectall_button">Select All</a>'+
                   '</div>'+
                   '<div id="did_problem" class="large-3 columns">'+
                   '</div>'+
                   '<div class="large-7 columns">'+
                   '</div>'+
               '</div>';
    $("#did_search").html(html);

    var data = [];
    $.each(dids, function(index, value) {
        var html_checkbox = '<input type="checkbox" class="inline" name="checkbox_' + value + '">';
        data.push({'name': value, 'selected': html_checkbox});
    });

    dt_dids = $("#dt_list_dids").DataTable( {
        data: data,
        bAutoWidth: false,
        columns: [{'data': 'name',
                   'width': '94%',
                   'className': 'name'},
                  {"className": 'details-control',
                   "orderable": false,
                   "data": null,
                   "defaultContent": '',
                   "width": "5%"}
                  ]
    });

    // Add event listener for opening and closing details
    $('#dt_list_dids tbody').on('click', 'td.details-control', function () {
        var tr = $(this).closest('tr');
        var row = dt_dids.row( tr );
        if ( row.child.isShown() ) {
            row.child.hide();
            tr.removeClass('shown');
        }
        else {
            did_details(tr, row, scope);
        }
    });

    $('#dt_list_dids').on( 'click', 'td.name', function () {
        $(this).parent().toggleClass('selected');
    });

    $('#selectall_button').on('click', function() {
        $.each(dt_dids.rows().nodes(), function(index, row) {
            $(row).addClass('selected');
        });
    });

    $('#continue_button').on('click', function() {
        if (dt_dids.rows('.selected').data().length == 0) {
            html_message = '<font color="red">please select at least one DID!</font>';
            $("#did_problem").html(html_message);
        } else {
            $("#did_problem").html("");
        }
        selected_names = [];
        $.each(dt_dids.rows('.selected').data(), function(index, selected){
            selected_dids.push({'scope': scope, 'name': selected['name']});
            selected_names.push(selected['name']);
        });
        window.history.pushState('#rse', null, null);
        $("#did_panel").removeClass("active");
        $("#rse_panel").addClass("active");
        storage.set('selected_names', selected_names);
    });

    return dt_dids;
};

create_rse_table = function(){
    data = storage.get('rse_data');
    button_enabled = storage.get('rse_button_enabled');

    var html_continue = '<div class="large-2 columns"><a class="button postfix" id="rse_continue_button">Continue</a></div>';
    var html_table = '<table id="dt_list_rses" class="compact stripe order-column" style="word-wrap: break-word;"><thead><th>RSE</th><th>Used Quota</th><th>Total Quota</th></thead><tfoot><th>Name</th><th>Used Quota</th><th>Total Quota</th></tfoot></table><br>';
    $("#rse_table").html(html_table);
    dt = $("#dt_list_rses").DataTable({
        data: data,
        sDom : '<"top">tp',
        paging: false,
        columns: [{'data': 'rse'},
                 {'data': 'bytes_remaining'},
                 {'data': 'bytes_limit'}]
    });
    $("#rse_continue").html(html_continue);
    if (!button_enabled) {
        $("#rse_continue_button").addClass("disabled");
    } else {
        $('#rse_continue_button').on('click', function() {
            var expr = $("#rse_input")[0].value;
            selected_rse = expr;
            $("#rse_panel").removeClass("active");
            $("#options_panel").addClass("active");
            window.history.pushState('#options', null, null);
        });
    }
};

create_rse_select = function() {
    r.list_rses({
        success: function(data) {
            rses = [];
            $.each(data, function(index, value) {
                rses.push(value['rse']);
            });
            $("#rse_input").autocomplete({
                source: rses
            });
        }
    });
    $('#search_rse_button').on('click', function() {
        var expr = $("#rse_input")[0].value;
        storage.set('rse_expr', expr);
        $("#rse_table").html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
        r.list_rses({
            'expression': expr,
            success: function(rses) {
                rse_data = [];
                button_enabled = false;
                $.each(rses, function(index, rse) {
                    r.get_account_usage({
                        account: account,
                        rse: rse['rse'],
                        async: false,
                        success: function(usage) {
                            if (usage.length == 0) {
                                bytes_remaining = '';
                                bytes_limit = 'no quota for this RSE';
                            } else {
                                bytes_remaining = usage[0]['bytes_remaining'] / 1000 /1000/1000;
                                bytes_limit = usage[0]['bytes_limit'] / 1000 /1000/1000;
                                bytes_remaining = bytes_remaining.toFixed(2) + ' GB';
                                bytes_limit = bytes_limit.toFixed(2) + ' GB';
                                button_enabled = true;
                            }
                            rse_data.push({'rse': rse['rse'], 'bytes_limit': bytes_limit, 'bytes_remaining': bytes_remaining});
                        }
                    });
                });
                storage.set('rse_data', rse_data);
                storage.set('rse_button_enabled', button_enabled);
                create_rse_table();
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.log(jqXHR);
            }
        });
    });
};

search_dids = function(event) {
    var pattern = $("#pattern_input")[0].value;
    storage.set('pattern', pattern);
    var items = pattern.split(":");
    $("#did_message").html("");
    if (items.length != 2 && items[0] == "") {
        $("<div/>").text("please provide a search pattern in the form: <scope>:<name|pattern> or <name|pattern>").appendTo("#did_message");
        return;
    }
    var type = $('input[name=didtype]:checked', '#did_form').val();
    scope_name = extract_scope(pattern);
    if (!scope_name) {
        $("<div/>").text("cannot determine scope. please provide the did with scope").appendTo("#did_message");
        return;
    }

    $("#did_search").html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    r.list_dids({
        'scope': scope_name[0],
        'name': scope_name[1],
        type: type,
        success: function(dids) {
            storage.set('scope', scope_name[0]);
            storage.set('dids', dids);
            create_did_list(scope_name[0], dids);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });
};

create_did_search = function() {
    $("#search_did_button").click(search_dids);
};

check_options = function() {
    $("#check_text").html("");
    selected_names = storage.get('selected_names');
    rse_expr = storage.get('rse_expr');
    if (selected_names == null) {
        html_message = '<font color="red">Please select at least one DID first</font>';
        $("#check_text").html(html_message);
        return false;
    }
    if (rse_expr == null) {
        html_message = '<font color="red">Please select an RSE first</font>';
        $("#check_text").html(html_message);
        return false;
    }

    $("#check_text").html("");
    selected_options['grouping'] = $('input[name=grouping]:checked').val();
    selected_options['lifetime'] = $("#lifetime").val();
    if (selected_options['lifetime'].length == 0) {
        selected_options['lifetime'] = 0
    }
    selected_options['lifetime'] = parseInt(selected_options['lifetime']);
    if (isNaN(selected_options['lifetime'])) {
        html_message = '<font color="red">Please give a valid lifetime</font>';
        $("#check_text").html(html_message);
        return;
    }
    selected_options['copies'] = $("#copies").val();
    if (selected_options['copies'].length == 0) {
        selected_options['copies'] = 1
    }
    selected_options['copies'] = parseInt(selected_options['copies']);
    if (isNaN(selected_options['copies'])) {
        html_message = '<font color="red">Please give a valid number of copies</font>';
        $("#check_text").html(html_message);
        return;
    }

    if (selected_rse.indexOf('SCRATCHDISK') > -1) {
        if (selected_options['lifetime'] != 0) {
            if (selected_options['lifetime'] > 15) {
                html_message = '<font color="red">You cannot select a lifetime of more than 15 days for SCRATCHDISK</font>';
                $("#check_text").html(html_message);
                return;
            }
        } else {
            selected_options['lifetime'] = 15;
        }
    }
    selected_options['comment'] = $("#comment").val();
    storage.set('selected_options', selected_options);
    $("#options_panel").removeClass("active");
    $("#summary_panel").addClass("active");
    window.history.pushState('#summary', null, null);
    return true;
};

create_rules = function() {
    var html_ok = '<div class="row">'+
                      '<div class="large-6 columns">Your rule(s) have been created. You can check here:'+
                      '</div>'+
                  '</div>'+
                  '<div class="row">'+
                      '<div id="rules_table" class="large-8 columns">'+
                          '<div>'+
                              '<table id="dt_rules" class="compact stripe order-column" style="word-wrap: break-word;">'+
                                  '<thead>'+
                                      '<th>ID</th>'+
                                      '<th>DID</th>'+
                                  '</thead>'+
                                  '<tfoot>'+
                                      '<th>ID</th>'+
                                      '<th>DID</th>'+
                                  '</tfoot>'+
                              '</table>'+
                          '</div>'+
                      '</div>'+
                  '</div>'+
                  '<div class="row">'+
                      '<div class="large-8 columns">'+
                          '<div id="list_rules">'+
                          '</div>'+
                      '</div>'+
                  '</div>';

    var options = {};
    selected_options = storage.get('selected_options');
    selected_names = storage.get('selected_names');
    scope = storage.get('scope');
    rse_expr = storage.get('rse_expr');
    selected_dids = [];
    $.each(selected_names, function(index, name) {
        selected_dids.push({'scope': scope, 'name': name});
    });
    options['dids'] = selected_dids;
    options['rse_expression'] = rse_expr;
    options['copies'] = selected_options['copies'];
    options['grouping'] = selected_options['grouping'];
    if (selected_options['lifetime'] == 0) {
        options['lifetime'] = 15 * 86400;
    } else {
        options['lifetime'] = selected_options['lifetime'] * 86400;
    }
    options['comment'] = selected_options['comment'];
    options['success'] = function(data) {
        $("#main").html(html_ok);
        list_rules_html = 'Or you can find a list of all your rules <a href="/list_rules?account=' + account + '">here</a>';
        $("#list_rules").html(list_rules_html);
        table_data = [];
        $.each(data, function(index, rule_id) {
            link = '<a href=/rule?rule_id=' + rule_id + '>' + rule_id + '</a>';
            table_data.push({'id': link, 'did': options['dids'][index]['scope'] + ":" + options['dids'][index]['name']});
        });
        dt = $("#dt_rules").DataTable({
            data: table_data,
            sDom : '<"top">tip',
            paging: false,
            columns: [{'data': 'id'},
                      {'data': 'did'}
                     ]
        });
        clear_form();
    };
    options['error'] = function(jqXHR, textStatus, errorThrown) {
        if (jqXHR['responseText'] == 'DuplicateRule: ()') {
            html_check = '<font color="red">The rule you are trying to create already exists, please got back and choose another DID or RSE</font>';
        } else {
            html_check = '<font color="red">' + jqXHR['responseText'] + '</font>';
        }
        $("#error_msg").html(html_check);
        console.log(jqXHR);
    };
    r.create_rule(options);
};

init_storage = function() {
    ns=$.initNamespaceStorage('rucio_webui_request_rule');
    storage=ns.localStorage;

    pattern = storage.get('pattern');
    if (pattern != undefined) {
        $("#pattern_input").val(pattern);
    }
    scope = storage.get('scope');
    dids = storage.get('dids');
    if (scope != undefined && dids != undefined) {
        dt_dids = create_did_list(scope, dids);
        selected_names = storage.get('selected_names');

        if (selected_names != undefined) {
            $.each(dt_dids.rows().nodes(), function(index, row) {
                var tr = $(row).closest('tr');
                var row = dt_dids.row( tr );
                if (selected_names.indexOf(row.data().name) > -1) {
                    tr.addClass('selected');
                }
            });
        }
    }
    rse_expr = storage.get('rse_expr');
    if (rse_expr != undefined) {
        $("#rse_input").val(rse_expr);
    }
    rse_data = storage.get('rse_data');
    if (rse_data != undefined) {
        create_rse_table();
    }
    options = storage.get('selected_options');
    if (options != undefined) {
        $("#grouping_" + options['grouping'].toLowerCase()).prop( "checked", true );
        $("#copies").val(options['copies']);
        $("#lifetime").val(options['lifetime']);
        $("#comment").text(options['comment']);
    }
};

change_panel = function(name) {
    $("#did_panel").removeClass("active");
    $("#rse_panel").removeClass("active");
    $("#options_panel").removeClass("active");
    $("#summary_panel").removeClass("active");
    if (name == '#did') {
        $("#did_panel").addClass("active");
    } else if (name == '#rse') {
        $("#rse_panel").addClass("active");
    } else if (name == '#options') {
        $("#options_panel").addClass("active");
    } else if (name == '#summary') {
        $("#summary_panel").addClass("active");
    }
}

window.onpopstate = function(event) {
    if (event['state'] != null) {
        change_panel(event['state']);
    }
};

create_summary = function() {
    html_summary = '<div class="row">'+
                       '<p id="did_summary_text">This request will create rules for the following DIDs:</p>'+
                   '</div>'+
                   '<div class="row">'+
                       '<div id="did_table" class="large-12 columns">'+
                           '<div>'+
                               '<table id="dt_summary_dids" class="compact stripe order-column" style="word-wrap: break-word;">'+
                                   '<thead>'+
                                       '<th>DID</th>'+
                                       '<th>Copies</th>'+
                                       '<th>Size</th>'+
                                       '<th>Requested Size</th>'+
                                   '</thead>'+
                                   '<tfoot>'+
                                       '<th>Total</th>'+
                                       '<th></th>'+
                                       '<th></th>'+
                                       '<th></th>'+
                                   '</tfoot>'+
                               '</table>'+
                           '</div>'+
                       '</div>'+
                   '</div>'+
                   '<div class="row">'+
                       '<br>'+
                       '<p id="rse_summary_text"></p>'+
                   '</div>'+
                   '<div class="row">'+
                       '<div id="rse_table" class="large-12 columns">'+
                           '<div>'+
                               '<table id="dt_summary_rses" class="compact stripe order-column" style="word-wrap: break-word;">'+
                                   '<thead>'+
                                       '<th>RSE</th>'+
                                       '<th>Remaining Quota</th>'+
                                       '<th>Total Quota</th>'+
                                   '</thead>'+
                                   '<tfoot>'+
                                       '<th>RSE</th>'+
                                       '<th>Remaining Quota</th>'+
                                       '<th>Total Quota</th>'+
                                   '</tfoot>'+
                               '</table>'+
                           '</div>'+
                       '</div>'+
                   '</div>'+
                   '<div class="row">'+
                       '<br>'+
                       '<p id="lifetime_summary_text"></p>'+
                   '</div>'+
                   '<div class="row">'+
                       '<div class="button postfix" id="request_submit">Submit request</div>'+
                   '</div>'+
                   '<div class="row">'+
                       '<div id="error_msg"></div>'+
                   '</div>';


    $("#summary_panel").html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    scope = storage.get('scope');
    names = storage.get('selected_names');
    selected_options = storage.get('selected_options');
    data = [];
    copies = selected_options['copies'];
    total_copies = 0
    total_size = 0;
    total_requested_size = 0;
    $.each(names, function(index, name) {
        r.did_get_metadata({
            'scope': scope,
            'name': name,
            async: false,
            success: function(metadata){
                total_copies += copies;
                size = metadata['bytes'] / 1000/1000/1000;
                total_size += size;
                requested_size = size * copies;
                total_requested_size += requested_size;
                size = size.toFixed(2) + ' GB';
                requested_size = requested_size.toFixed(2) + ' GB';
                data.push({'did': scope + ':' + name, 'copies': copies, 'size': size, 'requested_size': requested_size});
            }
        });
    });

    rse_data = storage.get('rse_data');

    $("#summary_panel").html(html_summary);
    dt = $("#dt_summary_dids").DataTable({
        data: data,
        sDom : '<"top">tp',
        paging: false,
        columns: [{'data': 'did', 'width': '50%'},
                  {'data': 'copies', 'width': '10%'},
                  {'data': 'size', 'width': '20%'},
                  {'data': 'requested_size', 'width': '20%'}
                 ]
    });
    $(dt.column(1).footer()).html(total_copies);
    $(dt.column(2).footer()).html(total_size.toFixed(2) + ' GB');
    $(dt.column(3).footer()).html(total_requested_size.toFixed(2) + ' GB');

    dt = $("#dt_summary_rses").DataTable({
        data: rse_data,
        sDom : '<"top">tp',
        paging: false,
        columns: [{'data': 'rse', 'width': '60%'},
                  {'data': 'bytes_remaining', 'width': '20%'},
                  {'data': 'bytes_limit', 'width': '20%'},
                 ]
    });

    rse_data = storage.get('rse_data');

    if (copies == 1 && names.length == 1 && rse_data.length == 1) {
        $("#did_summary_text").html("This request will create a rule for the following DID:");
        $("#rse_summary_text").html("The rule will replicate to the following RSE:");
    } else if (names.length == 1 && rse_data.length > 1) {
        $("#did_summary_text").html("This request will create a rule for the following DID:");
        $("#rse_summary_text").html("The rule will replicate to one of the following RSEs:");
    } else if (copies == 1 && names.length > 1 && rse_data.length > 1) {
        $("#did_summary_text").html("This request will create rules for the following DIDs:");
        $("#rse_summary_text").html("The rules will replicate to one of the following RSEs:");
    } else {
        $("#did_summary_text").html("This request will create rules for the following DIDs:");
        $("#rse_summary_text").html("The rules will replicate to one of the following following RSEs:");
    }

    lifetime = selected_options['lifetime'];
    if (lifetime == 1) {
        $("#lifetime_summary_text").html("The lifetime will be " + lifetime + " day. If this is ok you can submit the rule request. If not you can go back and change it.");
    } else {
        $("#lifetime_summary_text").html("The lifetime will be " + lifetime + " days. If this is ok you can submit the rule request. If not you can go back and change it.");
    }

    $("#request_submit").click(function(event) {
        create_rules();
    });
};

clear_form = function() {
    storage.removeAll();
    $("#pattern_input").val("");
    $("#rse_input").val("");
    $("#grouping_dataset".toLowerCase()).prop( "checked", true );
    $("#copies").val(1);
    $("#lifetime").val(15);
};

$(document).ready(function() {
    create_did_search();
    create_rse_select();
    $("#options_continue").click(function(event) {
        if (!check_options()) {
            return;
        }
        create_summary();
    });
    $("#clear_data").click(function(event) {
        clear_form();
        location.reload();
    });
    init_storage();
    window.history.pushState('#did', null, null);
});
