/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2015-2018
 * - Eric Vaandering, <ewv@fnal.gov>, 2020
 * - Martin Barisits, <martin.barisits@cern.ch>, 2021
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

do_approval = function() {
    $("#rse_continue").html("");
    $("#rse_table").html('<div class="row">You don\'t have quota for this RSE. If you have multiple accounts you can check if any of them has quota for this RSE. Otherwise you can ask for approval. If you check the box below the rule will be created, but I will not start copying files until the rule has been approved.</div></br><div class="row"><div class="large-12 columns"><input id="ask_approval_checkbox" type="checkbox"> I want to ask for approval</input></div></div><div class="row"><div class="large-2 columns"><a class="button postfix disabled" id="rse_continue_button">Continue</a></div></div>');

    $("#ask_approval_checkbox").click(function() {
        if ($(this).is(":checked")) {
            $("#rse_continue_button").removeClass("disabled");
            $('#rse_continue_button').on('click', continue_rse);
        } else {
            $("#rse_continue_button").addClass("disabled");
            $('#rse_continue_button').unbind('click');
        }
    });

    $("#options_continue").unbind("click");
    $("#options_continue").click(function(event) {
        if (!check_options(true)) {
            return;
        }
        create_summary(true)
    });
};

did_details = function(tr, row, scope) {
    r.did_get_metadata({
        'scope': scope,
        'name': row.data()['name'],
        async: false,
        success: function(data){
            html_table = '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">';
            if (data['bytes'] != undefined) {
                data['filesize'] = filesize(data['bytes'], {'base': 10});
                delete data['bytes'];
            }
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
                        if (sorted_keys[i] == 'bytes') {
                            data['size'] == filesize(data['bytes'], {'base': 10});
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
        oLanguage: {
            sSearch: "Filter: "
        },
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
        $.each(dt_dids.rows({filter: 'applied'}).nodes(), function(index, row) {
            $(row).addClass('selected');
        });
    });

    $('#continue_button').on('click', function() {
        if (dt_dids.rows('.selected').data().length == 0) {
            html_message = '<font color="red">please select at least one DID!</font>';
            $("#did_problem").html(html_message);
            return;
        } else {
            $("#did_problem").html("");
        }
        selected_dids = [];
        $.each(dt_dids.rows('.selected').data(), function(index, selected){
            selected_dids.push({'scope': scope, 'name': selected['name']});
        });
        window.history.pushState('#rse', null, null);
        $("#did_panel").removeClass("active");
        $("#rse_panel").addClass("active");
        storage.set('selected_dids', selected_dids);
        show_info_rse();
    });

    return dt_dids;
};

create_multi_did_list = function(table_data) {
    var html = '<div class="row">'+
                   '<div id="multi_did_table" class="large-12 columns">'+
                       '<div>'+
                       '<table id="dt_multi_dids" class="compact stripe order-column" style="word-wrap: break-word;">'+
                           '<thead>'+
                               '<th>Scope</th>'+
                               '<th>Name</th>'+
                               '<th>Type</th>'+
                               '<th></th>'+
                           '</thead>'+
                           '<tfoot>'+
                               '<th>Scope</th>'+
                               '<th>Name</th>'+
                               '<th>Type</th>'+
                               '<th></th>'+
                           '</tfoot>'+
                       '</table>'+
                       '</div>'+
                   '</div>'+
               '</div>'+
               '<div class="row">'+
                   '<div class="large-2 columns">'+
                       '<a class="button postfix" id="continue_multi_button">Continue</a>'+
                   '</div>'+
                   '<div id="multi_did_problem" class="large-3 columns">'+
                   '</div>'+
                   '<div class="large-7 columns">'+
                   '</div>'+
               '</div>';
    $("#did_multi_search").html(html);

    var data = [];
    $.each(table_data, function(index, value) {
        var html_checkbox = '<input type="checkbox" class="inline" name="checkbox_' + value['scope'] + '_' + value['name'] + '">';
        value['selected'] = html_checkbox;
        data.push(value);
    });

    dt_dids = $("#dt_multi_dids").DataTable( {
        data: data,
        bAutoWidth: false,
        columns: [{'data': 'scope',
                   'width': '25%',
                   'className': 'scope'},
                  {'data': 'name',
                   'width': '50%',
                   'className': 'name'},
                  {'data': 'type',
                   'width': '20%',
                   'className': 'type'},
                  {"className": 'details-control',
                   "orderable": false,
                   "data": null,
                   "defaultContent": '',
                   "width": "5%"}
                  ]
    });

    // Add event listener for opening and closing details
    $('#dt_multi_dids tbody').on('click', 'td.details-control', function () {
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

    $('#continue_multi_button').on('click', function() {
        if (dt_dids.rows('.selected').data().length == 0) {
            html_message = '<font color="red">please select at least one DID!</font>';
            $("#did_problem").html(html_message);
        } else {
            $("#did_problem").html("");
        }
        selected_dids = [];
        $.each(data, function(index, selected){
            selected_dids.push({'scope': selected['scope'], 'name': selected['name']});
        });
        window.history.pushState('#rse', null, null);
        $("#did_panel").removeClass("active");
        $("#rse_panel").addClass("active");
        storage.set('selected_dids', selected_dids);
        show_info_rse();
    });

    return dt_dids;
};


create_sample = function() {
    selected_options = storage.get('selected_options');
    nbfiles = selected_options['sample'];
    sample_dids = storage.get('sample_dids');

    new_dids = []
    $.each(sample_dids, function(index, did) {
        options = {'input_scope': did['input_scope'], 'input_name': did['input_name'], 'output_scope': did['scope'], 'output_name': did['name'], 'nbfiles': nbfiles};
        options['success'] = function(data) {
            new_dids.push({'scope': did['scope'], 'name': did['name']});
        };
        options['error'] = function(jqXHR, textStatus, errorThrown) { console.log(jqXHR); };
        options['async'] = false;
        r.create_did_sample(options);
    });
    storage.set('selected_dids', new_dids);
};

continue_rse = function() {
    var expr = $("#rse_input")[0].value;
    selected_rse = expr;
    if (selected_rse.indexOf('SCRATCHDISK') > -1) {
        $("#lifetime").val("15");
    }
    $("#rse_panel").removeClass("active");
    $("#options_panel").addClass("active");
    window.history.pushState('#options', null, null);
    show_info_options();
};

create_rse_table = function(quota){
    $("#options_continue").click(function(event) {
        ask_approval = false;
        if (!quota) {
            ask_approval = true;
        }
        if (!check_options(ask_approval)) {
            return;
        }
        if (quota) {
            create_summary(false);
        } else {
            create_summary(true);
        }
    });

    data = storage.get('rse_data');
    total_selected_size = storage.get('total_selected_size');
    button_enabled = storage.get('rse_button_enabled');

    var html_size = 'Total size of selected DIDs: ' + filesize(total_selected_size, {'base': 10});
    $("#rse_total_did_size").html(html_size);
    var html_continue = '';
    if (!quota) {
        html_continue += '<div class="row"><div class="large-12 columns">You do not have enough quota left on the selected RSE. However, if you check to box below you can still submit the rule and ask for approval.</div></div></br><div class="row"><div class="large-12 columns"><input id="ask_approval_checkbox" type="checkbox"> I want to ask for approval</input></div></div>';
    }
    html_continue += '<div class="row"><div class="large-2 columns"><a class="button postfix" id="rse_continue_button">Continue</a></div></div>';
    var html_table = '<table id="dt_list_rses" class="compact stripe order-column" style="word-wrap: break-word;"><thead><th>RSE</th><th>Remaining Quota</th><th>Total Quota</th></thead><tfoot><th>Name</th><th>Remaining Quota</th><th>Total Quota</th></tfoot></table><br>';
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
    $("#ask_approval_checkbox").click(function() {
        if ($(this).is(":checked")) {
            $("#rse_continue_button").removeClass("disabled");
            $('#rse_continue_button').on('click', continue_rse);
        } else {
            $("#rse_continue_button").addClass("disabled");
            $('#rse_continue_button').unbind('click');
        }
    });


    if (!button_enabled) {
        $("#rse_continue_button").addClass("disabled");
    } else {
        $('#rse_continue_button').on('click', continue_rse);
    }
};

did_check = function() {
    $("#rse_total_did_size").html("");
    $("#rse_continue").html("");

    $("#rse_table").html('<div class="row"><div class="large-12">Checking DIDs</div></div><div class="row"><div class="progress large-12 radius round"><span id="did_check_progress" class="meter" style="width: 0%"></span></div></div>');
    // little bit of a dirty hack, but otherwise Firefox freezes for a few seconds and does not show the progress bar.
    setTimeout(get_did_meta, 100);
};

get_did_meta = function() {
    selected_dids = storage.get('selected_dids');
    total_dids = selected_dids.length;
    checked_dids = 0;
    did_meta = [];
    $.each(selected_dids, function(index, did) {
        r.get_did({
            'scope': did['scope'],
            'name': did['name'],
            'dynamic': true,
            success: function(metadata){
                files = metadata['length'];
                size = metadata['bytes'];
                open = metadata['open']
                did_meta.push({'scope': did['scope'], 'name': did['name'], 'files': files, 'size': size, 'open': open});
                checked_dids += 1;
                percentage = Math.round(checked_dids / total_dids * 100.0);
                $("#did_check_progress").css("width", percentage.toString() + "%");

                if (checked_dids == total_dids) {
                    storage.set('did_meta', did_meta);
                    search_rses();
                }
            }
        });
    });
};

search_rses = function() {
    $('#rse_total_did_size').html('');
    $('#rse_table').html('');
    $('#rse_continue').html('');
    $('#manual_approval').html('');

    did_meta = storage.get('did_meta');

    var total_size = 0;
    $.each(did_meta, function(index, did) {
        total_size += did['size'];
    });
    var expr = $("#rse_input")[0].value;
    storage.set('rse_expr', expr);
    $("#rse_table").html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');

    r.list_rses({
        'expression': expr,
        success: function(rses) {
            var account_limits = {};
            r.get_account_limits({
                account: account,
                async: false,
                success: function(limits) {
                    account_limits = limits
                }, error: function(jqXHR, textStatus, errorThrown) {
                }
            });

            var account_usages = {};
            r.get_account_usage({
                account: account,
                async: false,
                success: function(usage) {
                    $.each(usage, function(index, values) {
                        account_usages[values['rse']] = values['bytes_remaining']
                    });
                }
            });

            rse_data = [];
            button_enabled = false;
            has_quota = 'N';
            $.each(rses, function(index, rse) {
                bytes_remaining = '';
                bytes_limit = 'no quota for this RSE';
                if ((rse['rse'] in account_limits) && (rse['rse'] in account_usages)) {
                    bytes_limit = filesize(account_limits[rse['rse']], {'base': 10});
                    if (account_usages[rse['rse']] >= total_size) {
                        has_quota = 'Y';
                        button_enabled = true;
                        bytes_remaining = filesize(account_usages[rse['rse']], {'base': 10});
                    } else {
                        has_quota = 'R';
                        bytes_remaining = '<font color="red">' + filesize(account_usages[rse['rse']], {'base': 10}) + '</font>';
                    }
                    if (account_limits[rse['rse']] == -1) {
                        has_quota = 'Y';
                        button_enabled = true;
                        bytes_remaining = filesize(account_usages[rse['rse']], {'base': 10});
                        bytes_limit = "Infinite";
                    }
                } else if ((rse['rse'] in account_limits) && !(rse['rse'] in account_usages)) {
                    bytes_limit = filesize(account_limits[rse['rse']], {'base': 10});
                    if (account_limits[rse['rse']] >= total_size) {
                        has_quota = 'Y';
                        button_enabled = true;
                        bytes_remaining = bytes_limit;
                    } else {
                        has_quota = 'R';
                        bytes_remaining = '<font color="red">' + bytes_limit + '</font>';
                    }
                    if (account_limits[rse['rse']] == -1) {
                        has_quota = 'Y';
                        button_enabled = true;
                        bytes_remaining = "Infinite";
                        bytes_limit = "Infinite";
                    }

                }
                rse_data.push({'rse': rse['rse'], 'bytes_limit': bytes_limit, 'bytes_remaining': bytes_remaining});
            });
            storage.set('rse_data', rse_data);
            storage.set('rse_button_enabled', button_enabled);
            storage.set('total_selected_size', total_size);
            storage.set('has_quota', has_quota);
            if (has_quota == 'Y') {
                create_rse_table(true);
            } else if (has_quota == 'R') {
                create_rse_table(false);
            } else {
                do_approval();
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $("#rse_continue").html('');
            error_detail = JSON.parse(jqXHR.responseText);
            if (error_detail['ExceptionClass'] == 'InvalidRSEExpression') {
                if (error_detail['ExceptionMessage'] == 'RSE Expression resulted in an empty set.') {
                    $("#rse_table").html('<font color="red">No RSE found that matches your input.<font>');
                } else {
                    $("#rse_table").html('<font color="red">' + error_detail['ExceptionMessage'] + '</font>');
                }
            } else {
                $("#rse_table").html('<font color="red">' + error_details['ExceptionClass'] + ': ' + error_details['ExceptionMessage'] + '</font>');
            }
        }
    });
};

create_rse_select = function() {
    $("#rse_input").keypress(function(event){
        if(event.keyCode == 13){
            did_check();
            return false;
        }
    });
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
    $('#search_rse_button').on('click', did_check);
};

search_dids = function(event) {
    var pattern = $("#pattern_input")[0].value.trim();
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
    $("#did_form").submit(function() {
        search_dids();
        return false;
    });
    $("#search_did_button").click(search_dids);
};

search_multi_dids = function(event) {
    multi_did_input = $("#multi_did_input").val().split('\n');
    $("#multi_did_search").html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    var type = $('input[name=multi_didtype]:checked', '#multi_did_form').val();
    var table_data = [];
    $.each(multi_did_input, function(index, line) {
        scope_name = extract_scope(line);
        if (!scope_name) {
            return;
        }
        r.get_did({
            'scope': scope_name[0],
            'name': scope_name[1],
            success: function(did) {
                table_data.push({'scope': did['scope'], 'name': did['name'], 'type': did['type']});
                create_multi_did_list(table_data);
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.log(jqXHR);
            }
        });
    });
};

create_multi_did_search = function() {
    $("#search_multi_did_button").click(search_multi_dids);
};

check_options = function(approval) {
    $("#check_text").html("");
    selected_dids = storage.get('selected_dids');
    rse_expr = storage.get('rse_expr');
    if (selected_dids == null || selected_dids.length == 0) {
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
    selected_options['notify'] = $('input[name=notify]:checked').val();
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
    if (approval) {
        if (selected_options['comment'] == '') {
            html_message = '<font color="red">You have to give a reason in the comment field if you want to ask for approval.</font>';
            $("#check_text").html(html_message);
            return;
        }
    }

    selected_options['sample'] = null;
    if ($('#check_sample').is(':checked') ) {
        nbfiles = parseInt($('#nbfiles').val());
        if (isNaN(nbfiles)) {
            html_message = '<font color="red">Please give a valid number of sample files</font>';
            $("#check_text").html(html_message);
            return;
        }
        selected_options['sample'] = nbfiles;
    }

    selected_options['async'] = false;
    if ($('#async_mode').is(':checked') ) {
        selected_options['async'] = true;
    }

    storage.set('selected_options', selected_options);
    $("#options_panel").removeClass("active");
    $("#summary_panel").addClass("active");
    window.history.pushState('#summary', null, null);
    show_info_none();
    return true;
};

create_request_container = function(dids) {
    scope = "";
    r.get_account_info({
        account: account,
        async: false,
        success: function(data) {
            if (data['account_type'] == 'USER') {
                scope = 'user.' + account;
            } else if (data['account_type'] == 'GROUP') {
                scope = 'group.' + account;
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });
    var now = new Date();
    var date = now.getFullYear() + '-';
    if ((now.getMonth() + 1) < 10) {
        date += '0' + (now.getMonth() + 1);
    } else {
        date += (now.getMonth() + 1);
    }
    date += '-';
    if (now.getDate() < 10) {
        date += '0' + now.getDate();
    } else {
        date += now.getDate();
    }
    var hour = now.getHours();
    if (hour < 10) {
        hour = '0' + hour;
    }
    date += '_' + hour;
    var minutes = now.getMinutes();
    if (minutes < 10) {
        minutes = '0' + minutes;
    }
    date += '-' + minutes;
    var seconds = now.getSeconds();
    if (seconds < 10) {
        seconds = '0' + seconds;
    }
    date += '-' + seconds;

    name = scope + ".r2d2_request." + date;

    r.add_did({
        'scope': scope,
        'name': name,
        'type': 'CONTAINER',
        'async': false,
        success: function(data) {
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
            html_check = '<font color="red">There was an error creating the request container.</font>';
            $('#submit_progress').html('');
            $("#error_msg").html(html_check);
        }
    });
    r.attach_dids({
        'scope': scope,
        'name': name,
        'dids': dids,
        'async': false,
        success: function(data) {
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
            html_check = '<font color="red">There was an error adding the DIDs to the request container.</font>';
            $('#submit_progress').html('');
            $("#error_msg").html(html_check);
        }
    });
    r.set_status({
        'scope': scope,
        'name': name,
        'open': false,
        'async': false,
        success: function(data) {
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
            html_check = '<font color="red">There was an error closing the request container.</font>';
            $('#submit_progress').html('');
            $("#error_msg").html(html_check);
        }
    });

    return [{'scope': scope, 'name': name}]
}

create_request_dataset = function(dids) {
    scope = "";
    r.get_account_info({
        account: account,
        async: false,
        success: function(data) {
            if (data['account_type'] == 'USER') {
                scope = 'user.' + account;
            } else if (data['account_type'] == 'GROUP') {
                scope = 'group.' + account;
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });
    var now = new Date();
    var date = now.getFullYear() + '-';
    if ((now.getMonth() + 1) < 10) {
        date += '0' + (now.getMonth() + 1);
    } else {
        date += (now.getMonth() + 1);
    }
    date += '-';
    if (now.getDate() < 10) {
        date += '0' + now.getDate();
    } else {
        date += now.getDate();
    }
    var hour = now.getHours();
    if (hour < 10) {
        hour = '0' + hour;
    }
    date += '_' + hour;
    var minutes = now.getMinutes();
    if (minutes < 10) {
        minutes = '0' + minutes;
    }
    date += '-' + minutes;
    var seconds = now.getSeconds();
    if (seconds < 10) {
        seconds = '0' + seconds;
    }
    date += '-' + seconds;

    name = scope + ".r2d2_request." + date;

    r.add_did({
        'scope': scope,
        'name': name,
        'type': 'DATASET',
        'async': false,
        success: function(data) {
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
            html_check = '<font color="red">There was an error creating the request dataset.</font>';
            $('#submit_progress').html('');
            $("#error_msg").html(html_check);
        }
    });
    r.attach_dids({
        'scope': scope,
        'name': name,
        'dids': dids,
        'async': false,
        success: function(data) {
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
            html_check = '<font color="red">There was an error adding the DIDs to the request dataset.</font>';
            $('#submit_progress').html('');
            $("#error_msg").html(html_check);
        }
    });
    r.set_status({
        'scope': scope,
        'name': name,
        'open': false,
        'async': false,
        success: function(data) {
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
            html_check = '<font color="red">There was an error closing the request dataset.</font>';
            $('#submit_progress').html('');
            $("#error_msg").html(html_check);
        }
    });

    return [{'scope': scope, 'name': name}]
}


create_rules = function(approval) {
    var html_ok = '<div class="row">';
    if (approval) {
        html_ok += '<div class="large-6 columns">Your rule(s) have been created in ASK_APPROVAL state and will be reviewed. You can check here:';
    } else {
        html_ok += '<div class="large-6 columns">Your rule(s) have been created. You can check here:';
    }
    html_ok += '</div>'+
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
    if (selected_options['sample'] != null) {
        create_sample();
    }

    selected_dids = storage.get('selected_dids');

    var request_container = null;
    did_datasets = [];
    did_files = [];
    if ((selected_dids.length > 1) && (approval)) {
        $.each(selected_dids, function(index, did) {
            r.get_did({
                'scope': did['scope'],
                'name': did['name'],
                'dynamic': true,
                success: function(data){
                    if (data['did_type'] == 'FILE'){
                        did_files.push({'scope': did['scope'], 'name': did['name']});
                    } else if (data['did_type'] == 'DATASET'){
                        did_datasets.push({'scope': did['scope'], 'name': did['name']});
                    }
                }
            });
        });
    }

    if (did_datasets.length != 0 && did_files.length != 0){
        var request_dataset = create_request_dataset(did_files);
        did_datasets.push({'scope': request_dataset[0]['scope'], 'name': request_dataset[0]['name']});
        request_container = create_request_container(did_datasets);
    } else if (did_datasets.length != 0 && did_files.length == 0) {
        request_container = create_request_container(did_datasets);
    } else if (did_datasets.length == 0 && did_files.length != 0){
        var request_dataset = create_request_dataset(did_files);
    }

    rse_expr = storage.get('rse_expr');
    if (request_container) {
        options['dids'] = request_container;
    } else if (request_dataset) {
        options['dids'] = request_dataset;
    } else {
        options['dids'] = selected_dids;
    }
    options['rse_expression'] = rse_expr;
    options['copies'] = selected_options['copies'];
    options['grouping'] = selected_options['grouping'];
    options['notify'] = selected_options['notify'];

    if (selected_options['lifetime'] == 0) {
        if (options['rse_expression'].indexOf('SCRATCHDISK') > -1) {
            options['lifetime'] = 15 * 86400;
        }
    } else {
        options['lifetime'] = selected_options['lifetime'] * 86400;
    }
    if (request_container) {
        options['comment'] = selected_options['comment'] + ' \r\nSearch pattern: ' + storage.get('pattern');
    } else {
        options['comment'] = selected_options['comment'];
    }
    options['activity'] = "User Subscriptions";
    options['ask_approval'] = approval;
    if (request_container) {
        options['asynchronous'] = true;
    } else {
        options['asynchronous'] = selected_options['async'];
    }
    options['success'] = function(data) {
        $("#main").html(html_ok);
        list_rules_html = 'Or you can find a list of all your rules <a href="/r2d2?account=' + account + '">here</a>';
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
        error_details = JSON.parse(jqXHR.responseText);
        if (error_details['ExceptionClass'] == 'DuplicateRule') {
            html_check = '<font color="red">The rule that you are trying to create already exists, please go back and choose another DID or RSE.</font>';
        } else if (error_details['ExceptionClass'] == 'RSEWriteBlocked') {
            html_check = '<font color="red">The RSE that you chose is currently not available for writing. Please check <a href="https://atlas-cric.cern.ch/atlas/ddmendpointstatus/list/" target="_blank">here</a> for more information.</font>';
        } else {
            html_check = '<font color="red">' + error_details['ExceptionClass'] + ': ' + error_details['ExceptionMessage'] + '</font>';
        }
        $('#submit_progress').html('');
        $("#error_msg").html(html_check);
        console.log(jqXHR);
    };
    $('#request_submit').hide();
    $('#submit_progress').html('<div class="large-1 columns"><img width="40%" height="40%" src="/media/spinner.gif"></div><div class="large-11 columns">Your rules are being created. Please wait. It may take a some time.</div>');

    setTimeout(function() {
        r.create_rule(options);
    }, 2000);
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
    has_quota = storage.get('has_quota');
    if (rse_data != undefined) {
        if (has_quota == 'N') {
            do_approval();
        } else if (has_quota == 'R') {
            create_rse_table(false);
        } else {
            create_rse_table(true);
        }
    }
    options = storage.get('selected_options');
    if (options != undefined) {
        $("#grouping_" + options['grouping'].toLowerCase()).prop( "checked", true );
        $("#notify_" + options['notify'].toLowerCase()).prop( "checked", true );
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
        show_info_did();
    } else if (name == '#rse') {
        $("#rse_panel").addClass("active");
        show_info_rse();
    } else if (name == '#options') {
        $("#options_panel").addClass("active");
        show_info_options();
    } else if (name == '#summary') {
        $("#summary_panel").addClass("active");
        show_info_none();
    }
}

window.onpopstate = function(event) {
    if (event['state'] != null) {
        change_panel(event['state']);
    }
};

create_summary = function(approval) {
    html_summary = '<div class="row">';

    if (approval) {
        html_summary += '<p id="did_summary_text">This request will <b>ask for approval</b> to create rules for the following DIDs:</p>';
    } else {
        html_summary += '<p id="did_summary_text">This request will create rules for the following DIDs:</p>';
    }
    html_summary += '</div>'+
                   '<div class="row">'+
                       '<div id="did_summary_table" class="large-12 columns">'+
                           '<div>'+
                               '<table id="dt_summary_dids" class="compact stripe order-column" style="word-wrap: break-word;">'+
                                   '<thead>'+
                                       '<th>DID</th>'+
                                       '<th>Copies</th>'+
                                       '<th>Files</th>'+
                                       '<th>Size</th>'+
                                       '<th>Requested Size</th>'+
                                   '</thead>'+
                                   '<tfoot>'+
                                       '<th>Total</th>'+
                                       '<th></th>'+
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
                       '<div id="error_msg"></div>'+
                   '</div>' +
                   '<div class="row">'+
                       '<div id="submit_progress"></div>'+
                   '</div>'+
                   '<div class="row">'+
                      '<div class="button postfix" id="request_submit">Submit request</div>'+
                   '</div>';



    $("#summary_panel").html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    scope = storage.get('scope');
    selected_dids = storage.get('selected_dids');
    selected_options = storage.get('selected_options');
    data = [];
    copies = selected_options['copies'];
    total_copies = 0
    total_files = 0;
    total_size = 0;
    total_requested_size = 0;
    nbfiles = selected_options['sample'];
    open = false;

    new_scope = "";
    if (nbfiles != null ) {
        r.get_account_info({
            account: account,
            async: false,
            success: function(data) {
                if (data['account_type'] == 'USER') {
                    new_scope = 'user.' + account;
                } else if (data['account_type'] == 'GROUP') {
                    new_scope = 'group.' + account;
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.log(jqXHR);
            }
        });
    }

    sample_dids = []
    $.each(selected_dids, function(index, did) {
        if (nbfiles != null ) {
            new_name = new_scope + '.' + did['name'] + '_der' + parseInt((Date.now() / 1000));
            data.push({'did': new_scope + ':' + new_name, 'copies': copies, 'size': '-', 'requested_size': '-', 'files': nbfiles});
            sample_dids.push({'scope': new_scope, 'name': new_name, 'input_scope': did['scope'], 'input_name': did['name']});
        } else {
            r.get_did({
                'scope': did['scope'],
                'name': did['name'],
                'dynamic': true,
                async: false,
                success: function(metadata){
                    total_copies += copies;
                    files = metadata['length'];
                    size = metadata['bytes'];
                    total_files += files;
                    total_size += size;
                    requested_size = size * copies;
                    total_requested_size += requested_size;
                    size = filesize(size, {'base': 10});
                    requested_size = filesize(requested_size, {'base': 10});
                    did = did['scope'] + ':' + did['name'];
                    if (metadata['open']) {
                        open = true;
                        did = "<b>" + did + '</b>';
                    }
                    data.push({'did': did, 'copies': copies, 'files': files, 'size': size, 'requested_size': requested_size});
                }
            });
        }
    });
    storage.set('sample_dids', sample_dids);

    rse_data = storage.get('rse_data');

    $("#summary_panel").html(html_summary);
    dt = $("#dt_summary_dids").DataTable({
        data: data,
        sDom : '<"top">tp',
        paging: false,
        columns: [{'data': 'did', 'width': '50%'},
                  {'data': 'copies', 'width': '10%'},
                  {'data': 'files', 'width': '10%'},
                  {'data': 'size', 'width': '15%'},
                  {'data': 'requested_size', 'width': '15%'}
                 ]
    });
    $(dt.column(1).footer()).html(total_copies);
    $(dt.column(2).footer()).html(total_files);
    $(dt.column(3).footer()).html(filesize(total_size, {'base': 10}));
    $(dt.column(4).footer()).html(filesize(total_requested_size, {'base': 10}));

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

    if (copies == 1 && selected_dids.length == 1 && rse_data.length == 1) {
        if (approval) {
            $("#did_summary_text").html("This request will <b>ask for approval</b> to create a rule for the following DID:");
        } else {
            $("#did_summary_text").html("This request will create a rule for the following DID:");
        }
        $("#rse_summary_text").html("The rule will replicate to the following RSE:");
    } else if (selected_dids.length == 1 && rse_data.length > 1) {
        if (approval) {
            $("#did_summary_text").html("This request will <b>ask for approval</b> to create a rule for the following DID:");
        } else {
            $("#did_summary_text").html("This request will create a rule for the following DID:");
        }
        $("#rse_summary_text").html("The rule will replicate to one of the following RSEs:");
    } else if (copies == 1 && selected_dids.length > 1 && rse_data.length > 1) {
        if (approval) {
            $("#did_summary_text").html("You <b>asked for approval</b> for multiple DIDs. This request will create a new container and will put all of the following DIDs into it. The rule will then be created on the new container.");
        } else {
            $("#did_summary_text").html("This request will create rules for the following DIDs:");
        }
        $("#rse_summary_text").html("The rules will replicate to one of the following RSEs:");
    } else {
        if (approval) {
            $("#did_summary_text").html("You <b>asked for approval</b> for multiple DIDs. This request will create a new container and will put all of the following DIDs into it. The rule will then be created on the new container.");
        } else {
            $("#did_summary_text").html("This request will create rules for the following DIDs:");
        }
        $("#rse_summary_text").html("The rules will replicate to one of the following following RSEs:");
    }

    if (nbfiles != null) {
        if (approval) {
            $('#did_summary_text').html('This will <b>ask for approval</b> to create a rule for the following sample dataset(s) with ' + nbfiles + ' file(s):');
        } else {
            $('#did_summary_text').html('This will create the following sample dataset(s) with ' + nbfiles + ' file(s):');
        }
    }

    if (open) {
        $('#did_summary_text').append('</br>The DIDs in bold are still open. Everything that will be added to them after you created the rule will also be transferred to the selected RSE.');
    }

    lifetime = selected_options['lifetime'];
    if (lifetime == 1) {
        $("#lifetime_summary_text").html("The lifetime will be " + lifetime + " day. If this is ok you can submit the rule request. If not you can go back and change it.");
    } else if (lifetime == 0) {
        $("#lifetime_summary_text").html("The lifetime will be infinite. If this is ok you can submit the rule request. If not you can go back and change it.");
    } else {
        $("#lifetime_summary_text").html("The lifetime will be " + lifetime + " days. If this is ok you can submit the rule request. If not you can go back and change it.");
    }

    $("#request_submit").click(function(event) {
        create_rules(approval);
    });
};

clear_form = function() {
    tour_alert = storage.get('tour_alert');
    gh_issue_alert = storage.get('gh_issue_alert');
    storage.removeAll();
    storage.set('tour_alert', tour_alert);
    storage.set('gh_issue_alert', gh_issue_alert)
    $("#pattern_input").val("");
    $("#rse_input").val("");
    $("#grouping_dataset".toLowerCase()).prop( "checked", true );
    $("#notify_no".toLowerCase()).prop( "checked", true );
    $("#copies").val(1);
    $("#lifetime").val(15);
};

show_info_did = function() {
    $("#info_did").show();
    $("#info_rse").hide();
    $("#info_options").hide();
};

show_info_rse = function() {
    $("#info_rse").show();
    $("#info_did").hide();
    $("#info_options").hide();
};

show_info_none = function() {
    $("#info_rse").hide();
    $("#info_did").hide();
    $("#info_options").hide();
};

show_info_options = function() {
    $("#info_options").show();
    $("#info_rse").hide();
    $("#info_did").hide();
};


$(document).ready(function() {
    show_info_did();
    create_did_search();
    create_multi_did_search();
    create_rse_select();
    $("#clear_data").click(function(event) {
        clear_form();
        location.reload();
    });
    init_storage();
    window.history.pushState('#did', null, null);
    $("#start_tour").click(function(event) {
        $(document).foundation('joyride', 'start', {
            post_step_callback: function(e) {
                if (e == 3) {
                    show_info_rse();
                    window.history.pushState('#rse', null, null);
                    $("#did_panel").removeClass("active");
                    $("#rse_panel").addClass("active");
                }
                if (e == 5) {
                    show_info_options();
                    window.history.pushState('#options', null, null);
                    $("#rse_panel").removeClass("active");
                    $("#options_panel").addClass("active");
                }
            }
        });
    });
    $(document).foundation({
        accordion: {
            callback : function (accordion) {
                if ($(accordion)[0].id == 'rse_panel') {
                    show_info_rse();
                } else if ($(accordion)[0].id == 'options_panel') {
                    show_info_options();
                } else if ($(accordion)[0].id == 'did_panel') {
                    show_info_did();
                }
            }
        }
    });
    $(document).on('close.fndtn.alert', function(event) {
        if (event.target.id == 'tour_alert') {
            storage.set('tour_alert', false);
        }
        if (event.target.id == 'gh_issue_alert') {
            storage.set('gh_issue_alert', false);
        }
    });
    if (storage.get('tour_alert') == false) {
        $("#tour_alert").hide();
    }
    if (storage.get('gh_issue_alert') == false) {
        $("#gh_issue_alert").hide();
    }

    $('#check_sample').click(function() {
        var $this = $(this);
        if ($this.is(':checked')) {
            $('#nbfiles').prop('disabled', false);
        } else {
            $('#nbfiles').prop('disabled', true);
        }
    });
});
