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
}

continue_rse_select = function() {
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

    $('#check_quota_button').on('click', function() {
        selected_rse = $("#rse_input")[0].value;
        var sum_bytes = 0;
        $.each(selected_dids, function(index, did) {
            r.did_get_metadata({
                scope: did['scope'],
                name: did['name'],
                async: false,
                success: function(data) {
                    sum_bytes += data.bytes;
                    console.log(data);
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    console.log(jqXHR);
                }
            });
        });

        r.get_account_usage({
            account: account,
            rse: selected_rse,
            success: function(data) {
                if (data.length == 0) {
                    $('#quota_details').html('<font color="red">You don\'t have any quota for the selected RSE.</font>');
                } else {
                    data = data[0];
                    console.log(data, sum_bytes)
                    if (data['bytes_remaining'] < sum_bytes) {
                        message = '<font color="red">You don\'t have enough quota on the selected RSE. Total request size: ' + sum_bytes + 'B, remaining quota: ' + data['bytes_remaining'] + 'B (total quota: ' + data['bytes_limit'] + 'B).</font>';
                        $('#quota_details').html(message);
                    } else {
                        $('#quota_details').html('<font color="green">You have enough quota on the selected RSE. Total request size: ' + sum_bytes + 'B, remaining quota: ' + data['bytes_remaining'] + 'B (total quota: ' + data['bytes_limit'] + 'B).</font>');
                    }
                }
                console.log(data);
            },

            error: function(jqXHR, textStatus, errorThrown) {
                console.log(jqXHR);
            }
        });

    });

    $('#continue_rse_button').on('click', function() {
        selected_rse = $("#rse_input")[0].value;
        $("#rse_panel").removeClass("active");
        $("#options_panel").addClass("active");
    });
}

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
                        /*if (sorted_keys[i] == 'bytes') {
                            var gb = data[sorted_keys[i]] / 1000 / 1000 / 1000;
                            console.log(gb);
                            data[sorted_keys[i]] = gb;
                        }*/

                    }
                    html_table += '</tr>';
                }
            }
            html_table += '</table>';
            console.log(html_table);
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

    dt = $("#dt_list_dids").DataTable( {
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
        var row = dt.row( tr );
        console.log(row.data());
        console.log(tr);
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
        $.each(dt.rows().nodes(), function(index, row) {
            $(row).addClass('selected');
        });
    });

    $('#continue_button').on('click', function() {
        if (dt.rows('.selected').data().length == 0) {
            html_message = '<font color="red">please select at least one DID!</font>';
            $("#did_problem").html(html_message);
        } else {
            $("#did_problem").html("");
        }
        $.each(dt.rows('.selected').data(), function(index, selected){
            selected_dids.push({'scope': scope, 'name': selected['name']});
            $("#did_panel").removeClass("active");
            $("#rse_panel").addClass("active");
            console.log(selected['name']);
        });
    });
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
        var html_continue = '<div class="large-2 columns"><a class="button postfix" id="continue_button">Continue</a></div>';
        console.log('test');
        var expr = $("#rse_input")[0].value;
        r.list_rses({
            'expression': expr,
            success: function(data) {
                var html_table = '<table id="dt_list_rses" class="compact stripe order-column" style="word-wrap: break-word;"><thead><th>Name</th></thead><tfoot><th>Name</th></tfoot></table>';
                $("#rse_table").html(html_table);
                dt = $("#dt_list_rses").DataTable({
                    data: data,
                    columns: [{'data': 'rse'}]
                });
                $("#rse_continue").html(html_continue);
                $('#rse_continue').on('click', function() {
                    selected_rse = expr;
                    $("#rse_panel").removeClass("active");
                    $("#options_panel").addClass("active");
                });
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.log(jqXHR);
            }
        });
    });
};

create_did_search = function() {
    $("#search_did_button").click(function(event) {
        var pattern = $("#pattern_input")[0].value;
        var items = pattern.split(":");
        console.log(account, items.length, items[0]);
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

        r.list_dids({
            'scope': scope_name[0],
            'name': scope_name[1],
            type: type,
            success: function(dids) {
                create_did_list(scope_name[0], dids);
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.log(jqXHR);
            }
        });
    });
};

check_rules = function() {
    $("#check_text").html("");
    /*if (selected_dids.length == 0) {
        html_message = '<font color="red">Please select at least one DID first</font>';
        $("#check_text").html(html_message);
        return;
    }
    if (selected_rse == "") {
        html_message = '<font color="red">Please select an RSE first</font>';
        $("#check_text").html(html_message);
        return;
    }*/

    $("#check_text").html("");
    selected_options['grouping'] = $('input[name=grouping]:checked').val();
    selected_options['lifetime'] = $("#lifetime").val();
        console.log(selected_options['lifetime'].length);
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
        console.log(selected_options['copies'].length);
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
        console.log(selected_options['lifetime']);
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

    console.log(selected_options);
    var sum_bytes = 0;
    $.each(selected_dids, function(index, did) {
        r.did_get_metadata({
            scope: did['scope'],
            name: did['name'],
            async: false,
            success: function(data) {
                sum_bytes += data.bytes;
                console.log(data);
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.log(jqXHR);
            }
        });
    });

    /*r.get_account_usage({
        account: account,
        rse: selected_rse,
        success: function(data) {
            console.log(data);
            var html_check = ""
            if (data.length == 0) {
                console.log("no quota");
                html_check = '<font color="red">No quota defined on ' + selected_rse + '</font>';
            } else {
                if (sum_bytes > data[0]['bytes_remaining']) {
                    console.log("not enough quota");
                    html_check = '<font color="red">Not enough quota on ' + selected_rse + '</font>';
                } else {
                    html_check = 'Please wait while your rule is created';
                    create_rule();
                }
            }
            $("#check_text").html(html_check);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });*/
    create_rule();
};

create_rule = function() {
    var html_ok = '<div class="row">'+
                      '<div class="large-6 columns">Your rule(s) have been created. You can check here:'+
                      '</div>'+
                  '</div>'+
                  '<div class="row">'+
                      '<div class="large-6 columns">'+
                         '<ul id="new_rules"></ul>'+
                      '</div>'+
                  '</div>'+
                  '<div class="row">'+
                      '<div class="large-6 columns">'+
                          '<div id="list_rules">'+
                          '</div>'+
                      '</div>'+
                  '</div>';

    var options = {};
    options['dids'] = selected_dids;
    options['rse_expression'] = selected_rse;
    options['copies'] = selected_options['copies'];
    //options['copies'] = 1;
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
        $.each(data, function(index, rule_id) {
            link = '<li><a href=/rule?rule_id=' + rule_id + '>' + rule_id + '</a></li>';
            $("#new_rules").append(link);
        });
        console.log(data);
    };
    options['error'] = function(jqXHR, textStatus, errorThrown) {
        html_check = '<font color="red">' + jqXHR['responseText'] + '</font>';
        $("#check_text").html(html_check);
        console.log(jqXHR);
    };
    r.create_rule(options);
};

$(document).ready(function() {
    create_did_search();
    //continue_rse_select();
    create_rse_select();
    $("#options_submit").click(function(event) {
        check_rules();
    });
});
