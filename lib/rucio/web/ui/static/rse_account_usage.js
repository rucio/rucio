/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2015-2016
 * - Ralph Vigne, <ralph.vigne@cern.ch>, 2015
 */

var html_result = '<h4>Individual Quotas</h4></br><table id="resulttable" class="compact stripe order-column" style="word-wrap: break-word;"><thead><th>Account</th><th>Quota</th><th>Used</th><th>Available</th><th>Files</th></tr></thead><tfoot><tr><th>Account</th><th>Quota</th><th>Used</th><th>Available</th><th>Files</th></tr></tfoot></table>';

var html_options= '<h4>General Settings</h4></br><div class="large-1 columns">      <span data-tooltip aria-haspopup="true" class="has-tip top" data-disable-hover="false" tabindex="2" title="If a rule is smaller than this threshold it will be auto-approved."><label>Auto Approve Limit<input type="text" id="auto_approve_bytes_input" placeholder="500GB, 0.5TB, etc."></input></label></span>    </div>    <div class="large-2 columns">      <span data-tooltip aria-haspopup="true" class="has-tip top" data-disable-hover="false" tabindex="2" title="List of accounts that can approve rules and will be notified about new rules that ask for approval."><label>Approver Accounts        <select id="approver_select" data-placeholder="Add accounts..." style="width:100%;height=50px;" multiple class="chosen-select"></select>      </label></span>    </div>    <div class="large-1 columns">     <span data-tooltip aria-haspopup="true" class="has-tip top" data-disable-hover="false" tabindex="2" title="Default quota for new users."> <label>Default Quota <input type="text" id="default_limit_bytes_input" placeholder="500GB, 0.5TB, etc."></input></label></span>    </div>    <div class="large-1 columns">  <div class="row"> <div class="large-12 large-centered">     <span data-tooltip aria-haspopup="true" class="has-tip" data-disable-hover="false" tabindex="2" title="If enabled, then the manual approval will be disabled for this RSE."><label>Block Manual Approval        <div class="switch">          <input id="approval_mode" type="checkbox">  <label for="approval_mode">Enable Approval</label> </span>  </div> </div>     </div>      </label>    </div>     <div class="columns large-2">   <label><text style="visibility:hidden">.</text><a class="button postfix" id="save_attr">Save</a>  </label> </div>      <div class="large-3 columns">    </div></br>';

var selected_rse = '';
var rule_approvers_changed = false;
var auto_approve_bytes_changed = false;
var default_limit_bytes_changed = false;
var approval_mode_changed = false;

delete_attr = function(key) {
    r.delete_rse_attribute({
        'rse': selected_rse,
        'key': key,
        'async': false,
        success: function(data) {},
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });
}

set_attr = function(key, value) {
    r.add_rse_attribute({
        'rse': selected_rse,
        'key': key,
        'value': value,
        'async': false,
        success: function(data) {},
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    });
}


change_attrs = function() {
    $('#rse_options_message').html('<div class="large-1 large-centered columns"><img width="40%" height="40%" src="/media/spinner.gif"></div>');
    var rule_approvers = [];
    var auto_approve_bytes = '';
    var default_limit_bytes = '';
    var block_manual_approval = false;

    if ($('#approval_mode').is(':checked') ) {
        block_manual_approval = true;
    } else {
        block_manual_approval = false;
    }

    $('#approver_select option:selected').each(function(i, selected){
        rule_approvers.push($(selected).text());
    });

    rule_approvers = rule_approvers.join(',');
    auto_approve_bytes = $("#auto_approve_bytes_input").val();
    default_limit_bytes = $("#default_limit_bytes_input").val();

    parsed_auto_approve_bytes = '';
    parsed_default_limit_bytes = '';

    try {
        if (auto_approve_bytes != '') {
            parsed_auto_approve_bytes = parse_quota_input(auto_approve_bytes);
        }
    } catch(err) {
        $('#rse_options_message').html('<font color="red">Invalid Input</font>');
    }

    try {
        if (default_limit_bytes != '') {
            parsed_default_limit_bytes = parse_quota_input(default_limit_bytes);
        }
    } catch(err) {
        $('#rse_options_message').html('<font color="red">Invalid Input</font>');
    }

    if (auto_approve_bytes_changed) {
        if (parsed_auto_approve_bytes == '') {
            delete_attr('auto_approve_bytes');
        } else {
            set_attr('auto_approve_bytes', parsed_auto_approve_bytes)
        }
        auto_approve_bytes_changed = false;
    }

    if (rule_approvers_changed) {
        if (rule_approvers == '') {
            delete_attr('rule_approvers');
        } else {
            set_attr('rule_approvers', rule_approvers)
        }
        rule_approvers_changed = false;
    }

    if (default_limit_bytes_changed) {
        if (parsed_default_limit_bytes == '') {
            delete_attr('default_limit_bytes');
        } else {
            set_attr('default_limit_bytes', parsed_default_limit_bytes)
        }
        default_limit_bytes_changed = false;
    }

    if (approval_mode_changed) {
        if (block_manual_approval) {
            set_attr('block_manual_approval', block_manual_approval);
        } else {
            delete_attr('block_manual_approval');
        }
        approval_mode_changed = false;
    }
    $('#rse_options_message').html('<div class="columns large-12"><font color="green">Your changes have been saved.</font></div>');
    $("#save_attr").addClass("disabled");
}

load_rse_attr = function(rse) {
    $('#rse_options_message').html("");
    selected_rse = rse;
    var rule_approvers = [];
    var auto_approve_bytes = '';
    var default_limit_bytes = '';

    r.list_rse_attributes({
        'rse': rse,
        success: function(data) {
            tmp_approver = data[0]['rule_approvers'];
            if (tmp_approver) {
                rule_approvers = tmp_approver.split(',');
            }
            auto_approve_bytes = data[0]['auto_approve_bytes'];
            default_limit_bytes = data[0]['default_limit_bytes'];
            block_manual_approval = data[0]['block_manual_approval'];
            if (block_manual_approval == undefined) {
                block_manual_approval = false;
            }

            if (tmp_approver) {
                rule_approvers_set = true;
            }
            if (auto_approve_bytes) {
                auto_approve_bytes_set = true;
                auto_approve_bytes = filesize(auto_approve_bytes, {'base': 10});
            }
            if (default_limit_bytes) {
                default_limit_bytes_set = true;
                default_limit_bytes = filesize(default_limit_bytes, {'base': 10});
            }

            if (block_manual_approval) {
                block_manual_approval_set = true;
            }

        }
    });

    r.list_accounts({
        'async': true,
        success: function(data) {
            $("#rse_options").html(html_options);
            $("#save_attr").addClass("disabled");
            $.each(data, function(index, value) {
                $('#approver_select')
                    .append($("<option></option>")
                            .attr("value",value['account']).attr('id', 'approver_select_option_' + value['account'])
                            .text(value['account']));
            });
            $('#approver_select').chosen();
            $.each(rule_approvers, function(index, value) {
                $("#approver_select_option_" + value).attr('selected', 'selected');
                $("#approver_select_option_" + value).attr('selected', 'selected');
            });
            $("#auto_approve_bytes_input").on('input', function() {
                $("#save_attr").removeClass("disabled");
                auto_approve_bytes_changed = true;
            });
            $("#default_limit_bytes_input").on('input', function() {
                $("#save_attr").removeClass("disabled");
                default_limit_bytes_changed = true;
            });
            $("#approver_select").on('change', function() {
                $("#save_attr").removeClass("disabled");
                rule_approvers_changed = true;
            });
            $("#approval_mode").on('change', function() {
                $("#save_attr").removeClass("disabled");
                approval_mode_changed = true;
            });

            $("#approver_select").trigger("chosen:updated");
            $('#auto_approve_bytes_input').val(auto_approve_bytes);
            $('#default_limit_bytes_input').val(default_limit_bytes);
            if (block_manual_approval) {
                $('#approval_mode').prop('checked', true);
            }
            $("#save_attr").click(change_attrs);

        }});

}

load_data = function(rse) {

    $("#rse_input").removeAttr('data-srm-total')
    $('#results').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    if (rse == undefined) {
        var rse = $("#rse_input")[0].value;
    }
    load_rse_attr(rse);
    r.get_rse_usage({
        rse: rse,
        success: function(data) { 
            $(data).each(function(index, element) {
                if (element.source == 'srm') $("#rse_input").attr('data-srm-total', element.total);
            });
            r.get_rse_account_usage({
                rse: rse,
                success: function(data) {
                    $("#results").html(html_result);
                    table_data = [];
                    $.each(data, function(index, value) {
                        if (value['used_bytes'] < 0) {
                            value['difference'] = value['quota_bytes'];
                        } else {
                            value['difference'] = value['quota_bytes'] - value['used_bytes'];
                        }
                        table_data.push(value);
                    });
                    var dt = $("#resulttable").DataTable( {
                        data: table_data,
                        bAutoWidth: false,
                        paging: false,
                        destroy: true,
                        dom: '<"#bulk_edit">frtip',
                        columns: [
                                  {'data': 'account', width: '30%'},
                                  {'data': 'quota_bytes', width: '25%', 'class': 'editable', 'render': renderBytesWithPct},
                                  {'data': 'used_bytes', width: '15%', 'render': renderBytes},
                                  {'data': 'difference', width: '15%', 'render': renderBytes},
                                  {'data': 'used_files', width: '15%' }
                        ],
                    });
                    dt.order([0, 'asc']).draw();
                    $.each(JSON.parse($.cookie('rucio-account-attr')), function(index, attr) {
                        if ((attr.key == 'admin' && attr.value == true) || (attr.key.startsWith('country-') && attr.value == 'admin')) {
                            $('#resulttable tbody .editable').each( function(index, element) {
                                $(element)
                                    .bind('dblclick', 'td', function() { start_editing(this); } )
                                    .bind('focusout', 'td', function() { done_editing(this); } );
                                $('#bulk_edit').html('<a class="button small" data-reveal-id="bulk_editor">Bulk Edit</a>' +
                                                     '<a id="reset-all" class="button small alert">Reset All</a>' +
                                                     '<a data-reveal-id="info" class="info"><i title="Info" class="fi-info size-24"></i></a>');
                                $('#reset-all').click(function(event) {
                                    $('.updated').each( function(index, element) { reset(element); } );
                                });
                            });
                        }
                    });
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    $("#results").html('<font color="red">' + jqXHR['responseText'] + '</font>');
                }
            });
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR, textStatus, errorThrown); 
        }
    });
};

function renderBytes(data, type, row) { return ( type === 'display' || type === 'filter' ) ? filesize(data, {'base': 10}) : data; }
function renderBytesWithPct(data, type, row) { 
  var button = '<a class="button tiny alert reset">Reset</a>';

  if (type === 'display' || type === 'filter') { 
    switch(data) {
      case 0:  return button + '<span>Read-Only</span>';
      case -1: return button + '<span>Unlimited access</span>';
      default: return button + '<span/>' + filesize(data, {'base': 10}) + ' (' + Math.floor(100 / $("#rse_input").attr('data-srm-total') * data) + '%)</span>';
    }
  } else {
    return data; 
  }
}

function updateQuotaBytes() {
    $('#resulttable .updated').each( function(index, element) {
        var account = $('td', $(element).parent()).first().html(), // first column hold the account name
            bytes = $("#resulttable").DataTable().cell(element).data();

        r.set_account_limit({
            account: account,
            rse: $('#rse_input').val(),
            bytes: bytes,
            success: function(data) {
                $(element).removeAttr('data-bytes')
                    .removeAttr('data-info')
                    .removeClass('updated');
            },
            error: function(jqXHR, textStatus, errorThrown) {
                $(element).attr('data-info', 'Error: ' + errorThrown);
                $(element).addClass('error');
            }
        });
    });
    // Hide save button
    $('#save_quota').hide();
}

function parse_quota_input(quota_str) {
    var parts = quota_str.match(/^([0-9\.-]+)\s*([eEpPtTgGmMkKbB%]{0,1})/);
    if ((parts == null) || (isNaN(parts[1]))) { throw 'Invalid input'; }
    switch(parts[2].toLowerCase()) {
        case '%': return (Number(parts[1])/100.0*Number($("#rse_input").attr('data-srm-total')));
        case 'e': return Number(parts[1]) * Math.pow(1024, 6);
        case 'p': return Number(parts[1]) * Math.pow(1024, 5);
        case 't': return Number(parts[1]) * Math.pow(1024, 4);
        case 'g': return Number(parts[1]) * Math.pow(1024, 3);
        case 'm': return Number(parts[1]) * Math.pow(1024, 2);
        case 'k': return Number(parts[1]) * Math.pow(1024, 1);
        case 'b': 
        default: return Math.round(parts[1]);
    }
}

function done_editing(container) {
    if (!$(container).hasClass('editing')) return;  // when column is sorted, lostfocus event is triggered. This avoids execution if field wasn't currently edited

    var container = $(container),
        old_bytes = Number(container.attr('data-bytes'));
        new_bytes = undefined,
        delta_bytes = undefined;

    try {
        new_bytes = parse_quota_input($('input[type="text"]', container).val());
    } catch(err) {
        container.attr('data-info', err);
        new_bytes = 0;
    }

    delta_bytes = new_bytes - old_bytes;
    container.removeClass('editing');
    $("#resulttable").DataTable().cell(container).data(new_bytes);

    // Check if value changed, and thus cell should be marked as 'updated' i.e. if delta greate than 1%
    if (delta_bytes && (new_bytes > 0)) {
        container.addClass('updated');
        container.attr('data-info', 'Delta: ' + filesize(delta_bytes, {'base': 10}));
    } else if (new_bytes == 0) {
        //container.attr('data-info', 'Read-Only access');
    } else if (new_bytes == -1) {
        //container.attr('data-info', 'Unlimited access');
    } else {
        container.removeClass('updated');
        container.removeAttr('data-bytes');
        container.removeAttr('data-info');
    }

    // Check if Save button should be shown
    ($('.updated').length) ? $('#save_quota').show() : $('#save_quota').hide();
}

function start_editing(container) {
    var container = $(container),
        value = $("#resulttable").DataTable().cell(container).data(),
        edit_field = $('<input type="text" value="' + $('span', container).html() + '"/>');        

    if ($('input', container).length) return;

    if (container.attr('data-bytes') == undefined)
        container.attr('data-bytes', value);

    edit_field.bind('keydown', function(e) { 
        if (e.which == 13) {
            done_editing($(e.target).closest('.editing'));
        } else if (e.which == 27) {
            $(e.target).val($(e.target).closest('[data-bytes]').attr('data-bytes'));
            done_editing($(e.target).closest('.editing'));
        }
    });

    container.removeClass('error')
             .addClass('editing')
             .removeAttr('data-info')
             .html(edit_field);
    edit_field.select().focus();
}


$(document).ready(function(){
    rse = url_param('rse');
    if (rse != "") {
        $("#rse_input").val(rse);
        load_data(rse);
    }

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

    $("#rse_input").keydown(function(e) {
        if (e.keyCode == 13) {
            load_data();
        }
    });

    $("#select_rse").on('click', function() {
        load_data();
    });

    $('#save_quota').bind('click', updateQuotaBytes);
    $(document).on('click', '#resulttable .button.reset', reset);

    $('#bulk_apply').click(function() {
      var bytes = undefined,
          table = $('#resulttable').DataTable();

      try { bytes = parse_quota_input($('#bulk_editor input[type="text"]').val()); } catch(err) { alert(err); $('#bulk_editor input[type="text"]').select().focus(); return;}
      
      $('tbody .editable').each( function(index, element) {
        if ($(element).attr('data-bytes') == undefined) $(element).attr('data-bytes', table.cell(element).data());
        if (bytes != $(element).attr('data-bytes')) {
          $(element).addClass('updated')
            $(element).attr('data-info', 'Delta: ' + filesize(bytes - Number($(element).attr('data-bytes')), {'base': 10}));
        }
        table.cell(element).data(bytes);
      });
      table.draw();

      $('#bulk_editor input[type="text"]').val('');
      $('#bulk_editor .close-reveal-modal').click();

      ($('.updated').length) ? $('#save_quota').show() : $('#save_quota').hide();
    });

    $('#bulk_cancel').click(function(event) { $('#bulk_editor .close-reveal-modal').click(); });
    //$('#bulk_edit').click(function(event) { $('#bulk_editor input[type="text"]').focus(); });

    $('#bulk_editor input[type="text"]').keydown(function(e) {
      if (e.which == 13) {
        $('#bulk_apply').click();
      } else if (e.which == 27) {
        $('#bulk_cancel').click();
      }
    });

});


function reset(e) {
    var element = e.target || e;
        container = $(element).closest('tbody .editable');

    $("#resulttable").DataTable().cell(container).data(container.attr('data-bytes')),
    container.removeClass('updated')
             .removeClass('error')
             .removeAttr('data-info')
             .removeAttr('data-bytes');
    ($('.updated').length) ? $('#save_quota').show() : $('#save_quota').hide();
}
