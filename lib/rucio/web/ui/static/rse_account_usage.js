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

var html_result = '<table id="resulttable" class="compact stripe order-column" style="word-wrap: break-word;"><thead><th>Account</th><th>Quota</th><th>Used</th><th>Available</th><th>Files</th></tr></thead><tfoot><tr><th>Account</th><th>Quota</th><th>Used</th><th>Available</th><th>Files</th></tr></tfoot></table>';

load_data = function(rse) {
    $("#rse_input").removeAttr('data-srm-total')
    $('#results').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    if (rse == undefined) {
        var rse = $("#rse_input")[0].value;
    }
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

function renderBytes(data, type, row) { return ( type === 'display' || type === 'filter' ) ? filesize(data) : data; }
function renderBytesWithPct(data, type, row) { 
  var button = '<a class="button tiny alert reset">Reset</a>';

  if (type === 'display' || type === 'filter') { 
    switch(data) {
      case 0:  return button + '<span>Read-Only</span>';
      case -1: return button + '<span>Unlimited access</span>';
      default: return button + '<span/>' + filesize(data) + ' (' + Math.floor(100 / $("#rse_input").attr('data-srm-total') * data) + '%)</span>';
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
        container.attr('data-info', 'Delta: ' + filesize(delta_bytes));
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
          $(element).attr('data-info', 'Delta: ' + filesize(bytes - Number($(element).attr('data-bytes'))));
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
