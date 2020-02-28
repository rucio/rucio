/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2017-2019
 */


function formatBytes(bytes){
   if(bytes == 0) return '0 Bytes';
   sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'],
   i = Math.floor(Math.log10(bytes) / 3);
   return parseFloat(bytes / Math.pow(1000, i)).toFixed(2) + ' ' + sizes[i];
}

$(document).ready(function(){
    var today = new Date();
    var ms = today.getTime() + 86400000;
    var from_date = new Date(ms);
    var to_date =  new Date(today.getTime() + 86400000 * 366);
    var scopes = []
    var proj = ['mc', 'data', 'valid'];
    var chosen_proj = null;
    var project = null;
    var datatypes = [];
    var datatype = null;
    $('#datasets').multiSelect({
        selectableHeader: "<input type='text' class='search-input' autocomplete='off' placeholder='Put you pattern there or click on the datasets you want to keep'>",
        //selectionHeader: "<input type='text' class='search-input' autocomplete='off' placeholder='Selected datasets'>",
        selectableFooter: "<div class='custom-header'>List of expiring datasets</div>",
        selectionFooter: "<div class='custom-header'>List of datasets that need to be kept</div>",
        afterInit: function(ms){
          var that = this,
              $selectableSearch = that.$selectableUl.prev(),
              $selectionSearch = that.$selectionUl.prev(),
              selectableSearchString = '#'+that.$container.attr('id')+' .ms-elem-selectable:not(.ms-selected)',
              selectionSearchString = '#'+that.$container.attr('id')+' .ms-elem-selection.ms-selected';
          that.qs1 = $selectableSearch.quicksearch(selectableSearchString)
          .on('keydown', function(e){
            if (e.which === 40){
              that.$selectableUl.focus();
              return false;
            }
          });
          that.qs2 = $selectionSearch.quicksearch(selectionSearchString)
          .on('keydown', function(e){
            if (e.which == 40){
              that.$selectionUl.focus();
              return false;
            }
          });
        },
        afterSelect: function(){
          this.qs1.cache();
          this.qs2.cache();
        },
        afterDeselect: function(){
          this.qs1.cache();
          this.qs2.cache();
        }
    });
    $('#datasets').empty().multiSelect('refresh');

    $('input:radio[name="pattern_selector"]').change(function() {
        chosen_proj = $(this).val()
        $("#scope_div").show().fadeIn(2000)
        $('#scopeselect').empty()
        $('#scopeselect').trigger("chosen:updated");;
        $('#datatype').empty()
        $('#datatype').trigger("chosen:updated");;
        $('#datasets').empty().multiSelect('refresh');
        $('#estimated_vol').empty();
        scopes = [];
        $.get("/dumpsproxy/lifetime/latest/beyond-lifetime-centrally-managed/beyond-lifetime-"+chosen_proj+"/by-project/", function(data) {
            $.each($(data), function( i, el ){
               if (el.localName == 'table'){
                  var tmp = $(this).find('a')
                  $.each($(data).find('a'), function(k, v) {
                       var scope = v.innerText;
                       if ($.inArray(scope, ['Name', 'Last Modified', 'Size', 'Description', 'Parent Directory', 'Last modified']) == -1){
                           scopes.push(scope.slice(0, -1));
                       }
                  });
               }
            });
            $("#scopeselect").append($('<option>').attr('id', 'Choose a scope...').attr('value', 'Choose a scope...').text('Choose a scope...'));
            $.each(scopes, function(i, value) {
                $("#scopeselect").append($('<option>').attr('id', value).attr('value', value).text(value));
            });
            $('#scopeselect').chosen();
            $('#scopeselect').trigger("chosen:updated");
        });
    });
    $('#scopeselect').on('change', function() {
       $("#datatype_div").show().fadeIn(2000)
       $("#scopeselect").find('option:contains("Choose a scope...")').attr('disabled', true);
       project = $(this).val();
       datatypes = [];
       $('#datatype').empty()
       $('#datatype').trigger("chosen:updated");;
       $('#datasets').empty().multiSelect('refresh');
       $('#estimated_vol').empty();
       $.get("/dumpsproxy/lifetime/latest/beyond-lifetime-centrally-managed/beyond-lifetime-"+chosen_proj+"/by-project/"+project, function(data) {
          $.each($(data), function( i, el ){
             if (el.localName == 'table'){
                var tmp = $(this).find('a')
                $.each($(data).find('a'), function(k, v) {
                     var datatype = v.innerText;
                     if ($.inArray(datatype, ['Name', 'Last Modified', 'Size', 'Description', 'Parent Directory', 'Last modified']) == -1){
                         datatypes.push(datatype);
                     }
                });
             }
          });
          $("#datatype").append($('<option>').attr('id', 'Choose a datatype...').attr('value', 'Choose a datatype...').text('Choose a datatype...'));
          $.each(datatypes, function(i, value) {
             $("#datatype").append($('<option>').attr('id', value).attr('value', value).text(value));
          });
          $('#datatype').chosen();
          $('#datatype').trigger("chosen:updated");
       });
    });

    var dataset_volume = {};
    $('#datatype').on('change', function() {
        datatype = $(this).val();
        $("#datatype").find('option:contains("Choose a datatype...")').attr('disabled', true);
        $('#datasets').empty().multiSelect('refresh');
        $('#estimated_vol').empty();
        $('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
        $.get("/dumpsproxy/lifetime/latest/beyond-lifetime-centrally-managed/beyond-lifetime-"+chosen_proj+"/by-project/"+project+"/"+datatype, function(data) {
            var datasets_array = [];
            dataset_volume = {};
            d = jQuery.Deferred();
            var list_dids = data.split("\n");
            var get_datasets = false;
            if (list_dids.length > 5000){
                $("#dialogform").text('There are '+list_dids.length+' datasets matching these criteria !\n In that case it is recommended to use the Rucio CLI.\n Do you really want to continue (This is most likely a bad idea) ?');
                dialog = $("#dialogform").dialog({
                    autoOpen: false,
                    height: 400,
                    width: 600,
                    modal: true,
                    title: "WARNING : Too many datasets",
                    buttons: {
                      Yes: function(){
                          get_datasets = true;
                          $(this).dialog("close");
                          d.resolve();
                      },
                      Cancel: function() {
                          $('#loader').html('');
                          d.resolve();
                          $(this).dialog("close");
                      }
                    }
                });
                dialog.dialog("open");
            }
            else{
               get_datasets = true;
               d.resolve();
            }
            $.when(d).done(function(){
                if (get_datasets){
                    for (idx = 0; idx < list_dids.length; idx++){
                        var res = list_dids[idx].split(" ");
                        dataset_volume[res[0]]= res[2];
                        datasets_array.push('<option value="'+res[0]+'" id='+idx+'>'+res[0]+'</option>');
                    }
                    $("#datasets").append(datasets_array);
                    $('#select-all').click(function(){
                       var selected_array = [];
                       $.each($('.ms-elem-selectable'), function( i, el ){
                           if (el.style.display != "none"){
                               selected_array.push(el.innerText);
                           };
                       });
                       $('#datasets').multiSelect('select', selected_array);
                       return false;
                    });
                    $('#deselect-all').click(function(){
                       $('#datasets').multiSelect('deselect_all');
                       return false;
                    });
                    $('#datasets').multiSelect('refresh');
                    $('#loader').html('');
                }
            });
       });
    });

    $('#datasets').on('change', function() {
        $('#estimated_vol').empty();
        var selected_volume = 0;
        var selected_datasets = $("#datasets").val();
        for (idx = 0; idx < selected_datasets.length; idx++){
            if (selected_datasets[idx] != ""){
                selected_volume += Number(dataset_volume[selected_datasets[idx]]);
            }
        }
        $('#estimated_vol').text(formatBytes(selected_volume));
    });

    $("#datepicker").datepicker({
                                 defaultDate: null,
                                 dateFormat: "D, d M yy",
                                 minDate: from_date,
                                 maxDate: to_date,
                                 onSelect: function(){
                                          var lifetime = $("#datepicker").val();
                                      }
                                 });
    $("#datepicker").datepicker( "setDate" , null )
    $("#submit_request").submit(function( event) {
        var datasets = $("#datasets").val();
        var reason = $("#reason").val();
        var lifetime = $("#datepicker").val();
        var scope = $("#scopeselect").val();
        var volume = $("#estimated_vol").text();
        if (reason == null || reason == ""){
            alert("You must provide a reason !");
            return false;
        }
        if (lifetime == null || lifetime == ""){
            alert("You must provide an expiration date for you request !");
            return false;
        }
        lifetime += ' 00:00:00 UTC'
        var dids = [];
        for (idx = 0; idx < datasets.length; idx++){
            if (datasets[idx] != ""){
                dids.push({'scope': scope, 'name': datasets[idx], 'did_type': 'DATASET'});
            }
        }
        $("#dialogform").text('You requested an exception for '+dids.length+' datasets representing '+volume+'\n Do you confirm ?');
        dialog = $("#dialogform").dialog({
            autoOpen: false,
            height: 400,
            width: 350,
            modal: true,
            title: "Request Lifetime exception",
            buttons: {
              Yes: function(){
                 process_request = true;
                 r.create_lifetime_exception({
                     dids: dids,
                     pattern: null,
                     comments: reason + '||||' + volume,
                     expires_at: lifetime,
                     success: function(data) {
                         dialog.dialog( "close");
                         $("#alert_box").html('<div data-alert class="alert-box success radius">The request has been successfully submitted. It will be approved or rejected in the coming days.</div>');
                     },
                     error: function(jqXHR, textStatus, errorThrown) {
                         var alert_text = '<div data-alert class="alert-box alert radius"> Problem to create the exception : '
                         dialog.dialog( "close");
                         alert_text += errorThrown
                         alert_text += '</div>'
                         $("#alert_box").html(alert_text);
                     }
                 });
              },
              Cancel: function() {
                dialog.dialog( "close");
              }
            }
        });
        dialog.dialog("open");
        return false
    });
});
