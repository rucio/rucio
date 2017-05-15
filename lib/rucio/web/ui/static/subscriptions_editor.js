/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2017
 */

$(document).ready(function(){
    var filter = [];
    var already_selected = {};
    var results = {};
    options = {};
    $('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
    d = jQuery.Deferred();
    if (url_param('name') != '' && url_param('account')) {
        options['name'] =  url_param('name');
        options['account'] = url_param('account');
        r.list_subscriptions({
             name: options['name'],
             account: options['account'],
             success: function(data){
                 if (data == '') {
                    $('#result').html('<font color="red">Could not find the subscription</font>');
                 }
                 else{
                    tmp = JSON.parse(data[0]['filter']);
                    var replication_rules = JSON.parse(data[0]['replication_rules']);
                    $('#name').val(data[0].name);
                    $('#sub_account').val(data[0].account);
                    $('#comments').val(data[0].comments);
                    $('#lifetime').val(replication_rules[0].lifetime / 86400);
                    $('#copies').val(parseInt(replication_rules[0].copies));
                    $('#rse_expression').val(replication_rules[0].rse_expression);
                    $('#source_replica_expression').val(replication_rules[0].source_replica_expression);
                    $('#activity').val(replication_rules[0].activity);
                    $('#weight').val(replication_rules[0].weight);
                    $.each(tmp, function(i, value) {
                         already_selected[i] = [];
                         already_selected[i].push(value);
                    });
                 }
                 d.resolve();
             },
             error: function(jqXHR, textStatus, errorThrown) {
                $('#result').html('<font color="red">Could not find the subscription</font>');
                console.log('Could not list subscriptions: ' + textStatus);
             }
        });
    }
    else{
       d.resolve();
    }

    $('.numbersOnly').keyup(function () {
        this.value = this.value.replace(/[^0-9\.]/g,'');
    });
    $("#enable_pattern_yes").click(function() {
        $("#pattern").attr("disabled", false);
    });
    $("#enable_pattern_no").click(function() {
        $("#pattern").val("");
        $("#pattern").attr("disabled", true);
    });

    $.when(d).done(function(){
        d1 = jQuery.Deferred();
        d2 = jQuery.Deferred();
        r.list_scopes({
            account: account,
            success: function(data) {
               tmp = JSON.parse(data);
               $.each(tmp, function(i, value) {
		$("#scopeselect").append($('<option>').attr('id', value).attr('value', value).text(value));
               });
               $("#scopeselect").chosen();
               if (already_selected.scope){
                  $.each(already_selected.scope, function(index, value){
                     $('#scopeselect').val(value);
                     $('#scopeselect').trigger("chosen:updated");
                  });
               }
               d2.resolve();
            },
            error: function(jqXHR, textStatus, errorThrown) {
               console.log('Could not list scopes: ' + textStatus);
               d2.resolve();
            }
        });
        var wrapper = $(".input_fields_wrap");
        var existing_meta =[]
        r.show_metadata({
            account: account,
            success: function(data) {
	         $("#metaselect").append($('<option>').attr('id', 'did_type').attr('value', 'did_type').text('did_type'));
                 $("#metaselect").append($('<option>').attr('id', 'transient').attr('value', 'transient').text('transient'));
                 $("#metaselect").append($('<option>').attr('id', 'account').attr('value', 'account').text('account'));
                 $.each(data, function(i, value) {
                    $("#metaselect").append($('<option>').attr('id', value).attr('value', value).text(value));
                 });
                 $("#metaselect").chosen();
                 $.each(already_selected, function(index, value){
                     if (index != 'scope' && index != 'split_rule' && index != 'pattern'){
                        $(wrapper).append('<div id="'+index+'"><label>'+index+'<input type="text" id="input_'+index+'" value="'+value+'"/></label></div>');
                        existing_meta.push(index);
                     }
                 });
                 if ($.inArray('split_rule', existing_meta) && (existing_meta || existing_meta.split_rule == 'True')){
                     $("#split_rule_yes").prop("checked", true);
                 }
                 else{
                     $("#split_rule_yes").prop("checked", false);
                 }
                 $('#metaselect').val(existing_meta);
                 $('#metaselect').trigger("chosen:updated");
                 d1.resolve();
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.log('Could not list metadata: ' + textStatus);
                d1.resolve();
            }
          });
       $.when( d1, d2 ).done(function(){
            $('#loader').html('');
       });
      if (already_selected.pattern == undefined){
          $("#enable_pattern_no").prop("checked", true);
          $("#pattern").attr("disabled", true);
      }
      else{
          $("#enable_pattern_yes").prop("checked", true);
          $("#pattern").val(already_selected.pattern);
      }
      $("#metaselect").change(function(){
         var metadata = $(this).val();
         // Check new metadata
         if (metadata){
            $.each(metadata, function(index, value) {
               if ($.inArray(value, existing_meta) == -1 &&value != 'pattern'){
                   console.log("Adding new metadata : "+value);
                   $(wrapper).append('<div id="'+value+'"><label>'+value+'<input type="text" id="input_'+value+'"/></label></div>');
                   existing_meta.push(value);
               }
            });
         }
         // Check metadata removed
         var tmp = $.extend(true, [], existing_meta);
         $.each(tmp, function(index, value) {
              console.log('Looping on existing_meta');
              if ($.inArray(value, metadata) == -1) {
                  console.log("Will remove : "+value);
                  $(wrapper).find('#'+value).remove();
                  existing_meta.pop(value);
              }
           });
        });

        $('#rse_expression_checker').submit(function( event) {
            r.list_rses({
                    'expression': $('#rse_expression').val(),
                    success: function(data) {
                       $("#rse_val_result").text( "Validated." ).show().fadeOut(2000);
                    },
                    error: function(jqXHR, textStatus, errorThrown) {
                       $("#rse_val_result").text( "RSE expression not valid!" ).show();
                    }
                });
            return false;
        });

        $("#submit_request").submit(function( event) {
            var scopes = $("#scopeselect").chosen().val();
            var filter = {scope: scopes};
            $.each(existing_meta, function(index, value){
                     if (index != 'scope' && index != 'pattern'){
                         if ($('#input_'+value).val() != undefined){
                             filter[value] =  $('#input_'+value).val().split(',');
                         }
                     }
                 });
           if ($('#pattern') && ($('#pattern').val() != undefined) && ($('#pattern').val() != "")){
               filter.pattern = $('#pattern').val();
           }

           $("#split_rule_yes").click(function() {
               filter.split_rule = true;
               filter.split_rule = "True";
           });
           $("#split_rule_no").click(function() {
               if (filter.split_rule != undefined){
                   delete filter.split_rule;
               }
           });
           if ($("#split_rule_yes:checked").val()){
               filter.split_rule = true;
           }
           if ($("#split_rule_no:checked").val()){
               delete filter.split_rule;
           }

           results.name = $('#name').val();
           results.account = $('#sub_account').val();
           results.comments = $('#comments').val();
           var replication_rule = {};
           if ($('#lifetime').val() && !isNaN($('#lifetime').val())){
                replication_rule.lifetime = parseInt($('#lifetime').val() * 86400);
           }
           replication_rule.copies = parseInt($('#copies').val());
           replication_rule.rse_expression = $('#rse_expression').val();
           if ($('#source_replica_expression').val()){
               replication_rule.source_replica_expression = $('#source_replica_expression').val();
           }
           replication_rule.activity = $('#activity').val();
           if ($('#weight').val()){
              replication_rule.weight = $('#weight').val();
           }
           var replication_rule_array = [replication_rule];
           var process_request = false;
           r.list_subscriptions({
                 name: results.name,
                 account: results.account,
                 success: function(data){
                     $("#dialogform").text('The subscription already exists. Do you want to update it ?');
                     dialog = $("#dialogform").dialog({
                       autoOpen: false,
                       height: 400,
                       width: 350,
                       modal: true,
                       title: "Update subscription",
                       buttons: {
                         Yes: function(){
                            process_request = true;
                            var params = {'filter': filter, 'replication_rules': replication_rule_array,
                                          'comments': results.comments}
                            r.update_subscription({
                                account: results.account,
                                name: results.name,
                                params: params,
                                success: function(data) {
                                    console.log('Subscription updated');
                                    dialog.dialog( "close");
                                    window.location.href='/subscription?name=' + url_param('name') + '&account=' + url_param('account');
                                },
                                error: function(jqXHR, textStatus, errorThrown) {
                                    console.log('Could not update subscription: ' + textStatus);
                                    console.log(errorThrown);
                                    dialog.dialog( "close");
                                }
                            });
                         },
                         Cancel: function() {
                            dialog.dialog( "close" );
                         }
                       }
                     });
                     dialog.dialog( "open" );
                 },
                 error: function(jqXHR, textStatus, errorThrown) {
                    console.log('Could not list subscriptions: ' + textStatus);
                    if (errorThrown == "Not Found"){
                        $("#dialogform").text('Subscription does not exists. Do you want to create it ?');
                        dialog = $("#dialogform").dialog({
                          autoOpen: false,
                          height: 400,
                          width: 350,
                          modal: true,
                          title: "Create new subscription",
                          buttons: {
                            Yes: function(){
                               process_request = true;
                               var params = {'filter': filter, 'replication_rules': replication_rule_array,
                                             'comments': results.comments, 'retroactive': null, 'dry_run': null, 'lifetime': null}
                               r.create_subscription({
                                   account: results.account,
                                   name: results.name,
                                   params: params,
                                   success: function(data) {
                                       console.log('New subscription created with id ' + data);
                                       dialog.dialog( "close");
                                       window.location.href='/subscription?name=' + url_param('name') + '&account=' + url_param('account');
                                   },
                                   error: function(jqXHR, textStatus, errorThrown) {
                                       console.log('Could not create subscription: ' + textStatus);
                                       console.log(errorThrown);
                                       dialog.dialog( "close");
                                   }
                               });
                            },
                            Cancel: function() {
                              dialog.dialog( "close");
                            }
                          }
                        });
                        dialog.dialog("open");
                    }
                 }
           });
           return false;
        });
    });
});
