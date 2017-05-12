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
    var today = new Date();
    var ms = today.getTime() + 86400000;
    var from_date = new Date(ms);
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
            $.each(scopes, function(i, value) {
                $("#scopeselect").append($('<option>').attr('id', value).attr('value', value).text(value));
            });
            $('#scopeselect').chosen();
            $('#scopeselect').trigger("chosen:updated");
        });
    });
    $('#scopeselect').on('change', function() {
       $("#datatype_div").show().fadeIn(2000)
       project = $(this).val();
       datatypes = [];
       $('#datatype').empty()
       $('#datatype').trigger("chosen:updated");;
       $('#datasets').empty().multiSelect('refresh');
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
          $.each(datatypes, function(i, value) {
             $("#datatype").append($('<option>').attr('id', value).attr('value', value).text(value));
          });
          $('#datatype').chosen();
          $('#datatype').trigger("chosen:updated");;
       });
    });

    $('#datatype').on('change', function() {
       datatype = $(this).val();
       $('#datasets').empty().multiSelect('refresh');
       $('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');
       $.get("/dumpsproxy/lifetime/latest/beyond-lifetime-centrally-managed/beyond-lifetime-"+chosen_proj+"/by-project/"+project+"/"+datatype, function(data) {
            var datasets_array = [];
            $.each(data.split("\n"), function(i, value) {
                var res = value.split(" ");
                //$("#datasets").append($('<option>').attr('id', res[0]).attr('value', res[0]).text(res[0]));
                datasets_array.push($('<option>').attr('id', res[0]).attr('value', res[0]).text(res[0]));
            });
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
       });
    });

    $("#datepicker").datepicker({
                                 defaultDate: null,
                                 minDate: from_date,
                                 onSelect: function(){
                                          var lifetime = $("#datepicker").val();
                                          console.log(lifetime);
                                      }
                                 });
    $("#datepicker").datepicker( "setDate" , null )
    $("#submit_request").submit(function( event) {
        var datasets = $("#datasets").val();
        var reason = $("#reason").val()
        var lifetime = $("#datepicker").val()
        if (reason == null || reason == ""){
            alert("You must provide a reason !");
            return false;
        }
        if (lifetime == null || lifetime == ""){
            alert("You must provide an expiration date for you request !");
            return false;
        }
        console.log(datasets);
        console.log(reason);
        console.log(lifetime);
        //alert("Hello! I am an alert box!!");
        return false;
    });
});
