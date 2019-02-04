/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Cedric Serfon, <cedric.serfon@cern.ch>, 2015-2019
 */


$(document).ready(function(){

    dt = $('#suspiciousreplicas').DataTable();
    var today = new Date();
    var ms = today.getTime() + 86400000;
    var to_date = new Date(ms);
    var ms = to_date.getTime() - 86400000 * 7;
    var from_date = new Date(ms);
    $("#datepicker1").datepicker({
                                      defaultDate: from_date,
                                      minDate: new Date(2015, 0, 1),
                                      onSelect: function(){
                                          from_date = $("#datepicker1").val();
                                      }
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
        })

    var handle = $( "#custom-slider" );
    $( "#slider-range-min" ).slider({
      range: "min",
      value: 10,
      min: 1,
      max: 400,
      create: function() {
        handle.text( $( this ).slider( "value" ) );
      },
      slide: function( event, ui ) {
        handle.text( ui.value );
      }
    });


    $("#submit_button").click(function(){
       if (typeof from_date == "undefined"){
            alert('Please select a start date');
            return
        }
       if (typeof from_date != 'string'){
          from_date = from_date.toISOString().slice(0, 19);
        }
       if (typeof from_date == 'string'){
          split_from_date = from_date.split('/');
          if (split_from_date.length > 2){
              var day = split_from_date[0];
              var month = split_from_date[1];
              var year = split_from_date[2];
              from_date = year + '-' + month + '-' + day + 'T00:00:00';
          }
        }

        dt.destroy();
        $('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div>');

        r.get_suspicious_files({
            rse_expression: $("#rse_expression").val(),
            nattempts: $("#slider-range-min").slider("value"),
            younger_than: from_date,
            success: function(data) {
                $('#loader').html('');

                var tbl_head = '<thead><tr><th>Scope</th><th>Name</th><th>RSE</th><th>Created_at</th><th>Count</th></tr></thead>';
                var tbl_foot = '<tfoot><tr><th>Scope</th><th>Name</th><th>RSE</th><th>Created_at</th><th>Count</th></tr></foot>';
                $("#suspiciousreplicas").remove();
                $("#suspiciousreplicas2").append('<table id="suspiciousreplicas" style="word-wrap: break-word;">'+tbl_head+tbl_foot+'</table>');

                var download = '<a href="data:application/octet-stream;base64,' + btoa(JSON.stringify(data)) + '" download="dump.json">download as JSON</a>';
                $('#downloader').html(download);
                dt = $('#suspiciousreplicas').DataTable({
                                                         data: data,
                                                         columns: [{'data': 'scope'},
                                                                   {'data': 'name'},
                                                                   {'data': 'rse'},
                                                                   {'data': 'created_at'},
                                                                   {'data': 'cnt'}]
                });
                var suspicious_replicas = {};
                var series = [];
                $.each( data, function(index, value ) {
                    var datetime_created_at = new Date(value.created_at);
                    var year = datetime_created_at.getFullYear();
                    var month = datetime_created_at.getMonth();
                    var day = datetime_created_at.getDate();
                    var created_at = new Date(year, month, day);
                    created_at = created_at.getTime();
                    if (!(value.rse in suspicious_replicas)){
                         suspicious_replicas[value.rse] = Object();
                    }
                    if (!(created_at in suspicious_replicas[value.rse])){
                         suspicious_replicas[value.rse][created_at] = 0;
                    }
                    suspicious_replicas[value.rse][created_at] += 1;
                });

                var ordered_suspicious = {};
                Object.keys(suspicious_replicas).sort().forEach(function(key) {
                   ordered_suspicious[key] = suspicious_replicas[key];
                });

                $.each(ordered_suspicious, function( key, value ) {
                    var entries = Array()
                     $.each(value, function(k , v ) {
                        entries.push([parseInt(k), v]);
                    });
                    entries.sort();
                    series.push({'name': key, 'data': entries});
                });


                var chart = $("#suspiciousplot").highcharts( {
                    plotOptions: { area: { stacking: 'normal' } },
                    chart: { type: 'column',
                             zoomType: 'x' },
                    yAxis: { title: { text: 'NB suspicious files' },
                             min: 0 },
                    xAxis: { type: 'datetime',
                             title: { text: 'Day' } },
                    credits: false,
                    title: { text: 'Creation date of the replicas' },
                    series: series
                });
            }
        });
    });
 });
