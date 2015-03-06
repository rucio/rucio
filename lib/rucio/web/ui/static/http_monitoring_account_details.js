/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Ralph Vigne <ralph.vigne@cern.ch> 2015
 * - Thomas Beermann <thomas.beermann@cern.ch> 2015
 */

var oTable = null;

function load_data(date, account) {
    $.ajax({
        url: "/http-monitoring/data?report=account_details&date="+date+"&account="+account+"&top=20000",
        crossDomain: true,
        success: function(csv) {
            fill_table(csv);
            $("#content h1").html("Request details of " + account);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert(textStatus);
        }
    });
}

function fill_table(csv) {
    var tbl_data = [];
    var splitted = csv.split('\n');
    for(var i=1; i < splitted.length; i++) {
        cols = splitted[i].split('\t');
        if(cols[0] == "") continue;
        tbl_data.push([cols[2], Number(cols[3]), (Number(cols[4]/1024/1024)).toFixed(2), (Number(cols[5]/10000)).toFixed(2)]);
    }
    if (oTable != null) {
        oTable.clear();
        oTable.rows.add(tbl_data);
        oTable.order([3, 'desc']).draw();
    } else {
      oTable = $('#account_activity').DataTable({
        data: tbl_data,
        aoColumns: [
          {'width': '75%'},
          {'class': 'align-right'},
          {'class': 'align-right'},
          {'class': 'align-right'}
        ],
        "order": [[ 3, "desc" ]]
      });
    }
}


$(document).ready(function() {
    var chosen_account = /\S+\/(.*)$/g.exec(window.location.pathname)[1]
    $( "#datepicker" ).datepicker({
        onSelect: function() {
            report_date = $("#datepicker").val();
            window.history.replaceState(undefined, "Account Details " + report_date , "/webstats/accounts/" + chosen_account  + "?date="+report_date);
            load_data(report_date, chosen_account);
        }
    });
    $( "#datepicker" ).datepicker("option", "dateFormat", "yy-mm-dd");

    var report_date = url_param('date');
    if (report_date != '') {
      $( "#datepicker" ).val(report_date);
    } else {
      $( "#datepicker" ).datepicker('setDate', new Date());
      report_date = $( "#datepicker" ).val();
    }
    load_data(report_date, chosen_account);
    window.history.replaceState(undefined, "Account Details " + report_date , "/webstats/accounts/" + chosen_account  + "?date="+report_date);
    $('#graphite').attr("href","http://rucio-graphite-int.cern.ch/grafana/#/dashboard/db/http-details-per-account?from="+(new Date(report_date+" 00:00")).getTime()+"&var-Account="+account);
});
