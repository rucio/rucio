/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Ralph Vigne <ralph.vigne@cern.ch> 2015
 */
$(document).ready(function() {
  var report_date = url_param('date');
  $("#datepicker").datepicker({
    onSelect: function() {
      report_date = $("#datepicker").val();
      $('#resources').attr('href','/webstats/resources?date='+report_date);
      $('#accounts').attr('href','/webstats/accounts?date='+report_date);
      $('#apiclasses').attr('href','/webstats/apiclasses?date='+report_date);
      window.history.replaceState(undefined, "WebStats " + report_date , "/webstats?date="+report_date);
    },
    dateFormat: "yy-mm-dd",
    maxDate: new Date(),
    numberOfMonths: 2
  });

  if (report_date != '') {  $("#datepicker").datepicker("setDate", report_date); }
  else {
    $("#datepicker").datepicker('setDate', new Date());
    report_date = $("#datepicker").val();
  }
  window.history.replaceState(undefined, "WebStats " + report_date , "/webstats?date="+report_date);
  $('#resources').attr('href','/webstats/resources?date='+report_date);
  $('#accounts').attr('href','/webstats/accounts?date='+report_date);
      $('#apiclasses').attr('href','/webstats/apiclasses?date='+report_date);
});
