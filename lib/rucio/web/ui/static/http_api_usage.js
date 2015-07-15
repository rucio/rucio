/*
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Ralph Vigne, <ralph.vigne@cern.ch>, 2015
*/

$(document).ready(function() {
  setDashboard();
});


function setDashboard() {
  var src = "https://rucio-ui-dev.cern.ch/kibana/#/dashboard/Rucio-RESTAPI-Account-Usage?embed&_g=("+
            "time:"+$('input[name=period]:checked', '#timeframe').val()+")&"+
            "_a=(filters:!(),panels:!("+
            "(col:8,id:Rucio-RESTAPI-Overall-Numbers,row:1,size_x:5,size_y:4,type:visualization),"+
            "(col:1,id:Rucio-RESTAPI-Account-Usage-Resources,row:5,size_x:12,size_y:5,type:visualization),"+
            "(col:1,id:Rucio-RESTAPI-Account-Usage-Activity-over-Time,row:1,size_x:7,size_y:4,type:visualization)),"+
            "query:(query_string:(analyze_wildcard:!t,query:'account:"+account+"')),title:'Rucio%20-%20RESTAPI%20-%20Account%20Usage')"

  $('#db').attr('src', src);
}

