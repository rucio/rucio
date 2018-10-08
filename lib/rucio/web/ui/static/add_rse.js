/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018
 */

add_rse = function() {
    $('.error').hide();

    var values = {};
    var city = $('#city').val();
    var country = $('#country').val();
    var region = $('#region').val();
    var continent = $('#continent').val();
    var isp = $('#isp').val();
    var time_zone = $('#timeZone').val();
    var name = $('#name').val();

    if(RegExp('^([A-Z0-9]+([_-][A-Z0-9]+)*)').test(name) && !RegExp('[a-z]').test(name)) {
        $('#loader').show();
        if(city) values["city"] = city;
        if(country) values["country_name"] = country;
        if(region) values["region_code"] = region;
        if(continent) values["continent"] = continent;
        if(isp) values["ISP"] = isp;
        if(time_zone) values["time_zone"] = time_zone;
        values["deterministic"] = $('#deterministic').is(':checked');
        values["volatile"] = $('#volatile').is(':checked');
        values["staging_area"] = $('#stagingArea').is(':checked');
    
    
        r.add_rse(name, {
            'values': values,
            success: function(data) {
                $('#result').text('RSE successfully created');
                $('#loader').hide();
                window.location.href = window.location.origin = "/rses";
            },
            error: function(jqXHR, textStatus, errorThrown) {
                if (errorThrown == "Internal Server Error") {
                    $('#result').text("RSE could not be created. There was an Internal Server Error.");
                } else if (errorThrown == "Conflict") {
                    $('#result').text("RSE exists already.");
                } else if (errorThrown == "Bad Request") {
                    $('#result').text("RSE could not be created. There was problem with decoding your input.");
                } 
                $('#loader').hide();
            }
        })
    } else {
        $('#name').after('<span class="error"> Please use only uppersace letters, underscores, minus signs or numbers</span>');
    }
};

$(document).ready(function(){
    $('#loader').hide();
    $('#addRSEButton').on('click', function() {
        add_rse();
    })
});
