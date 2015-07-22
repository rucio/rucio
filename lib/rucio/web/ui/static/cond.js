/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2015
 */

$(document).ready(function(){

    r.get_cond_from_dumps({
        success: function(response) {
            updated_at = response['updated_at'];
            $('#note').html('This data is updated periodically. Last update: ' + updated_at.split('.')[0].replace('T', ' '));
            console.log(updated_at);
            data = response['data'];
            var table_data = [];
            $.each(data, function(did, meta) {
                scope_name = did.split(':');
                did_link = '<a href="/did?scope=' + scope_name[0] + '&name=' + scope_name[1] + '">' + did + '</a>'
                entry = {'name': did_link, 'creation_date': meta['creation_date'].replace('T', ' '), 'size': parseInt(meta['bytes'] / 1024 / 1024), 'HOTDISK': '', 'DATADISK': '', 'DATATAPE': '', 'CA': '', 'DE': '', 'ES': '', 'FR': '', 'IT': '', 'NG': '', 'NL': '', 'RU': '', 'TW': '', 'UK': '', 'US': ''};
                rses = meta['rses'];
                $.each(rses, function(rse, locks) {
                    if (rse == 'T0') {
                        console.log(locks);
                        $.each(locks, function(index, lock) {
                            rse = lock[0].split('_')[0];
                            if (lock[2] == 'O') {
                                entry[rse] = '<div style="background-color:#00FF00"><a style="color: black" href="/rule?rule_id=' + locks[1] +'"><center>' + locks[3] + '/' + meta['length'] + '</center></a></div>';
                                
                            } else if (locks[2] == 'R') {
                                entry[rse] = '<div style="background-color:orange"><a style="color: black" href="/rule?rule_id=' + locks[1] +'"><center>' + locks[3] + '/' + meta['length'] + '</center></a></div>';
                            } else {
                                entry[rse] = '<div style="background-color:red"><a style="color: white" href="/rule?rule_id=' + locks[1] +'"><center>' + locks[3] + '/' + meta['length'] + '</center></a></div></center>';
                            }
                        });
                    }
                    if (locks[2] == 'O') {
                        entry[rse] = '<div style="background-color:#00FF00"><a style="color: black" href="/rule?rule_id=' + locks[1] +'"><center>' + locks[3] + '/' + meta['length'] + '</center></a></div>';
                        
                    } else if (locks[2] == 'R') {
                        entry[rse] = '<div style="background-color:orange"><a style="color: black" href="/rule?rule_id=' + locks[1] +'"><center>' + locks[3] + '/' + meta['length'] + '</center></a></div>';
                    } else {
                        entry[rse] = '<div style="background-color:red"><a style="color: white" href="/rule?rule_id=' + locks[1] +'"><center>' + locks[3] + '/' + meta['length'] + '</center></a></div></center>';
                    }
                });
                table_data.push(entry);
            });
            console.log(table_data);
            var dt = $('#resulttable').DataTable( {
                data: table_data,
                bAutoWidth: false,
                paging: false,
                "oLanguage": {
                    "sProcessing": "test..."
                },
                columns: [{'data': 'name', width: '20%'},
                          {'data': 'creation_date', width: '5%'},
                          {'data': 'size', width: '5%'},
                          {'data': 'HOTDISK', width: '5%'},
                          {'data': 'DATATAPE', width: '5%'},
                          {'data': 'DATADISK', width: '5%'},
                          {'data': 'CA', width: '5%'},
                          {'data': 'DE', width: '5%'},
                          {'data': 'ES', width: '5%'},
                          {'data': 'FR', width: '5%'},
                          {'data': 'IT', width: '5%'},
                          {'data': 'NG', width: '5%'},
                          {'data': 'NL', width: '5%'},
                          {'data': 'RU', width: '5%'},
                          {'data': 'TW', width: '5%'},
                          {'data': 'UK', width: '5%'},
                          {'data': 'US', width: '5%'}
                         ]
            });
            $('#resulttable_length').find('select').attr('style', 'width: 4em;');
            $('#resulttable_filter').find('input').attr('style', 'width: 10em; display: inline');
            dt.order([1, 'desc']).draw();
            
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(textStatus);
        }
    });
});
