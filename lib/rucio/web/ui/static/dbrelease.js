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
    r.get_dbreleases_from_dumps({
        success: function(response) {
            updated_at = response['updated_at'];
            console.log(updated_at.split('.')[0].replace('T', ' '));
            $('#note').html('This data is updated periodically. Last update: ' + updated_at.split('.')[0].replace('T', ' '));
            console.log(updated_at);
            data = response['data'];
            var table_data = [];
            $.each(data, function(did, meta) {
                scope_name = did.split(':');
                size = meta['bytes'];
                length = meta['length'];
                open = false
                if ((size == null) && (length == null)) {
                    open = true;
                }
                if (open) {
                    size = "open";
                } else {
                    size =  parseInt(meta['bytes'] / 1024 / 1024);
                }
                did_link = '<a href="/did?scope=' + scope_name[0] + '&name=' + scope_name[1] + '">' + did + '</a>'
                entry = {'name': did_link, 'creation_date': meta['creation_date'].replace('T', ' '), 'size': size, 'HOTDISK': '', 'DATADISK': '', 'DATATAPE': '', 'CA': '', 'DE': '', 'ES': '', 'FR': '', 'IT': '', 'ND': '', 'NL': '', 'RU': '', 'TW': '', 'UK': '', 'US': ''};
                rses = meta['rses'];
                max_rows = 1;
                $.each(rses, function(cloud, locks) {
                    if (locks.length > max_rows) {
                        max_rows = locks.length;
                    }
                });
                $.each(rses, function(cloud, locks) {
                    if (max_rows == 3) {
                        entry[cloud] = '<div style="height:3.8em">';
                    } else if (max_rows == 2) {
                        entry[cloud] = '<div style="height:2.5em">';
                    } else {
                        entry[cloud] = '<div>';
                    }
                    $.each(locks, function(index, lock) {
                        if (lock[2] == 'O') {
                            if (open) {
                                entry[cloud] += '<div style="background-color:#00FFFF"><a title="' + lock[0] + '" style="color: black" href="/rule?rule_id=' + lock[1] +'"><center>' + lock[3] + '</center></a></div>';
                            } else {
                                entry[cloud] += '<div style="background-color:#00FF00"><a title="' + lock[0] + '" style="color: black" href="/rule?rule_id=' + lock[1] +'"><center>' + lock[3] + '/' + length + '</center></a></div>';
                            }
                        } else if (locks[2] == 'R') {
                            if (open) {
                                entry[cloud] == '<div style="background-color:orange"><a style="color: black" href="/rule?rule_id=' + lock[1] +'"><center>' + lock[3] + '</center></a></div>';
                            } else {
                                entry[cloud] == '<div style="background-color:orange"><a style="color: black" href="/rule?rule_id=' + lock[1] +'"><center>' + lock[3] + '/' + meta['length'] + '</center></a></div>';
                            }
                        } else {
                            if (open) {
                                entry[cloud] += '<div style="background-color:red"><a style="color: white" href="/rule?rule_id=' + lock[1] +'"><center>' + lock[3] + '</center></a></div></center>';
                            } else {
                                entry[cloud] += '<div style="background-color:red"><a style="color: white" href="/rule?rule_id=' + lock[1] +'"><center>' + lock[3] + '/' + length + '</center></a></div></center>';
                            }
                        }
                    });
                    entry[cloud] += '</div>'
                });
                table_data.push(entry);
            });
            var dt = $('#resulttable').DataTable( {
                data: table_data,
                bAutoWidth: false,
                paging: false,
                "oLanguage": {
                    "sProcessing": "test..."
                },
                columns: [{'data': 'name', width: '25%'},
                          {'data': 'creation_date', width: '10%'},
                          {'data': 'size', width: '5%'},
                          {'data': 'CERN', width: '5%'},
                          {'data': 'CA', width: '5%'},
                          {'data': 'DE', width: '5%'},
                          {'data': 'ES', width: '5%'},
                          {'data': 'FR', width: '5%'},
                          {'data': 'IT', width: '5%'},
                          {'data': 'ND', width: '5%'},
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
