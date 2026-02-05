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
                let entry = {
                    'name': $('<div>').append($('<a></a>', {'href': '/did?scope=' + scope_name[0] + '&name=' + scope_name[1]}).text(did)).html(),
                    'creation_date': $('<div>').text(meta['creation_date'].replace('T', ' ')).html(),
                    'size': $('<div>').text(String(size)).html(),
                    'CERN': '',
                    'CA': '',
                    'DE': '',
                    'ES': '',
                    'FR': '',
                    'IT': '',
                    'ND': '',
                    'NL': '',
                    'RU': '',
                    'TW': '',
                    'UK': '',
                    'US': '',
                }
                rses = meta['rses'];
                max_rows = 1;
                $.each(rses, function(cloud, locks) {
                    if (locks.length > max_rows) {
                        max_rows = locks.length;
                    }
                });
                $.each(rses, function(cloud, locks) {
                    let cloud_elem = $('<div>');
                    if (max_rows == 3) {
                        cloud_elem.attr('style', 'height:3.8em');
                    } else if (max_rows == 2) {
                        cloud_elem.attr('style', 'height:2.5em');
                    }
                    $.each(locks, function(index, lock) {
                        let background_color = 'red';
                        let link_color = 'white';
                        if (lock[2] == 'O') {
                            if (open) {
                                background_color = '#00FFFF';
                            } else {
                                background_color = '#00FF00';
                            }
                            link_color = 'black';
                        } else if (locks[2] == 'R') {
                            background_color = 'orange';
                            link_color = 'black';
                        }
                        let link = $('<a></a>', {'title': lock[0], 'style': 'color:' + link_color, 'href': '/rule?rule_id=' + lock[1]});
                        let centered = $('<center></center>');
                        if (open) {
                            centered.text(lock[3]);
                        } else {
                            centered.text(lock[3] + '/' + length);
                        }
                        link.append(centered)
                        cloud_elem.append($('<div></div>', {'style': 'background-color:' + background_color}).append(link));
                    });
                    entry[cloud] = $('<div>').append(cloud_elem).html();
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
