/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
 * - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2015
 * - Stefan Prenner, <stefan.prenner@cern.ch>, 2017-2018
 * - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018
 */

html_replicas_base = '<div id="t_replicas" class="columns panel">' +
    '<h4>File Replica States</h4>' +
    '</div>';

html_replicas_table = '<table id="dt_replicas" class="compact stripe order-column" style="word-wrap: break-word;">' +
    '<thead><th>Filename</th><th>Replicas</th></thead>' +
    '<tfoot><th>Filename</th><th>Replicas</th></tfoot>' +
    '</table>' +
    '<div>' +
    '<h5>Color Codes</h5>' +
    '<font color=green>AVAILABLE</font> ' +
    '<font color=red>UNAVAILABLE</font> ' +
    '<font color=orange>COPYING</font> ' +
    '<font color=black>BEING_DELETED</font> ' +
    '<font color=pink>BAD</font> ' +
    '<font color=blue>SOURCE</font> ' +
    '</div>';

html_contents = '<div id="t_contents" class="columns panel">' +
    '<h4>Contents</h4>' +
    '<table id="dt_contents" class="compact stripe order-column cell-border" style="word-wrap: break-word;">' +
    '<thead><th>DID</th><th>DID Type</th></thead>' +
    '<tfoot><th>DID</th><th>DID Type</th></tfoot>' +
    '</table>' +
    '</div>';

html_rules_base = '<div id="t_rules" class="columns panel">' +
    '<h4>Rules</h4>' +
    '<div id="loading_rules" "class="row"><div class="small-1 small-centered columns"><img src="/media/spinner.gif"></div>' +
    '</div>';

html_rules_table = '<table id="dt_rules" class="compact stripe order-column" style="word-wrap: break-word;">' +
    '<thead><th>Rule</th><th>State</th><th>Account</th><th>Subscription</th><th>Last modified</th></thead>' +
    '<tfoot><th>Rule</th><th>State</th><th>Account</th><th>Subscription</th><th>Last modified</th></tfoot>' +
    '</table>';

html_dataset_replicas_base = '<div id="t_dataset_replicas" class="columns panel">' +
    '<h4>Dataset Replicas <a href="#" data-reveal-id="infomodalmeta"><i title="Info" class="step fi-info size-24"></i></a> <span id="meta_button"></span></h4>' +
    '<div id="loading_dataset_replicas" "class="row"><div class="small-1 small-centered columns"><img src="/media/spinner.gif"></div>' +
    '</div>';

html_dataset_replicas_table = '<table id="dt_dataset_replicas" class="compact stripe order-column" style="word-wrap: break-word;">' +
    '<thead><th>RSE</th><th>State</th><th>Available Files</th><th>Available Size</th><th>Creation Date</th><th>Last Accessed</th></thead>' +
    '<tfoot><th>RSE</th><th>State</th><th>Available Files</th><th>Available Size</th><th>Creation Date</th><th>Last Accessed</th></tfoot>' +
    '</table>';

html_parents_base = '<div id="t_parents" class="columns panel">' +
    '<h4>Parent DIDs</h4>' +
    '</div>';

html_parent_dids_table = '<table id="dt_parent_dids" class="compact stripe order-column" style="word-wrap: break-word;">' +
    '<thead><th>DID</th><th>Type</th></thead>' +
    '<tfoot><th>DID</th><th>Type</th></tfoot>' +
    '</table>';

blacklisted_rses = [];


load_parent_dids = function(scope, name) {
    r.list_parent_dids({
        scope: scope,
        name: name,
        success: function(dids) {
            $.each(dids, function(index, did) {
                did.link = '<a href="/did?scope=' + did['scope'] + '&name=' + did['name'] + '">' + did['scope'] + ':' + did['name'] + '</a>';
            });
            $("#t_parents").append(html_parent_dids_table);
            var dt = $('#dt_parent_dids').DataTable( {
                data: dids,
                bAutoWidth: false,
                sEmtpyTable: "No parent dids found",
                columns: [{'data': 'link'},
                          {'data': 'type'}
                         ]
            });
            dt.order([0, 'asc']).draw();
        }, error: function(jqXHR, textStatus, errorThrown) {
            $('#t_parents').append('No parents found for this DID.');
        }
    });
};

load_replicas = function(scope, name) {
    var table_files = [];
    var dav_replicas = [];
    
    $('#load_replicas').html('');
    $('#t_replicas').append('<div id="loader_replicas" "class="row"><div class="small-1 small-centered columns"><img src="/media/spinner.gif"></div>');
    r.list_replicas({
        'scope': scope,
        'name': name,
        success: function(replicas) {
            r.list_replicas({
                'scope': scope,
                'name': name,
                'schemes': ['davs'],
                success: function(ret_dav_replicas) {
                    dav_replicas = ret_dav_replicas;
                    $('#loader_replicas').html('');
                    $('#t_replicas').append(html_replicas_table);
                    var dt2 = $('#dt_replicas').DataTable( {
                        bAutoWidth: false,
                        columns: [{'data': 'name'},
                                  {'data': 'rses'}
                                 ]
                    });
                    //create object that contains all dav rse links which can be queried by replica name      
                    var temp = {};
                    $.each(dav_replicas, function(index, dav_replica) {
                        var key = dav_replica['name'];
                        temp[key] = dav_replica['rses'];
                    });

                    $.each(replicas, function(index, replica) {
                        table_files[replica['name']] = [];
                        var str_rses = "";
                        var sorted_rses = Object.keys(replica['states']).sort();
                        var lfn = replica['scope'] + ':' + replica['name'];
                        var blacklisted = false;
                        var browser_enabled_rse_exists = false;
                        $.each(sorted_rses, function(index, rse) {
                            var state = replica['states'][rse];
                            if (blacklisted_rses.indexOf(rse) != -1) {
                                str_rses += '<i title="This RSE is blacklisted for reading" class="step fi-alert size-18"></i> ';
                                blacklisted = true;
                            }
                            str_rses += "<font color=";
                            if (state == 'AVAILABLE') {
                                str_rses += "green>";
                                try{
                                    if (browser_enabled_rses.indexOf(rse) != -1 && !blacklisted){
                                        var link = temp[replica['name']][rse][0].replace("davs", "https");
                                        str_rses += rse;
                                        if (link.includes(".log")) {
                                            str_rses += "<a href=\"#\" onclick=\"load_logfile('" + link  +"');return false;\"><i title=\"Click to preview " + lfn + " from " + rse  + ".\" class=\"fi-eye size-18\"></i></a> "; 
                                        }
                                        str_rses += " <a href=\"#\" onclick=\"download_file('" + temp[replica['name']][rse][0].replace("davs", "https")  +"', '" + replica['scope']  + "', '" + replica['name'] + "', '" + rse + "', '" + replica['bytes']  + "', '" + scope  + "', '" + name + "');return false;\"><i title=\"Click to download " + lfn + " from " + rse  + ".\" class=\"fi-download size-18\"></i></a> ";
                                        browser_enabled_rse_exists = true;
    		                        } else if(!browser_enabled_rse_exists) {
                                        str_rses += rse + " <span id='non_browser'><a href=\"#\" onclick=\"move_did('" + replica['scope'] + "','" + replica['name'] + "',false,1);return false;\" style=\"color: rgb(128,128,128)\"><i title=\"This RSE is not WebDAV-enabled. Click here to move the file to a WebDAV-enabled RSE.\" class=\"fi-download size-18\"></i></a></span>";
                                    } else {
                                        str_rses += rse;
                                    }
                                } catch(err) {
                                    console.log("An error occurred for RSE " + rse + " : " + err);
                                    str_rses += rse;
                                }
                            } else if (state == 'UNAVAILABLE') {
                                str_rses += "red>" + rse;
                            } else if (state == 'COPYING') {
                                str_rses += "orange>" + rse;
                            } else if (state == 'BEING_DELETED') {
                                str_rses += "black>" + rse;
                            } else if (state == 'BAD') {
                                str_rses += "pink>" + rse;
                            } if (state == 'SOURCE') {
                                str_rses += "blue>" + rse;
                            }
                            str_rses += "</font><br>";
                        });
                        if(browser_enabled_rse_exists) {
                            str_rses = str_rses.replace(/\<span id\=\'non_browser\'\>.*?\<\/span\>\s?/g, '');
                        }
                        browser_enabled_rse_exists = false;
                        dt2.row.add({
                            'name': lfn,
                            'rses': str_rses
                        });
                    });
                    dt2.order([0, 'asc']).draw();
                    $('#dt_replicas_length').find('select').attr('style', 'width: 4em;');
                    $('#dt_replicas_filter').find('input').attr('style', 'width: 10em; display: inline');
                }       
            });
        }
    });
};

download_file = function(link, file_scope, filename, rse, filesize, dataset_scope, dataset) {
    if(typeof(uuid) === 'undefined') {
        console.log('UUID not found, no trace sent.');
        return;
    }
    var options = {
        eventVersion: 'webui_' + get_version(),
        protocol: 'davs',
        uuid: uuid,
        datasetScope: dataset_scope,
        eventType: 'download',
        remoteSite: rse,
        dataset: dataset,
        filename: filename,
        filesize: filesize,
        scope: file_scope,
        clientState: 'DONE',
        success: function(data) {},
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
        }
    };
    r.send_trace(options);
    var element = document.createElement('a');
    element.setAttribute('href', link);
    element.setAttribute('target', '_blank');
    element.setAttribute('download', filename);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
};

uuid4 = function () {
    var uuid = '';
    for (var i = 0; i < 32; i ++) {
        switch (i) {
            case 12:
                uuid += '4';
                break;
            case 16:
                uuid += (Math.random() * 4 | 8).toString(16);
                break;
            default:
                uuid += (Math.random() * 16 | 0).toString(16);
        }
    }
    return uuid;
};

load_logfile = function(input){ 
    $('#infomodal').html('<div id="t_log_modal" class="columns panel">' +
            '<h4>Archive Content</h4>' +
            '<div id="loading_log_modal" "class="row"><div class="small-1 small-centered columns"><img src="/media/spinner.gif"></div>' +
            '</div></div><a class="close-reveal-modal" aria-label="Close">&#215;</a>');
    $('#infomodal').foundation('reveal', 'open');
   
    var jqXHR = $.ajax({
        type: "GET",
        url: "logfiles/load",
        async: false,
        data: {file_location: input},
        dataType: "json",
        success: function(res) {
            var html_modal_table = '<table id="dt_log_modal" class="compact stripe order-column" style="word-wrap: break-word;">' +
        '<thead><th>File</th><th>Compressed Size</th></thead>' +
        '<tfoot><th>File</th><th>Compressed Size</th></tfoot>' +
        '</table>';

    var data = []; 
    $.each(res, function(key, value) {
        var tmp = {};
        tmp['file'] = "<a href=\"#\" onclick=\"extract_logfile('" + input  + "', '" + key + "');return false;\">" + key  + "</a>";
        tmp['size'] = filesize(value, {'base': 10});
        data.push(tmp);
    });
    $('#loading_log_modal').html('');
    $('#t_log_modal').append(html_modal_table);
    dt = $('#dt_log_modal').DataTable( {
        data: data,
       bAutoWidth: false,
       sEmtpyTable: "No archive contents found",
       columns: [{'data': 'file'},
       {'data': 'size'},]
    });
    $('#dt_log_modal_length').find('select').attr('style', 'width: 4em;');
    $('#dt_log_modal_filter').find('input').attr('style', 'width: 10em; display: inline');
    dt.order([0, 'asc']).draw();        
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR.responseText);
        }
    });
    return jqXHR.responseText;
}

extract_logfile = function(link, filename) {
    var tempHtml = $('#infomodal').html();
    var w = window.open();
    $(w.document.body).html('<h1>Loading...</h1>');    

    var jqXHR = $.ajax({
        type: "GET",
        url: "logfiles/extract",
        async: false,
        data: {file_location: link, file_name: filename},
        dataType: "json",
        success: function(res) {
            var str = '';
            if(parseInt(res.size) >= 16000000){
                str = 'Displaying first '+ filesize(parseInt(res.size), {'base': 10}) + ' of the extracted file.';          
            }
            $(w.document.body).html('<h1>Content of ' + filename  + '</h1>' + str + '<textarea style="width:100%;height:40vw;resize:none;">' + res.content + '</textarea>');    
        },
        error: function(jqXHR, textStatus, errorThrown) {
            w.close();
            alert("Could not load preview of this file, please download the archive manually.");
            console.log(jqXHR.status + ': ' + jqXHR.responseText);
        }
    });
}

move_did = function(scope, name, is_dataset, no_of_files, attempt_no) {
    console.log('moving did...'); 
    var options = {
        dids:[{'scope': scope, 'name': name}],
        account:r.account,
        copies:1, 
        lifetime:172800, 
        asynchronous:false, 
        notify:'Y', 
        rse_expression:scratch_rses[get_rse_index(scope + ':' + name + '_' + attempt_no, scratch_rses.length)], 
        success: function(info) {
            console.log('moving did successful!');
            if(is_dataset) {
                alert('Moving ' + no_of_files + ' file(s) in this dataset to WebDAV-enabled RSEs, please come back later. You will be notified via email when all files have been moved.');
            } else {
                alert('File is being moved to a WebDAV enabled RSE (A new replication rule has been created). You will be notified via email when the file has been moved.');
            }
            location.reload();
        }, 
        error: function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR);
            if(!is_dataset && jqXHR.responseJSON.ExceptionClass == 'DuplicateRule') {
                console.log('Rule already exists');
                alert('This file is already being moved.');
                return;
            }
            // try again until attempt_no limit of 3
            if(typeof(attempt_no)==='undefined'){
                attempt_no = 1;
            }
            if(attempt_no < 3) {
                move_did(scope, name, is_dataset, no_of_files, attempt_no + 1);
            } else { alert('An error occurred: Could not move did(s).');}
        }
    };
    if (is_dataset) {
        options['grouping'] = 'DATASET';
    }
    r.create_rule(options);
};

get_rse_index = function(input, array_length) {
    var hash = 0;
    if (input.length == 0) return hash;
    for (i = 0; i < input.length; i++) {
        char = input.charCodeAt(i);
        hash = ((hash<<5)-hash)+char;
        hash = hash & hash; // Convert to 32bit integer                    
    } 
    return Math.abs(hash)%array_length;
};

load_rules = function(scope, name) {
    $('#result_rules').append(html_rules_base);
    r.did_get_rules({
        'scope': scope,
        'name': name,
        success: function(rules) {
            if (rules != '') {
                var data = [];
                rules.forEach(function(rule) {
                    var tmp_sub = '-';
                    if (rule.subscription_id != null) {
                        r.get_subscription_by_id({
                            'id': rule.subscription_id,
                            'async': false,
                            success: function(subscription) {
                                tmp_sub = '<a href="/subscription?name=' + subscription.name + '&account=' + subscription.account + '">' + subscription.name + '</a>';
                            },
                            error: function(jqXHR, textStatus, errorThrown) {
                                console.log(textStatus);
                            }});
                    }
                    rule.rse_expression = '<a href="/rule?rule_id=' + rule.id + '">' + rule.rse_expression + '</a>';
                    if (rule.state == 'OK') {
                        rule.state = "<font color=green>" + rule.state + "</font>";
                    } else if (rule.state == 'REPLICATING') {
                        rule.state = "<font color=orange>" + rule.state + "</font>";
                    } else if (rule.state == 'STUCK') {
                        rule.state = "<font color=RED>" + rule.state + "</font>";
                    }
                    data.push({
                        'rule': rule.rse_expression,
                        'state': rule.state,
                        'account': rule.account,
                        'subscription': tmp_sub,
                        'updated_at': rule.updated_at});
                });
                $('#t_rules').append(html_rules_table);
                var dt = $('#dt_rules').DataTable( {
                    data: data,
                    bAutoWidth: false,
                    sEmtpyTable: "No rules found",
                    columns: [{'data': 'rule'},
                              {'data': 'state'},
                              {'data': 'account'},
                              {'data': 'subscription'},
                              {'data': 'updated_at', 'width': '15em'}]
                });
                $('#dt_rules_length').find('select').attr('style', 'width: 4em;');
                $('#dt_rules_filter').find('input').attr('style', 'width: 10em; display: inline');
                dt.order([0, 'asc']).draw();
                $('#loading_rules').html('');
            } else {
                $('#loading_rules').html('No rules found for this DID.');
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $('#loading_rules').html(errorThrown);
        }
    });
};

load_blacklisting = function(rses) {
    $.each(rses, function(index, rse) {
        r.get_rse({
            'rse': rse,
            success: function(info) {
                if (info['availability_read'] == false) {
                    blacklisted_rses.push(rse);
                    $('#warning_bl_' + rse).show();
                }
            }
        })
    });
}

load_dataset_replicas = function(scope, name) {
    $('#result_dataset_replicas').append(html_dataset_replicas_base);
    var available_dataset_rses = {};

    r.list_dataset_replicas({
        'scope': scope,
        'name': name,
        success: function(replicas) {
            data = [];
            rses = [];
            $.each(replicas, function(index, replica) {
                var tmp = {};
                tmp['rse'] = '<i id="warning_bl_' + replica['rse'] + '" hidden title="This RSE is blacklisted for reading" class="step fi-alert size-18"></i> ' + replica['rse'];
                var state = replica['state'];
                tmp['state'] = '<font color=';
                if (state == 'AVAILABLE') {
                    tmp['state'] += "green>" + state;
                    if(filesize(replica['available_bytes'], {'base': 10}) == reference_size && browser_enabled_rses.indexOf(replica['rse']) != -1){
                        available_dataset_rses[replica['rse']] = {rses: []};
                    }
                } else if (state == 'UNAVAILABLE') {
                    tmp['state'] += "red>" + state;
                } else if (state == 'COPYING') {
                    tmp['state'] += "orange>" + state;
                } else if (state == 'BEING_DELETED') {
                    tmp['state'] += "black>" + state;
                } else if (state == 'BAD') {
                    tmp['state'] += "pink>" + state;
                } if (state == 'SOURCE') {
                    tmp['state'] += "blue>" + state;
                }
                tmp['created_at'] = replica['created_at'];
                tmp['accessed_at'] = replica['accessed_at'];
                tmp['available_bytes'] = filesize(replica['available_bytes'], {'base': 10});
                tmp['available_length'] = replica['available_length'];
                rses.push(replica['rse']);
                data.push(tmp);
            });
            $('#t_dataset_replicas').append(html_dataset_replicas_table);
            var dt = $('#dt_dataset_replicas').DataTable( {
                data: data,
                bAutoWidth: false,
                sEmtpyTable: "No dataset replicas found",
                columns: [{'data': 'rse'},
                          {'data': 'state'},
                          {'data': 'available_length'},
                          {'data': 'available_bytes'},
                          {'data': 'created_at'},
                          {'data': 'accessed_at'}]
            });
            $('#dt_dataset_replicas_length').find('select').attr('style', 'width: 4em;');
            $('#dt_dataset_replicas_filter').find('input').attr('style', 'width: 10em; display: inline');
            dt.order([2, 'asc']).draw();
            $('#loading_dataset_replicas').html('');
            load_blacklisting(rses);
            $('#meta_button').html('<a href="#" onclick="get_metalink(\'' + scope + '\',\'' + name + '\');return false;"><i title="Click to download metalink for this dataset." class="fi-download size-24"></i></a>');         
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $('#loading_rules').html(errorThrown);
        }
    });
};

get_metalink = function(scope, name) { 
    if(typeof(reference_length) === 'undefined' || reference_length == 0) {
        alert('No Files in Dataset.');
        return;
    }
    console.log('Dataset contains files.');
    if(reference_length <= 500){
        $('#meta_button').html('<img src="/media/spinner.gif" height="24" width="24">');
        r.list_replicas({
            'scope': scope,
            'name': name,
            'meta': true,
            'schemes': ['davs'],
            'browser_enabled': true,
            success: function(ret_meta) {
                var meta_files = [];            
                $(ret_meta).find('file').each(function() {
                    meta_files.push($(this).find('identity').text());
                });

                r.list_replicas({
                    'scope': scope,
                    'name': name,
                    success: function(ret) {
                        var dataset_files = [];
                        var files_to_move = [];  
                        $.each(ret, function(index, item) {
                            dataset_files.push({'scope': item['scope'], 'name': item['name']});
                        });
                        //check which of these items are NOT in the metalink and move them
                        $.each(dataset_files, function(index, item) {
                            if(meta_files.indexOf(item['scope'] + ':' + item['name']) == -1) {
                                console.log("move " + item['scope'] + ':' + item['name']);
                                files_to_move.push({'scope': item['scope'], 'name': item['name']});
                            }
                        });    
                        if(files_to_move.length == 0) {
                            console.log('Dataset not moved.');
                            $('#meta_button').html('<a href="#" onclick="get_metalink(\'' + scope + '\',\'' + name + '\');return false;"><i title="Click to download metalink for this dataset." class="fi-download size-24"></i></a>');
                            download('metalink_' + scope + ':' + name + '.meta4', ret_meta.replace(new RegExp('davs', 'g'), 'https'));
                        } else {
                            if(confirm('This will create a new Rucio rule and transfer requests for ' + files_to_move.length + ' files. Do you want to proceed?')){
                                console.log(files_to_move);
                                create_and_move_dataset('user.' + r.account, name, files_to_move);
                            }
                        }
                        $('#meta_button').html('<a href="#" onclick="get_metalink(\'' + scope + '\',\'' + name + '\');return false;"><i title="Click to download metalink for this dataset." class="fi-download size-24"></i></a>');   
                    },
                    error: function(jqXHR, textStatus, errorThrown) {
                        console.log(errorThrown);
                        $('#meta_button').html('<a href="#" onclick="get_metalink(\'' + scope + '\',\'' + name + '\');return false;"><i title="Click to download metalink for this dataset." class="fi-download size-24"></i></a>');
                    }
                }); 
            },
            error: function(jqXHR, testStatus, errorThrown){
                console.log(errorThrown);
                $('#meta_button').html('<a href="#" onclick="get_metalink(\'' + scope + '\',\'' + name + '\');return false;"><i title="Click to download metalink for this dataset." class="fi-download size-24"></i></a>');
            }
        });  
    } else {alert('This Dataset contains more than 500 files, no metalink created.');} 
};

download = function(filename, data) {
    var element = document.createElement('a');
    element.setAttribute('href', 'data:application/octet-stream,' + encodeURIComponent(data));
    element.setAttribute('download', filename); 
    element.style.display = 'none';
    document.body.appendChild(element); 
    element.click();   
    document.body.removeChild(element);
};

create_and_move_dataset = function(scope, name, dids) { 
    var found_dataset_list = [];
    var storage_list = [];
   
    var removeDatasetFromStorage = function(ds_scope, ds_name){
        if(!storage.isSet('moving_datasets')){
            console.log('removeDatasetFromStorage: storage not set.');
            return false;
        };
        console.log('Removing ' + ds_scope + ':' + ds_name + ' from storage...');
        var new_dataset_list = $.grep(storage.get('moving_datasets'), function(obj){return obj.id != ds_scope + ':' + ds_name;});
        storage.set('moving_datasets', new_dataset_list);
    };

    if(storage.isSet('moving_datasets')) {
        storage_list = storage.get('moving_datasets');
        var storage_list_cleaned = [];
        var dt = Date.now();
        $.each(storage_list, function(index, item){
            var ts = item['timestamp'];
            // remove datasets from storage that are older than 2.5 days (0.5 days buffer for rules to complete)
            if(dt - ts <= 216000000) {
                var rem = storage_list_cleaned.push(item);
            }
        });
        storage_list = storage_list_cleaned;
        found_dataset_list = $.grep(storage_list, function(obj){return obj.id == scope + ':' + name;}); 
    }

    if(storage.isSet('moving_datasets') && found_dataset_list.length > 0) {     
        console.log('Dataset already exists, getting rule...');
        r.did_get_rules({
            'scope': scope,
            'name': name + '.' + found_dataset_list[0]['timestamp'],
            success: function(data) { 
                // helper function
                var isDidInArray = function(arr, scope, name) {  
                    for (var i = 0; i < arr.length; i++) {
                        if (arr[i].scope === scope && arr[i].name === name) return true; // Return true as soon as the object is found
                    }                 
                    return false; // The object was not found
                };

                if(data.length == 0) {
                    // Dataset exists but (single) rule doesn't, create the rule again 
                    console.log('Dataset rule not found. Listing files attached to existing dataset..');
                    r.did_get_files({
                        'scope': scope,
                        'name': name + '.' + found_dataset_list[0]['timestamp'],
                        success: function(suc) {  
                            // check if all files are correct
                             $.each(dids, function(index, did){                                                                                                                                                                                                                                                                 if(!isDidInArray(suc, did.scope, did.name)){      
                                 console.log('did ' + did.scope + ':' + did.name + ' is not in dataset, reattaching correct files..');
                                 r.detach_dids({
                                     'scope': scope,
                                     'name': name + '.' + found_dataset_list[0]['timestamp'],
                                     'dids': suc,
                                     success: function(data) {
                                         console.log('Successfully detached.');
                                         r.attach_dids({
                                             'scope': scope,
                                             'name': name + '.' + found_dataset_list[0]['timestamp'],
                                             'dids': dids,
                                             success: function(data2) {
                                                 console.log('Attached correct files, moving now...');
                                                 move_did(scope, name + '.' + found_dataset_list[0]['timestamp'], true, dids.length);
                                             },
                                             error: function(jqXHR, textStatus, errorThrown) {
                                                 console.log(jqXHR);
                                                 alert('An error has ocurred: Could not attach correct files to temporary dataset.');
                                             }
                                         });
                                     },
                                     error: function(jqXHR, textStatus, errorThrown) {
                                         console.log(jqXHR);
                                         console.log('Could not detach dids, removing dataset from storage and creating it again...');    
                                         removeDatasetFromStorage(scope, name); 
                                         create_and_move_dataset(scope, name, dids);
                                     }
                                 });
                                 return false; // break out of each loop
                             }
                             if(index == dids.length - 1){
                                 console.log('All necessary files contained in dataset, moving now...');
                                 move_did(scope, name + '.' + found_dataset_list[0]['timestamp'], true, dids.length);
                             }
                             }); 
                        },
                        error: function(jqXHR, textStatus, errorThrown) {
                            console.log(jqXHR);
                            alert('An error has ocurred: Could not get files for dataset.');
                        }
                    }); 
                } else {
                    // Rule exists, check if enough files are being moved 
                    console.log('Dataset rule exists. Checking if files correct...');
                    r.get_replica_lock_for_rule_id({
                        'rule_id': data[0]['id'],
                        success: function(suc) {
                            $.each(dids, function(index, did) {
                                if(!isDidInArray(suc, did.scope, did.name)){ //not all necessary files in rule, remove rule, break loop and create new rule
                                    console.log('Replicating and necessary amount of locks not matching, restarting...');                                
                                    r.delete_replication_rule({
                                        'rule_id': data[0]['id'],
                                        'purge_replicas': false,
                                        success: function(ret){
                                            console.log('Successfully deleted replication rule.');
                                        },
                                        error: function(jqXHR, textStatus, errorThrown){
                                            console.log('Could not delete replication rule.');
                                            console.log(jqXHR);
                                        }
                                    });
                                    removeDatasetFromStorage(scope, name);
                                    create_and_move_dataset(scope, name, dids);
                                    return false; // break out of each loop
                                }
                                if(index == dids.length - 1) { // all dids contained in rule
                                    alert('This Dataset is already being moved. Please come back later.');
                                };
                            });                   
                        },
                        error: function(jqXHR, textStatus, errorThrown) {
                            console.log(jqXHR);
                            alert('An error has ocurred: Could not determine locks for replication rule.');
                        }
                    });
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.log(jqXHR);
                alert('An error has ocurred. Could not check whether rule already exists.');
            }
        });
    } else {
        var ts = Date.now();
        storage_list.push({id: scope + ':' + name, timestamp: ts});
        storage.set('moving_datasets', storage_list);
        r.add_did({
            'scope': scope,
            'name': name + '.' + ts,
            'type': 'DATASET',
            'lifetime': 864000,
            success: function(data) {
                r.attach_dids({
                    'scope': scope,
                    'name': name + '.' + ts,
                    'dids': dids,
                    success: function(data2) {                   
                        move_did(scope, name + '.' + ts, true, dids.length);
                    },
                error: function(jqXHR, textStatus, errorThrown) {
                    console.log(jqXHR);
                    removeDatasetFromStorage(scope, name);
                    alert('An error has ocurred: Could not attach files to newly created temporary dataset.');
                }   
                });
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.log(jqXHR);
                removeDatasetFromStorage(scope, name);
                alert('An error has ocurred: Could not create temporary dataset.');
            }
        });
    }
};

handle_container = function(scope, name) {
    load_rules(scope, name);
    $('#result_contents').append(html_contents);
    $('#result_file_replicas').append(html_replicas_base);
    $('#t_replicas').append('<div id="load_replicas">Click here to load replicas</div>');
    $('#load_replicas').click(function() {
        load_replicas(scope, name);
    });
    r.list_contents({
        'scope': scope,
        'name': name,
        success: function(dids) {
            data = [];
            $.each(dids, function(index, did) {
                did_link = '<a href="/did?scope=' + did['scope'] + '&name=' + did['name'] + '">' + did['scope'] + ':' + did['name'] + '</a>';
                data.push({'did': did_link, 'type': did['type']});
            });
            var dt = $('#dt_contents').DataTable( {
                data: data,
                bAutoWidth: false,
                columns: [{'data': 'did', 'width': '80%'},
                          {'data': 'type', 'width': '20%'}]
            });
            $('#dt_contents_length').find('select').attr('style', 'width: 4em;');
            $('#dt_contents_filter').find('input').attr('style', 'width: 10em; display: inline');
        }, error: function(jqXHR, textStatus, errorThrown) {
            $('#loading').html('<font color="red">Could not list the content for this container.</font>');
        }
    });
};

handle_dataset = function(scope, name) {
    load_rules(scope, name);
    $('#result_file_replicas').append(html_replicas_base);
    load_dataset_replicas(scope, name);
    $('#t_replicas').append('<div id="load_replicas">Click here to load file replicas</div>');
    $('#load_replicas').click(function() {
        load_replicas(scope, name);
    });
};

handle_file = function(scope, name) {
    $('#result').append(html_replicas_base);
    $('#result').append(html_parents_base);
    load_replicas(scope, name);
    load_parent_dids(scope, name);
};

build_page = function() {
    var scope = url_param('scope');
    var name = url_param('name');

    if (name.indexOf(':') > -1) {
        var splits = name.split(":");
        scope = splits[0];
        name = splits[1];
    }

    $('#subbar-details').html('[' + scope + ':' + name + ']');

    r.did_get_metadata({
        'scope': scope,
        'name': name,
        success: function(data) {
            $("#loading").html("");
            if (data == '') {
                $('#result').html('Could not find scope ' + scope);
            } else {
                if (data['bytes'] != undefined) {
                    data['filesize'] = filesize(data['bytes'], {'base': 10});
                    reference_size = filesize(data['bytes'], {'base': 10});
                    delete data['bytes'];
                }
                if (data['length'] != undefined) {
                    reference_length = data['length'];
                }                
                var sorted_keys = Object.keys(data).sort();
                uuid = uuid4()
                if (data['did_type'] == 'CONTAINER') {
                    handle_container(scope, name);
                } else if (data['did_type'] == 'DATASET') {
                    handle_dataset(scope, name);
                } else {
                    handle_file(scope, name);  
                }
                for(var i=0; i<sorted_keys.length; ++i) {
                    if (data[sorted_keys[i]] != undefined) {
                        if (typeof data[sorted_keys[i]] === 'boolean'){
                            if (data[sorted_keys[i]]) {
                                $('#t_metadata').append($('<tr><th>' + sorted_keys[i] + '</th><td style="color: green;">' + data[sorted_keys[i]] + '</td></tr>'));
                            } else {
                                $('#t_metadata').append($('<tr><th>' + sorted_keys[i] + '</th><td style="color: red;">' + data[sorted_keys[i]] + '</td></tr>'));
                            }
                        } else {
                            if (sorted_keys[i] == 'scope') {
                                data[sorted_keys[i]] = "<a href=/search?scope=" + data['scope'] + "&name=undefined>" + data['scope'] + "</a>";
                            } else if (sorted_keys[i] == 'task_id') {
                                data[sorted_keys[i]] = '<a href="http://bigpanda.cern.ch/task/' + data['task_id'] + '/">' + data['task_id'] + '</a>';
                            } else if (sorted_keys[i] == 'panda_id') {
                                data[sorted_keys[i]] = '<a href="http://bigpanda.cern.ch/job?pandaid=' + data['panda_id'] + '">' + data['panda_id'] + '</a>';
                            }
                            $('#t_metadata').append($('<tr><th>' + sorted_keys[i] + '</th><td>' + data[sorted_keys[i]] + '</td></tr>'));
                        }
                    }
                }
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $('#loading').html('<font color="red">Could not find the DID.</font>');
        }
    });

    r.did_get_generic_metadata({
        'scope': scope,
        'name': name,
        success: function(data) {
            $("#loading").html(""); 
            var sorted_keys = Object.keys(data).sort();
            for(var i=0; i<sorted_keys.length; ++i) {
                $('#t_generic_metadata').append($('<tr><th>' + sorted_keys[i] + '</th><td>' + data[sorted_keys[i]] + '</td></tr>'));
            }
            $('#generic_metadata').css('style', 'display: block') 
        },
        error: function(jqXHR, textStatus, errorThrown) {
            //$('#loading').html('<font color="red">Could not find the DID.</font>');
        }
    });
};

$(document).ready(function(){
    ns=$.initNamespaceStorage('rucio_webui_did');
    storage=ns.localStorage;
    
    if ((storage.isSet('expiration') && Date.now() - storage.get('expiration') > 3600000) || !storage.isSet('expiration')) {
        storage.set('expiration', Date.now());
        r.list_rses({
            expression: 'browser_enabled=1&availability_read=1',
            success: function(rses) {
                browser_enabled_rses = [];
                for(i = 0; i < rses.length; i++){
                    browser_enabled_rses[i] = rses[i]['rse'];
                }
            storage.set('browser_enabled_rses', browser_enabled_rses);
            r.list_rses({
                expression: 'browser_enabled=1&availability_read=1&availability_write=1&type=SCRATCHDISK',
                success: function(rses) {
                    scratch_rses = [];
                    for(i = 0; i < rses.length; i++){
                        scratch_rses[i] = rses[i]['rse'];
                    }
                    storage.set('scratch_rses', scratch_rses);
                    console.log("refreshed scratch storage");
                    build_page();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    console.log(jqXHR);
                }
            });
            }
        });
    } else {
        browser_enabled_rses = storage.get('browser_enabled_rses');
        scratch_rses = storage.get('scratch_rses');
        build_page();
    }
});
