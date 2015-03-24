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

function generateColumnLegend(row, legendIndices) {
  var columnLegend = '';
  for(var index in legendIndices) {
    columnLegend += row[legendIndices[index]]+'\t';
  }
  return columnLegend.trim();
}

function csv2chart(csv, legendIndices, dataColumn, top, aggregate, scale) {
  var data = [],
      dataMatrix = [],
      lines = csv.split('\n'),
      sum = 0,
      entries = 0;

  if (scale == undefined) {
    scale = 1;
  }

  if(aggregate == true) {
    var aData = {};
    for(var i=0; i < lines.length; i++) {
      var cols = lines[i].split('\t');
      if((cols.length < dataColumn) || (isNaN(cols[dataColumn])))
        continue
      legendColumn = (typeof(legendIndices) == typeof(Number())) ? cols[legendIndices] : generateColumnLegend(cols, legendIndices);
      aData[legendColumn] = (aData[legendColumn] == undefined) ? Number(cols[dataColumn]) : aData[legendColumn] + Number(cols[dataColumn])
    }
    for(var item in aData) {
      dataMatrix.push([item, aData[item]]);
    }
  } else {
    for(var i=0; i < lines.length; i++) {
      var cols = lines[i].split('\t');
      if((cols.length < dataColumn) || (isNaN(cols[dataColumn])))
        continue
      legendColumn = (typeof(legendIndices) == typeof(Number())) ? cols[legendIndices] : generateColumnLegend(cols, legendIndices);
      if ((/^Others.*/g).test(legendColumn))  // Data has been aggregated on the server too
        entries = legendColumn.match(/^.*\s+([0-9]+)\)$/)[1];
      dataMatrix.push([legendColumn, Number(cols[dataColumn])]);
    }
  }

  for(var i=0; i < dataMatrix.length; i++) {
    var cols = dataMatrix[i];
    if ((top == undefined || i <= top) && (!(/^Others.*/g).test(cols[0]) || top == undefined)) { data.push([cols[0], scale*cols[1]]); }
    else { sum += scale*cols[1]; }
  }
  data.sort(function(a,b) { return (b[1] - a[1]);});
  if (sum != 0) data.push(["Others (Pos: "+top+" - "+(entries == 0 ? dataMatrix.length : entries)+")", sum]);;
  return data;
}

function drawDoubleChart(traget, title, main, sub, series, top) {
  var colors = Highcharts.getOptions().colors,
      data = {},
      mainData = [],
      subData = [],
      mainCategoryCounter = 0,
      j,
      total = 0,
      drillDataLen,
      brightness;

  // Data drill-down into subcategories
  for(var i=0; i < series.length; i++) {
    var label = series[i][0],
        value = series[i][1],
        mainLabel = label.match(main.pattern)[1];
    
    if (data[mainLabel] == undefined)
      data[mainLabel] = { y: 0,
                          color: colors[i],
                          drilldown: { name: mainLabel,
                                       categories: [],
                                       data: [],
                                       color: colors[mainCategoryCounter++],
                                     },
                          total: 0
                        };
      data[mainLabel].y += value;
      data[mainLabel].drilldown.categories.push(label.match(sub.pattern)[1]);
      data[mainLabel].drilldown.data.push(value);
      total += value;
  }

  if(Number(top)) {  // Aggregate each category to have less values
    for(var category in data) {
      // Sorting (BubbleSort)
      var swapped, tmp, othersTotal = 0,
          values = data[category].drilldown.data,
          labels = data[category].drilldown.categories;
      do {
        swapped = false;
        for(var index=0; index < values.length-1; index++) {
          if(values[index] < values[index+1]) {
            tmp = values[index+1];
            values[index+1] = values[index];
            values[index] = tmp;
            tmp = labels[index+1];
            labels[index+1] = labels[index];
            labels[index] = tmp;
          }
        }
      } while(swapped);
      // Selecting top N entries
      data[category].drilldown.data = values.slice(0,top);
      data[category].drilldown.categories = labels.slice(0,top);
      for(var i=0, others=values.slice(top); i < others.length; i++) {
        othersTotal += others[i];
      }
      if (othersTotal) {
        data[category].drilldown.data.push(othersTotal);
        data[category].drilldown.categories.push('Others');
      }
    } 
  } 

  // creating data series
  for (var mainCategory in data) {
    var subCategoriesCounter = data[mainCategory].drilldown.data.length;
    mainData.push({ name: mainCategory,
                    y: data[mainCategory].y,
                    color: data[mainCategory].color
                  });
    for(var j = 0; j < subCategoriesCounter; j++) {
      brightness = 0.2 - (j / subCategoriesCounter) / 5;
      subData.push({ name: data[mainCategory].drilldown.categories[j],
                     y: data[mainCategory].drilldown.data[j],
                     color: Highcharts.Color(data[mainCategory].color).brighten(brightness).get()
                   });      
    }
  }
  
  // Create the chart
  $(traget).highcharts({
      chart: {
          type: 'pie'
      },
      title: {
          text: title
      },
      yAxis: {
          title: {
              text: 'Share in Percent'
          }
      },
      plotOptions: {
          pie: {
              shadow: false,
          }
      },
      series: [{
          name: main.name,
          data: mainData,
          animation: false,
          size: '60%',
          dataLabels: {
              formatter: function () {
                  return (100/total*this.y) > 10 ? this.point.name : null;
              },
              color: 'white',
              distance: -20
          }
      }, {
          name: sub.name,
          data: subData,
          size: '70%',
          innerSize: '80%',
          animation: false,
          dataLabels: {
              formatter: function () {
                  // display only if larger than 1
                  return (100/total*this.y) > 1 ? '<b>' + this.point.name + ':</b> ' + (100/total*this.y).toFixed(2) + '%'  : null;
              }
          }
      }]
  });
}

function drawChartH(target, title, series, layout) {
  $(target).highcharts({
    chart: {
      plotBackgroundColor: null,
      plotBorderWidth: null,
      spacingLeft: 30,
      spacingRight: 30,
      plotShadow: false
    },
    title: {
      text: title
    },
    tooltip: {
      pointFormat: '{point.y:.1f} ({point.percentage:.1f}%)'
    },
    plotOptions: {
      pie: {
        allowPointSelect: true,
        cursor: 'pointer',
        dataLabels: { enabled: false },
        showInLegend: true
      }
    },
    legend: {
      layout: 'horizontal',
      align: 'center',
      useHTML: true,
      verticalAlign: 'bottom',
      labelFormatter: function() {
        var text = this.name;
        var formatted = text.length > 30 ? text.substring(0, 20) + '...' : text;
        return '<div style="width:; overflow:hidden" title="' + text + ' (Num. Hits: ' + this.y + ')">' + formatted + '</div>';
      }
    },
    series: [{ type: 'pie', data: series, animation: false, size: '70%' }]
  });
}

function drawChartV(target, title, series, layout) {
  $(target).highcharts({
    chart: {
      plotBackgroundColor: null,
      plotBorderWidth: null,
      spacingLeft: 30,
      spacingRight: 30,
      plotShadow: false
    },
    title: {
      text: title
    },
    tooltip: {
      pointFormat: '{point.y:.1f} ({point.percentage:.1f}%)'
    },
    plotOptions: {
      pie: {
        allowPointSelect: true,
        cursor: 'pointer',
        dataLabels: { enabled: false },
        showInLegend: true
      }
    },
    legend: {
      layout: 'vertical',
      align: 'left',
      useHTML: true,
      verticalAlign: 'middle',
      labelFormatter: function() {
        var text = this.name;
        var formatted = text.length > 30 ? text.substring(0, 20) + '...' : text;
        return '<div style="width:; overflow:hidden" title="' + text + ' (Num. Hits: ' + this.y + ')">' + formatted + '</div>';
      }
    },
    series: [{ type: 'pie', data: series, animation: false, size: '90%' }]
  });
}

function initDatePicker(selectCallback) {
  var reportDate = url_param('date');
  $(".datepicker-tab").each(function() { $(this).datepicker({
    onSelect: function() {
      reportDate = $(this).val();
      selectCallback(reportDate);
    },
    dateFormat: "yy-mm-dd",
    maxDate: new Date(),
    numberOfMonths: 1,
    showOn: "focus",
  })});

  if (reportDate != '') {
    $(".datepicker-tab").each(function() { $(this).datepicker("setDate", reportDate) });
  } else {
    var yesterday = new Date((new Date()).setDate((new Date).getDate() -1));
    $(".datepicker-tab").each( function() { $(this).datepicker('setDate', yesterday); });
    reportDate = $(".datepicker-tab").val();
  }
}

function syncTabs(summaryTableSelector) {
  $('div.vertical-menu > ul > li').each(function() {
    $(this).click(function() {
      var id = $(this).attr('id');
      if (id == undefined) return;
      $('div.vertical-menu > ul > li').each(function() {
        $(this).removeClass('active');
      });
      $(this).addClass('active');
      $('div.tabs-content > section').each(function() {
        var panelID = $(this).attr('id');
        if (RegExp(id+'$', 'i').test(panelID)) {
          $(this).addClass('active');
        } else {
          $(this).removeClass('active');
        }
      });
      $('#drilldowns > li.active > a').first().click();
      //Toggeling columns in summary table
      summaryTable =  $(summaryTableSelector).DataTable();
      summaryTable.columns([1,2,3]).visible(false);;
      summaryTable.column($(this).attr('data-column')).visible(true);
      summaryTable.column($(this).attr('data-column')).order('desc');
      summaryTable.draw();
    });
  });
}

