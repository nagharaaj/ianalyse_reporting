
<script type="text/javascript">
         $(document).ready(function () {
             var theme = 'base';
             var classWon = 'stage-won';
             var classLost = 'stage-lost';
             var classLive = 'stage-live';
             // renderer for grid cells.
             var numberrenderer = function (row, column, value) {
                 return '<div style="text-align: center; margin-top: 5px;">' + (1 + value) + '</div>';
             }
             var estimatedRevenueColumnTitle = '<?php echo 'iP '. date('Y') . ' Estimated Revenue';?>';
             var actualRevenueColumnTitle = '<?php echo 'iP '. (date('Y')-1) . ' Actual Revenue';?>';
             var fiscalRevenueColumnTitle = '<?php echo 'Fiscal Yr. '. date('Y') . ' Revenue'; ?>';
             var cities = jQuery.parseJSON('<?php echo $cities; ?>');
             var arrCities = $.map(cities, function(el) { return el; });
             var markets = jQuery.parseJSON('<?php echo $markets; ?>');
             var arrMarkets = new Array();
             var regions = jQuery.parseJSON('<?php echo $regions; ?>');
             var arrRegions = $.map(regions, function(el) { return el; });
             var currencies = jQuery.parseJSON('<?php echo $currencies; ?>');
             var currYear = '<?php echo $current_year; ?>';
             var userRole = '<?php echo $userRole;?>';
             var widthPreferences = jQuery.parseJSON('<?php echo $widthPreferences; ?>');
             var arrCurrencies = new Array();
             var months = [
                     {value: 1, label: "Jan (1)"},
                     {value: 2, label: "Feb (2)"},
                     {value: 3, label: "Mar (3)"},
                     {value: 4, label: "Apr (4)"},
                     {value: 5, label: "May (5)"},
                     {value: 6, label: "Jun (6)"},
                     {value: 7, label: "Jul (7)"},
                     {value: 8, label: "Aug(8)"},
                     {value: 9, label: "Sep (9)"},
                     {value: 10, label: "Oct (10)"},
                     {value: 11, label: "Nov (11)"},
                     {value: 12, label: "Dec (12)"}
             ];
             var monthsSource =
             {
                 datatype: "array",
                 datafields: [
                     { name: 'label', type: 'string' },
                     { name: 'value', type: 'number' }
                 ],
                 localdata: months
             };
             var monthsAdapter = new $.jqx.dataAdapter(monthsSource, {
                autoBind: true
             });

             var calculateStats = function () {
                var dataRows = $('#jqxgrid').jqxGrid('getrows');
                var rowscount = dataRows.length;
                $('#no_of_records span').text(rowscount);
                var totalClients = new Array();
                for(var i = 0; i < rowscount; i++) {
                       if($.inArray(dataRows[i].ClientName, totalClients) == -1) {
                               totalClients.push(dataRows[i].ClientName);
                       }
                }
                $('#no_of_clients span').text(totalClients.length);
             }

             var horizontalScroll=function(){
                 var mousewheel = (/Firefox/i.test(navigator.userAgent)) ? "DOMMouseScroll" : "mousewheel" //FF doesn't recognize mousewheel as of FF3.x
                 $("#jqxScrollWraphorizontalScrollBarjqxgrid").bind(mousewheel, function(e) {
                        e.preventDefault();
                        var position = $('#jqxgrid').jqxGrid('scrollposition');
                        var left = position.left;
                        var top = position.top;
                        var evt = window.event || e //equalize event object
                        evt = evt.originalEvent ? evt.originalEvent : evt; //convert to originalEvent
                        var delta = evt.detail ? evt.detail*(-40) : evt.wheelDelta //check for it is used by Opera and FF
                        if(delta > 0) {
                                top=top+45;
                                left=left-25;
                                $('#jqxgrid').jqxGrid('scrolloffset',top,left);
                        } else {
                                top=top-45;
                                left=left+25;
                                $('#jqxgrid').jqxGrid('scrolloffset', top,left);
                        }
                });
             }

             var source =
             {
                dataType: "json",
                id: 'id',
                url: "/reports/get_currentclient_report_data/",
                datafields: [
                    { name: 'RecordId', type: 'number' },
                    { name: 'Region', type: 'string' },
                    { name: 'Country', type: 'string' },
                    { name: 'City', type: 'string' },
                    { name: 'LeadAgency', type: 'string' },
                    { name: 'ClientName', type: 'string' },
                    { name: 'ParentCompany', type: 'string' },
                    { name: 'ClientCategory', type: 'string' },
                    { name: 'PitchStart', type: 'string' },
                    { name: 'PitchStage', type: 'string' },
                    { name: 'ClientSince', type: 'string' },
                    { name: 'Lost', type: 'string' },
                    { name: 'Service', type: 'string' },
                    { name: 'MarketScope', type: 'string' },
                    { name: 'ActiveMarkets', type: 'string' },
                    { name: 'Currency', type: 'string' },
                    { name: 'EstimatedRevenue', type: 'number' },
                    { name: 'FiscalRevenue',type:'number'},
                    { name: 'ActualRevenue', type: 'number' },
                    { name: 'Comments', type: 'string' },
                    { name: 'Year', type: 'number' },
                    { name: 'ParentId', type: 'number' },
                    { name: 'Created', type: 'date' },
                    { name: 'Modified', type: 'date' },
                    { name: 'SearchClientName', type: 'string' },
                    { name: 'SearchParentCompany', type: 'string' }
                ],
                addRow: function (rowID, rowData, position, commit) {
                    // synchronize with the server - send insert command
                    // call commit with parameter true if the synchronization with the server is successful
                    // and with parameter false if the synchronization failed.
                    // you can pass additional argument to the commit callback which represents the new ID if it is generated from a DB.
                    commit(true);
                },
                updateRow: function (rowID, rowData, commit) {
                    // synchronize with the server - send update command
                    // call commit with parameter true if the synchronization with the server is successful
                    // and with parameter false if the synchronization failed.
                    commit(true);
                },
                deleteRow: function (rowID, commit) {
                    // synchronize with the server - send delete command
                    // call commit with parameter true if the synchronization with the server is successful
                    // and with parameter false if the synchronization failed.
                    commit(true);
                }
             };

             var dataAdapter = new $.jqx.dataAdapter(source);
             var cellclass = function (row, datafield, value, rowdata) {
                var stage = rowdata.PitchStage;
                if(stage.match(/Won/g) || stage == 'Current client') {
                        return classWon;
                } else if (stage.match(/Lost/g)) {
                        return classLost;
                } else if (stage.match(/Live/g)) {
                        return classLive;
                } else {
                        return '';
                }
             }
             var clientNameFilterInput;
             var parentCompanyFilterInput;
             var buildFilterPanel = function (filterPanel, datafield) {
                var textInput = $("<input style='margin:5px;'/>");
                var applyinput = $("<div class='filter' style='height: 25px; margin-left: 20px; margin-top: 7px;'></div>");
                var filterbutton = $('<span tabindex="0" style="padding: 4px 12px; margin-left: 2px;">Filter</span>');
                applyinput.append(filterbutton);
                var filterclearbutton = $('<span tabindex="0" style="padding: 4px 12px; margin-left: 5px;">Clear</span>');
                applyinput.append(filterclearbutton);
                filterPanel.append(textInput);
                filterPanel.append(applyinput);
                filterbutton.jqxButton({ theme: theme, height: 20 });
                filterclearbutton.jqxButton({ theme: theme, height: 20 });
                var column = $("#jqxgrid").jqxGrid('getcolumn', datafield);
                textInput.jqxInput({ theme: theme, placeHolder: "Enter " + column.text, popupZIndex: 9999999, displayMember: datafield, /*source: dataadapter,*/ height: 23, width: 155 });
                if(column.text == 'Parent Company') {
                        parentCompanyFilterInput = textInput;
                } else {
                        clientNameFilterInput = textInput;
                }
                textInput.keyup(function (event) {
                    if (event.keyCode === 13) {
                        filterbutton.trigger('click');
                    }
                });
                filterbutton.click(function () {
                    var filtergroup = new $.jqx.filter();
                    var filter_or_operator = 1;
                    var filtervalue = removeSpecialChars(textInput.val());
                    var filtercondition = 'contains';
                    var filter1 = filtergroup.createfilter('stringfilter', filtervalue, filtercondition);
                    filtergroup.addfilter(filter_or_operator, filter1);
                    // add the filters.
                    $("#jqxgrid").jqxGrid('addfilter', "Search"+datafield, filtergroup);
                    // apply the filters.
                    $("#jqxgrid").jqxGrid('applyfilters');
                    $("#jqxgrid").jqxGrid('closemenu');
                });
                filterbutton.keydown(function (event) {
                    if (event.keyCode === 13) {
                        filterbutton.trigger('click');
                    }
                });
                filterclearbutton.click(function () {
                    $("#jqxgrid").jqxGrid('removefilter', "Search"+datafield);
                    // apply the filters.
                    $("#jqxgrid").jqxGrid('applyfilters');
                    $("#jqxgrid").jqxGrid('closemenu');
                    textInput.val("");
                });
                filterclearbutton.keydown(function (event) {
                    if (event.keyCode === 13) {
                        filterclearbutton.trigger('click');
                    }
                    textInput.val("");
                });
             }
             // initialize jqxGrid
             $("#jqxgrid").jqxGrid(
             {
                width: (parseInt(screen.availWidth) - 30),
                rowsheight:45,
                height:'600',
                source: dataAdapter,
                enablemousewheel: true,
                pageable: false,
                pageSize: 20,
                pagerMode: 'simple',
                sortable: true,
                filterable: true,
                editable: false,
                autoRowHeight: false,
                columnsresize: true,
                autoshowfiltericon:true,
                autoshowcolumnsmenubutton: false,
                showpinnedcolumnbackground: false,
                enablehover: false,
                columnmenuopening: function (menu, datafield, height) {
                    var column = $("#jqxgrid").jqxGrid('getcolumn', datafield);
                    if (column.filtertype === "custom") {
                            menu.height(155);
                        setTimeout(function () {
                            menu.find('input').focus();
                        }, 25);
                    }
                    else menu.height(height);
                },
                columns: [
                  { text: 'RecordId', datafield: 'RecordId', hidden: true },
                  { text: 'ParentId', datafield: 'ParentId', hidden: true },
                  { text: 'Created', datafield: 'Created', hidden: true },
                  { text: 'Modified', datafield: 'Modified', hidden: true },
                  { text: 'Year', datafield: 'Year', hidden: true },
                  { text: '', datafield: 'SearchClientName', hidden: true },
                  { text: '', datafield: 'SearchParentCompany', hidden: true },
                  { text: 'Region', datafield: 'Region', width: 100, cellClassName: cellclass, filtertype: 'checkedlist', filteritems: arrRegions, pinned: true },
                  { text: 'Country', datafield: 'Country', width: 120, cellClassName: cellclass, filtertype: 'checkedlist', pinned: true },
                  { text: 'City', datafield: 'City', width: 120, cellClassName: cellclass, filtertype: 'checkedlist', pinned: true },
                  { text: 'Client', columngroup: 'ClientName', datafield: 'ClientName', width: 250, cellClassName: cellclass, pinned: true, filtertype: 'custom',
                      createfilterpanel: function (datafield, filterPanel) {
                          buildFilterPanel(filterPanel, datafield);
                      }
                  },
                  { text: 'Parent Company', columngroup: 'ParentCompany', datafield: 'ParentCompany', width: 250, cellClassName: cellclass, filtertype: 'custom',
                      createfilterpanel: function (datafield, filterPanel) {
                          buildFilterPanel(filterPanel, datafield);
                      }
                  },
                  { text: 'Client Category', datafield: 'ClientCategory', width: 200, cellClassName: cellclass, filtertype: 'checkedlist' },
                  { text: 'Lead Agency', datafield: 'LeadAgency', width: 130, cellClassName: cellclass, filtertype: 'checkedlist' },
                  { text: 'Status', columntype: 'template', datafield: 'PitchStage', width: 130, cellClassName: cellclass, filtertype: 'checkedlist' },
                  { text: 'Service', datafield: 'Service', width: 150, cellClassName: cellclass, filtertype: 'checkedlist' },
                  { text: 'Client Since (M-Y)', datafield: 'ClientSince', width: 140, cellClassName: cellclass, filtertype: 'date', cellsformat: 'MM/yyyy', editable: false },
                  { text: 'Lost Since (M-Y)', datafield: 'Lost', width: 140, cellClassName: cellclass, filtertype: 'date', cellsformat: 'MM/yyyy', editable: false },
                  { text: 'Pitched (M-Y)', datafield: 'PitchStart', width: 140, cellClassName: cellclass, filtertype: 'date', cellsformat: 'MM/yyyy', editable: false},
                  { text: 'Scope', datafield: 'MarketScope', width: 100, cellClassName: cellclass, filtertype: 'checkedlist', editable: false },
                  { text: 'Active Markets', columngroup: 'ActiveMarkets', datafield: 'ActiveMarkets', width: 160, cellClassName: cellclass, filtertype: 'checkedlist' },
                  { text: 'Currency', datafield: 'Currency', width: 100, cellClassName: cellclass, filtertype: 'checkedlist', hidden: ((userRole == 'Viewer') ? true : false) },
                  { text: estimatedRevenueColumnTitle, columngroup: 'EstimatedRevenue', datafield: 'EstimatedRevenue', width: 200, align: 'left', cellsalign: 'right', cellClassName: cellclass, cellsFormat: 'f2', hidden: ((userRole == 'Viewer') ? true : false) },
                  { text: fiscalRevenueColumnTitle, columngroup: 'FiscalRevenue',datafield: 'FiscalRevenue',width: 200, align: 'left', cellsalign: 'right', cellClassName: cellclass, cellsFormat: 'f2', hidden: ((userRole == 'Viewer') ? true : false)},
                  { text: actualRevenueColumnTitle, columngroup: 'ActualRevenue', datafield: 'ActualRevenue', width: 200, align: 'left', cellsalign: 'right', cellClassName: cellclass, cellsFormat: 'f2', hidden: ((userRole == 'Viewer') ? true : false) },
                  { text: 'Comments', columngroup: 'Comments', datafield: 'Comments', width: 230, cellClassName: cellclass }
                ],
                ready:function()
                {
                        defaultState = $("#jqxgrid").jqxGrid('savestate');
                        calculateStats();
                        horizontalScroll();
                        var columns = widthPreferences.columns;
                        if(columns) {
                                $.each(columns, function(columnName, columnSettings) {
                                       $('#jqxgrid').jqxGrid('setcolumnproperty',columnName,'width',columnSettings.width);
                                });
                        }
                }
            });
            $("#jqxgrid").on("filter", function (event) {
                    calculateStats();
                    $("#jqxgrid").jqxGrid('setcolumnproperty', 'City', 'filteritems', false);
                    $("#jqxgrid").jqxGrid('setcolumnproperty', 'Country', 'filteritems', false);

                    var paginginfo = $("#jqxgrid").jqxGrid('getpaginginformation');
                    if(paginginfo.pagescount <= 1) {
                        $('#pagerjqxgrid').hide();
                    } else {
                        $('#pagerjqxgrid').show();
                    }

                    var filterGroups = $("#jqxgrid").jqxGrid('getfilterinformation');
                    if(filterGroups.length) {
                        for (var i = 0; i < filterGroups.length; i++) {
                            var filterGroup = filterGroups[i];
                            if(filterGroup.filtercolumn == 'Region') {
                                var arrRegionCountries = new Array();
                                var arrCities = new Array();
                                var filters = filterGroup.filter.getfilters();
                                for (var j = 0; j < filters.length; j++) {
                                    $.map(markets[filters[j].value], function(el) {
                                            arrRegionCountries.push(el);
                                            $.map(cities[el], function(elm) { arrCities.push(elm); });
                                    });
                                }
                                arrRegionCountries.sort();
                                $("#jqxgrid").jqxGrid('setcolumnproperty', 'Country', 'filteritems', arrRegionCountries);
                                arrCities.sort();
                                $("#jqxgrid").jqxGrid('setcolumnproperty', 'City', 'filteritems', arrCities);
                            }
                            if(filterGroup.filtercolumn == 'Country') {
                                var arrCities = new Array();
                                var filters = filterGroup.filter.getfilters();
                                for (var j = 0; j < filters.length; j++) {
                                    $.map(cities[filters[j].value], function(el) { arrCities.push(el); });
                                }
                                arrCities.sort();
                                $("#jqxgrid").jqxGrid('setcolumnproperty', 'City', 'filteritems', arrCities);
                            }
                        }
                    }
            });
            $('#jqxgrid').jqxGrid({ rendered: function() {
                    var paginginfo = $("#jqxgrid").jqxGrid('getpaginginformation');
                    if(paginginfo.pagescount <= 1) {
                        $('#pagerjqxgrid').hide();
                    } else {
                        $('#pagerjqxgrid').show();
                    }
                }
            });
            $("#jqxgrid").on("columnresized", function (event) {
                    var state=null;
                    state = $("#jqxgrid").jqxGrid('savestate');
                    var obj=[];
                    obj= {
                            state:state,
                            formname:'current_client_report'
                         };
                    $.ajax({
                            type: "POST",
                            url: "/reports/user_grid_preferences/",
                            data: JSON.stringify(obj),
                            contentType: "application/json; charset=utf-8",
                            dataType: "json"
                    });
            });

            $('#clearfilteringbutton').jqxButton({ theme: theme });
            $('#exporttoexcelbutton').jqxButton({ theme: theme });
            $('#exportButton').jqxButton({ theme: theme });
            $('#cancelExportButton').jqxButton({ theme: theme });
            $('#selectcurrencybutton').jqxButton({ theme: theme });
            $('#changeCurrencyButton').jqxButton({ theme: theme });
            $('#cancelCurrencyButton').jqxButton({ theme: theme });
            // clear the filtering.
            $('#clearfilteringbutton').click(function () {
                $("#jqxgrid").jqxGrid('clearfilters');
                if(clientNameFilterInput)
                        clientNameFilterInput.val("");
                if(parentCompanyFilterInput)
                        parentCompanyFilterInput.val("");
                calculateStats();
                $.ajax({
                    type: "POST",
                    url: "/reports/delete_grid_preferences/",
                    contentType: "application/json; charset=utf-8",
                    dataType: "json",
                    data: JSON.stringify({
                        formname: 'current_client_report'
                    })
                });
                $('#jqxgrid').jqxGrid('loadstate', defaultState);
            });

            $("#popupWindow").jqxWindow({
                width: 320, resizable: false,  isModal: true, autoOpen: false, maxWidth: 400, maxHeight: 250, showCloseButton: false, keyboardCloseKey: 'none'
            });
            $('#exporttoexcelbutton').click(function () {
                if(userRole == 'Viewer' || userRole == 'Country - Viewer') {
                        $("#popupWindow").jqxWindow({ title: 'Export to excel', position: { x: 'center', y: 'top' }, cancelButton: $('#cancelExportButton'), height: "125px", maxWidth: 400, isModal: true, draggable: false });
                        $('#divSetting').hide();
                        $('#divLoader').show();
                        $('#divRevenueCurrency').hide();
                        $("#popupWindow").jqxWindow('open');

                        var rows = $("#jqxgrid").jqxGrid('getrows');
                        var tz = jstz.determine(); // Determines the time zone of the browser client
                        $.ajax({
                            type: "POST",
                            url: "/reports/export_currentclient_data/",
                                data: JSON.stringify({datarows: rows, timezone: tz.name(),
                                currency: $("#exportcurrency option:selected").text(),
                                format: 'excel'
                            }),
                            contentType: "application/json; charset=utf-8",
                            dataType: "json",
                            success : function(result) {
                                if(result.success == true) {
                                    $("#popupWindow").jqxWindow('close');
                                    window.open('/files/' + result.filename);
                                } else {
                                    alert(result.errors);
                                    return false;
                                }
                            }
                        });
                } else {
                        $("#popupWindow").jqxWindow({ title: 'Export to excel/CSV', position: { x: 'center', y: 'top' }, cancelButton: $('#cancelExportButton'), height: "220px", maxWidth: 400, isModal: true, draggable: false });
                        $('#divSetting').show();
                        $('#divLoader').hide();
                        $('#divRevenueCurrency').hide();
                        $("#popupWindow").jqxWindow('open');
                }
            });

            $('#selectcurrencybutton').click(function () {
                $("#popupWindow").jqxWindow({ title: 'Select currency for revenue', position: { x: 'center', y: 'top' }, cancelButton: $('#cancelCurrencyButton'), height: "125px", maxWidth: 400, isModal: true, draggable: false });
                $('#divSetting').hide();
                $('#divLoader').hide();
                $('#divRevenueCurrency').show();
                $("#popupWindow").jqxWindow('open');
            });

            $('#changeCurrencyButton').click(function () {
                var revenueCurrency = $("#revenuecurrency option:selected").text();
                source.data = { revenue_currency : revenueCurrency };
                $("#exportcurrency option").filter(function() {
                    //may want to use $.trim in here
                    return $(this).text() == revenueCurrency;
                }).prop('selected', true);
                $("#statscurrency option").filter(function() {
                    //may want to use $.trim in here
                    return $(this).text() == revenueCurrency;
                }).prop('selected', true);
                $('#jqxgrid').jqxGrid('showloadelement');
                dataAdapter.dataBind();
                calculateStats();
                $("#popupWindow").jqxWindow('close');
            });

            $('#exportButton').click(function () {
                $('#divSetting').hide();
                $('#divLoader').show();
                $('#divRevenueCurrency').hide();

                var rows = $("#jqxgrid").jqxGrid('getrows');
                var exportOpt = $("#exportOption").val();
                var tz = jstz.determine(); // Determines the time zone of the browser client
                $.ajax({
                    type: "POST",
                    url: "/reports/export_currentclient_data/",
                    data: JSON.stringify({datarows: rows, timezone: tz.name(),
                            currency: $("#exportcurrency option:selected").text(),
                            format: $("#exportformat").val(),
                            revenue:$("#exportrevenue option:selected").text(),
                            exportOpt:exportOpt
                    }),
                    contentType: "application/json; charset=utf-8",
                    dataType: "json",
                    success : function(result) {
                        if(result.success == true) {
                            $("#popupWindow").jqxWindow('close');
                            if(exportOpt=="export_email"){
                                    alert(result.message);
                            } else {
                                    window.open('/files/' + result.filename);
                            }
                        } else {
                            alert(result.errors);
                            return false;
                        }
                    }
                });
            });

            var toAppend = '';
            $.each(currencies,function(value,symbol){
                toAppend += '<option value="'+ value +'">'+ symbol +'</option>';
            });
            $('#statscurrency').append(toAppend);
            $('#exportcurrency').append(toAppend);
            $('#revenuecurrency').append(toAppend);
            $('#statscurrency').on('change', function () {
                    calculateStats();
            });
   });
    </script>

<script type="text/javascript">
        $(document).ready(function() {
                $('#tab-menu div#-<?php echo $this->params['controller'].'-'.$this->params['action']; ?>').addClass('selected');
        });
</script>

<div id='jqxWidget'>
        <div style="margin-right: 5px;" align="right">
                <fieldset style="width: 300px; margin-top:2px;">
                        <legend>QUICK STATS</legend>
                        <div id="no_of_records" style="padding-bottom: 5px">Number of records <span style="display: inline-block; width: 70px;"></span></div>
                        <div id="no_of_clients" style="padding-bottom: 5px">Number of Clients <span style="display: inline-block; width: 70px;"></span></div>
                </fieldset>
        </div>
        <div id="tab-menu" align="left">
        <?php
                if($userAcl->check(array('User' => $loggedUser), 'controllers/reports/current_client_report') && !preg_match('/Viewer/', $loggedUser['role'])) {
        ?>
            <div id="-reports-current-client-report" class="light-grey selected">
                    <a href="/reports/current_client_report">SEARCH</a>
            </div>
        <?php
                }
                if($userAcl->check(array('User' => $loggedUser), 'controllers/reports/current_client_data')) {
        ?>
            <div id="-reports-current-client-data" class="light-grey">
                    <a href="/reports/current_client_data">CREATE/UPDATE YOUR RECORDS</a>
            </div>
        <?php
                }
        ?>
            <div style="float: right; margin-top: 35px;">
                <button value="Reset" id="clearfilteringbutton" title="Reset filters">RESET</button>
                <button style="margin-left: 5px" id="selectcurrencybutton" title="Select currency for report">SELECT CURRENCY</button>
                <button style="margin-left: 5px" value="Export to Excel" id="exporttoexcelbutton">EXPORT .XLS</button>
            </div>
        </div>
        <div id="jqxgrid"></div>

        <div id="popupWindow">
                <div>Export to excel</div>
                <div style="overflow: hidden;">
                        <div id="divSetting">
                                <div style="padding-bottom:10px;margin-top: 10px">
                                        Select format:
                                        <select id="exportformat"><option value="Excel">Excel</option><option value="csv">CSV</option></select>
                                </div>
                                <div style="padding-bottom:10px;">
                                        Select currency:
                                        <select id="exportcurrency"><option value="default">Actual currencies</option></select>
                                </div>
                                <div style="padding-bottom:10px;">
                                        Show Revenue values for previous years:
                                        <select id="exportrevenue"><option selected="selected" value="NO">NO</option><option value="YES">YES</option></select>
                                </div>
                                <div style="padding-bottom:10px;">
                                       Export Option:
                                        <select id="exportOption"><option selected="selected" value="export_download">Export and Download</option><option value="export_email">Export and Email</option></select>
                                </div>
                                <div style="float: right; margin-top: 10px">
                                    <button style="margin-bottom: 5px;" id="exportButton">EXPORT</button>
                                    <button id="cancelExportButton">CANCEL</button>
                                </div>
                                <br />
                        </div>
                        <div id="divLoader" align="center" style="display: none; padding-top: 25px; padding-left: 90px;">
                                <div class="jqx-grid-load" style="float: left; overflow: hidden; width: 32px; height: 32px;"></div>
                                <span style="margin-top: 10px; float: left; display: block; margin-left: 5px;">Please wait...</span>
                        </div>
                        <div id="divRevenueCurrency">
                                <div style="padding: 10px 5px">
                                        Select currency:
                                        <select id="revenuecurrency"><option value="default">Actual currencies</option></select>
                                </div>
                                <div style="float: right; margin-top: 10px">
                                    <button style="margin-bottom: 5px;" id="changeCurrencyButton">SUBMIT</button>
                                    <button id="cancelCurrencyButton">CANCEL</button>
                                </div>
                                <br />
                        </div>
                </div>
        </div>
</div>
