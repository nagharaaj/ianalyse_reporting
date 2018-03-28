    <script type="text/javascript">
         var editClick;
         var deleteClick;
         $(document).ready(function () {
             var userRole = '<?php echo $userRole; ?>';
             var estimatedRevenueColumnTitle = '<?php echo 'iP '. date('Y') . ' Estimated Revenue';?>';
             var actualRevenueColumnTitle = '<?php echo 'iP '. (date('Y')-1) . ' Actual Revenue';?>';
             var fiscalRevenueColumnTitle = '<?php echo 'Fiscal Yr. '. date('Y') . ' Revenue'; ?>';
             var cities = jQuery.parseJSON('<?php echo $cities; ?>');
             var arrCities = $.map(cities, function(el) { return el; });
             var categories = jQuery.parseJSON('<?php echo $categories; ?>');
             var arrCategories = $.map(categories, function(el) { return el; });
             var countries = jQuery.parseJSON('<?php echo $countries; ?>');
             var arrCountries = $.map(countries, function(el) { return el; });
             var currencies = jQuery.parseJSON('<?php echo $currencies; ?>');
             var arrCurrencies = $.map(currencies, function(el) { return el; });
             var agencies = jQuery.parseJSON('<?php echo $agencies; ?>');
             var arrAgencies = $.map(agencies, function(el) { return el; });
             var services = jQuery.parseJSON('<?php echo $services; ?>');
             var arrServices = $.map(services, function(el) { return el; });
             var markets = jQuery.parseJSON('<?php echo $markets; ?>');
             var arrMarkets = $.map(markets, function(el) { return el; });
             var regions = jQuery.parseJSON('<?php echo $regions; ?>');
             var arrRegions = $.map(regions, function(el) { return el; });
             var stages = jQuery.parseJSON('<?php echo $stages; ?>');
             var arrStages = $.map(stages, function(el) { return el; });
             var scopes = ['Global', 'Regional', 'Multi-market', 'Local'];
             var widthPreferences_client_data = jQuery.parseJSON('<?php echo $widthPreferences_client_data; ?>');
             var arrMonths = ['Jan (1)', 'Feb (2)', 'Mar (3)', 'Apr (4)', 'May (5)', 'Jun (6)', 'Jul (7)', 'Aug (8)', 'Sep (9)', 'Oct (10)', 'Nov (11)', 'Dec (12)'];
             var currMonth = '<?php echo $currMonth; ?>';
             var currYear = '<?php echo $currYear; ?>';
             var defaultState;
             var localizationobj = {};
             localizationobj.loadtext = "Processing";
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
             var years = [];
             var currDate = new Date();
             var currYear = currDate.getFullYear();
             for(i = 1995; i <= currYear; i++) {
                     years[years.length] = {value: i, label: i.toString()};
             }

             var theme = 'base';
             var classWon = 'stage-won';
             var classLost = 'stage-lost';
             var classLive = 'stage-live';
             // renderer for grid cells.
             var numberrenderer = function (row, column, value) {
                 return '<div style="text-align: center; margin-top: 5px;">' + (1 + value) + '</div>';
             }

             var horizontalScroll=function(){
                 var mousewheel = (/Firefox/i.test(navigator.userAgent)) ? "DOMMouseScroll" : "mousewheel" //FF doesn't recognize mousewheel as of FF3.x
                 $("#jqxScrollWraphorizontalScrollBarjqxgrid").bind(mousewheel, function(e){
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
                id: 'RecordId',
                url: "/reports/get_current_client_data/",
                datafields: [
                    { name: 'RecordId', type: 'number' },
                    { name: 'Region', type: 'string' },
                    { name: 'Country', type: 'string' },
                    { name: 'City', type: 'string' },
                    { name: 'LeadAgency', type: 'string' },
                    { name: 'ClientName', type: 'string' },
                    { name: 'ParentCompany', type: 'string' },
                    { name: 'ClientCategory', type: 'string' },
                    { name: 'PitchStart', type: 'date' },
                    { name: 'PitchStage', type: 'string' },
                    { name: 'ClientMonth', type: 'string' },
                    { name: 'ClientYear', type: 'number' },
                    { name: 'ClientSince', type: 'date' },
                    { name: 'Lost', type: 'date' },
                    { name: 'Service', type: 'string' },
                    { name: 'MarketScope', type: 'string' },
                    { name: 'ActiveMarkets', type: 'string' },
                    { name: 'Currency', type: 'string' },
                    { name: 'EstimatedRevenue', type: 'float' },
                    { name: 'ActualRevenue', type: 'float' },
                    { name: 'FiscalRevenue',type:'float'},
                    { name: 'Comments', type: 'string' },
                    { name: 'ParentId', type: 'number' },
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
                if(stage == 'Current client') {
                        return classWon;
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
                autoheight:false,
                rowsheight:45,
                height:'600',
                source: dataAdapter,
                enablemousewheel: true,
                pageable:false,
                pageSize: 20,
                pagerMode: 'simple',
                sortable: true,
                filterable: true,
                editable: true,
                autoRowHeight:false,
                autoshowfiltericon:true,
                autoshowcolumnsmenubutton: false,
                selectionmode: 'none',
                columnsresize: true,
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
                  {
                      text: '', cellsAlign: 'center', pinned: true, columntype: 'custom', width: 255, sortable: false, dataField: null, filterable: false, editable: false,
                      cellsRenderer: function (row, column, value) {
                          // render custom column.
                          return "<div align='center'><button style='margin-right: 5px;' data-row='" + row + "' class='deleteButtons jqx-rc-all jqx-button jqx-widget jqx-fill-state-normal' onClick='deleteClick(event)'>DELETE</button><button style='margin-right: 5px;' data-row='" + row + "' class='editButtons jqx-rc-all jqx-button jqx-widget jqx-fill-state-normal' onClick='duplicateClick(event)'>DUPLICATE</button><button data-row='" + row + "' class='editButtons jqx-rc-all jqx-button jqx-widget jqx-fill-state-normal' onClick='editClick(event)'>EDIT</button></div>";
                      }
                  },
                  { text: 'RecordId', datafield: 'RecordId', hidden: true },
                  { text: 'ParentId', datafield: 'ParentId', hidden: true },
                  { text: '', datafield: 'SearchClientName', hidden: true },
                  { text: '', datafield: 'SearchParentCompany', hidden: true },
                  { text: 'Region', datafield: 'Region', width: 100, cellClassName: cellclass, filtertype: 'checkedlist', pinned: true, editable: false },
                  { text: 'Country', datafield: 'Country', width: 120, cellClassName: cellclass, filtertype: 'checkedlist', pinned: true, editable: false },
                  { text: 'City', datafield: 'City', width: 120, cellClassName: cellclass, filtertype: 'checkedlist', pinned: true, editable: false },
                  { text: 'Client', datafield: 'ClientName', width: 250, cellClassName: cellclass, pinned: true, editable: false, filtertype: 'custom',
                      createfilterpanel: function (datafield, filterPanel) {
                          buildFilterPanel(filterPanel, datafield);
                      }
                  },
                  { text: 'Parent Company', datafield: 'ParentCompany', width: 250, cellClassName: cellclass, editable: false, filtertype: 'custom',
                      createfilterpanel: function (datafield, filterPanel) {
                          buildFilterPanel(filterPanel, datafield);
                      }
                  },
                  { text: 'Client Category', datafield: 'ClientCategory', width: 200, cellClassName: cellclass, filtertype: 'checkedlist', editable: false },
                  { text: 'Lead Agency', datafield: 'LeadAgency', width: 130, cellClassName: cellclass, filtertype: 'checkedlist', editable: false },
                  { text: 'Status', datafield: 'PitchStage', width: 130, cellClassName: cellclass, filtertype: 'checkedlist', editable: false },
                  { text: 'Service', datafield: 'Service', width: 150, cellClassName: cellclass, filtertype: 'checkedlist', editable: false },
                  { text: 'Client Since (M-Y)', datafield: 'ClientSince', width: 140, cellClassName: cellclass, filtertype: 'custom', cellsformat: 'MM/yyyy', editable: false },
                  { text: 'Lost Since (M-Y)', datafield: 'Lost', width: 140, cellClassName: cellclass, filtertype: 'custom', cellsformat: 'MM/yyyy', editable: false },
                  { text: 'Pitched (M-Y)', datafield: 'PitchStart', width: 140, cellClassName: cellclass, filtertype: 'custom', cellsformat: 'MM/yyyy', editable: false },
                  { text: 'Scope', datafield: 'MarketScope', width: 100, cellClassName: cellclass, filtertype: 'checkedlist', editable: false },
                  { text: 'Active Markets', datafield: 'ActiveMarkets', width: 160, cellClassName: cellclass, filtertype: 'checkedlist', editable: false },
                  { text: 'Currency', datafield: 'Currency', width: 100, cellClassName: cellclass, filtertype: 'checkedlist', editable: false },
                  { text: estimatedRevenueColumnTitle, datafield: 'EstimatedRevenue', width: 200, align: 'left', cellsalign: 'right', cellClassName: cellclass, cellsFormat: 'f2', editable: false },
                  { text: fiscalRevenueColumnTitle,datafield: 'FiscalRevenue',width: 200, align: 'left', cellsalign: 'right', cellClassName: cellclass, cellsFormat: 'f2',editable: false},
                  { text: actualRevenueColumnTitle, datafield: 'ActualRevenue', width: 200, align: 'left', cellsalign: 'right', cellClassName: cellclass, cellsFormat: 'f2', editable: false },
                  { text: 'Expand Data', cellsAlign: 'center', align: "left", columnType: 'none', width: 110, editable: false, sortable: false, dataField: null,filterable:false,autoshowcolumnsmenubutton: true,
                      cellsRenderer: function (row, column, value) {
                          return "<div  align='center' style='margin-top:15px'><button data-row='" + row + "' class='expandButtons jqx-rc-all jqx-button jqx-widget jqx-fill-state-normal' onclick=expandClick(event)>+</button></div>";
                      }
                  },
                  { text: 'Comments', datafield: 'Comments', width: 200, cellClassName: cellclass, editable: false }

                ],

                ready:function()
                {
                        horizontalScroll();
                        defaultState = $("#jqxgrid").jqxGrid('savestate');
                        var columns = widthPreferences_client_data.columns;
                        if(columns) {
                                $.each(columns, function(columnName, columnSettings) {
                                       $('#jqxgrid').jqxGrid('setcolumnproperty',columnName,'width',columnSettings.width);
                                });
                        }
                }
            });
            $("#jqxgrid").on("filter", function (event) {
                    $("#jqxgrid").jqxGrid('setcolumnproperty', 'City', 'filteritems', false);
                    $("#jqxgrid").jqxGrid('setcolumnproperty', 'Country', 'filteritems', false);

                    var paginginfo = $("#jqxgrid").jqxGrid('getpaginginformation');
                    if(paginginfo.pagescount <= 1) {
                        $('#pagerjqxgrid').hide();
                    } else {
                        $('#pagerjqxgrid').show();
                    }

                    if ($(".editButtons").length > 0) {
                        $( ".editButtons" ).each(function( i ) {
                                $(this).parent().parent().css('line-height', $(this).parent().parent().css('height'));
                        });
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
                    $("#jqxgrid").jqxGrid('localizestrings', localizationobj);
                    var paginginfo = $("#jqxgrid").jqxGrid('getpaginginformation');
                    if(paginginfo.pagescount <= 1) {
                        $('#pagerjqxgrid').hide();
                    } else {
                        $('#pagerjqxgrid').show();
                    }

                    if ($(".editButtons").length > 0) {
                        $( ".editButtons" ).each(function( i ) {
                                $(this).parent().parent().css('line-height', $(this).parent().parent().css('height'));
                        });
                    }
                }
            });
            $("#jqxgrid").on("columnresized", function (event){
                    var state=null;
                    state = $("#jqxgrid").jqxGrid('savestate');
                    var obj=[];
                    obj= {
                            state:state,
                            formname:'current_client_data'
                         };
                $.ajax({
                            type: "POST",
                            url: "/reports/user_grid_preferences/",
                            data: JSON.stringify(obj),
                            contentType: "application/json; charset=utf-8",
                            dataType: "json"
                      });
            });

                editClick = function (event) {
                        var target = $(event.target);
                        // get button's value.
                        var value = target.val();
                        // get clicked row.
                        var rowIndex = parseInt(event.target.getAttribute('data-row'));
                        if (isNaN(rowIndex)) {
                            return;
                        }
                        // begin edit.
                        var rules = new Array();
                        var data = $('#jqxgrid').jqxGrid('getrowdata', rowIndex);
                        var recordid = data.RecordId;
                        var parentrecordid = data.ParentId;
                        var clientname = data.ClientName;
                        var parentcompany = data.ParentCompany;
                        var region = data.Region;
                        var country = data.Country;
                        var city = data.City;
                        var leadagency = data.LeadAgency;
                        var clientcategory = data.ClientCategory;
                        var pitchstart = data.PitchStart;
                        var pitchstage = data.PitchStage;
                        var clientsince = data.ClientSince;
                        var lostdate = data.Lost;
                        var service = data.Service;
                        var marketscope = data.MarketScope;
                        var activemarkets = data.ActiveMarkets;
                        var currency = data.Currency;
                        var estimatedrevenue = data.EstimatedRevenue;
                        var fiscalrevenue = data.FiscalRevenue;
                        var actualrevenue = data.ActualRevenue;
                        var comments = data.Comments;

                        var offset = $("#jqxgrid").offset();
                        $("#updateWindow").jqxWindow({ position: { x: 'center', y: 'top' }, height: "750px", maxWidth: 700, isModal: true });
                        $("#updateWindow").attr('data-row', rowIndex);
                        $("#recordid").val(recordid);
                        $("#update_parentrecordid").val(parentrecordid);
                        if(region != null) {
                                $("#divRegion").text(region);
                        } else {
                                $("#divRegion").html('');
                                var inpRegion = $("<div id=\"update_region\"></div>");
                                $("#divRegion").append(inpRegion);
                                $("#update_region").jqxDropDownList({ source: regions }).val(region);
                        }
                        if(country != null) {
                                $("#divEntity").text(country);
                        } else {
                                $("#divEntity").html('');
                                var inpEntity = $("<div id=\"update_nameofentity\"></div>");
                                $("#divEntity").append(inpEntity);
                                $("#update_nameofentity").jqxDropDownList({ source: markets }).val(country);
                        }
                        if(city != null) {
                                $("#divCity").text(city);
                        } else {
                                $("#divCity").html('');
                                var inpCity = $("<div id=\"update_city\"></div>");
                                $("#divCity").append(inpCity);
                                if(country == "Global") {
                                        $("#update_city").jqxDropDownList({ source: ['Global'], checkboxes: false, selectedIndex: 0 });
                                } else if(country.match(/Regional/g)) {
                                        $("#update_city").jqxDropDownList({ source: [country], checkboxes: false, selectedIndex: 0 });
                                } else {
                                        arrCities = cities[country];
                                        $("#update_city").jqxDropDownList({ source: arrCities, checkboxes: false, selectedIndex: -1 });
                                }
                                $("#update_city").val(city);
                        }
                        if(leadagency != null) {
                                $("#divAgency").html('');
                                var inpAgency = $("<div id=\"update_agency\"></div>");
                                $("#divAgency").append(inpAgency);
                                $("#update_agency").jqxDropDownList({ source: agencies }).val(leadagency);
                                rules.push(validator.agency);
                        } else {
                                $("#divAgency").html('');
                                var inpAgency = $("<div id=\"update_agency\"></div>");
                                $("#divAgency").append(inpAgency);
                                $("#update_agency").jqxDropDownList({ source: agencies }).val(leadagency);
                        }
                        $("#divAdvertiser").text(clientname);
                        if(parentcompany != null) {
                                $("#divParentCompany").text(parentcompany);
                        } else {
                                $("#divParentCompany").html('');
                                var inpParentCompany = $("<input type=\"text\" id=\"update_parentcompany\" />");
                                $("#divParentCompany").append(inpParentCompany);
                                $("#update_parentcompany").jqxInput({ height: 25, width: 175 }).val(parentcompany);
                        }
                        if(clientcategory != null) {
                                $("#divCategory").html('');
                                var inpCategory = $("<div id=\"update_category\"></div>");
                                $("#divCategory").append(inpCategory);
                                $("#update_category").jqxDropDownList({ source: categories }).val(clientcategory);
                                rules.push(validator.category);
                        } else {
                                $("#divCategory").html('');
                                var inpCategory = $("<div id=\"update_category\"></div>");
                                $("#divCategory").append(inpCategory);
                                $("#update_category").jqxDropDownList({ source: categories }).val(clientcategory);
                        }
                        if(pitchstart != '') {
                                pitchDate = new Date(pitchstart);
                                $("#divPitchStart").text((pitchDate.getMonth()+1) + '/' + pitchDate.getFullYear());
                        } else {
                                $("#divPitchStart").html('');
                                var inpPitchStart = $("<div id=\"update_pitchstart\"></div>");
                                $("#divPitchStart").append(inpPitchStart);
                                $("#update_pitchstart").jqxDateTimeInput({ formatString: 'MM/yyyy', width: 100, height: 25 });
                        }
                                $("#divPitchStage").html('');
                                var inpPitchStage = $("<div id=\"update_pitchstage\"></div>");
                                $("#divPitchStage").append(inpPitchStage);
                                $("#update_pitchstage").jqxDropDownList({ source: stages }).val(pitchstage);
                                
                                $("#divClientSince").html('');
                                var inpClientSince = $("<div id=\"update_clientsince\"></div>");
                                $("#divClientSince").append(inpClientSince);
                                $("#update_clientsince").jqxDateTimeInput({ formatString: 'MM/yyyy', width: 100, height: 25 });
                                if(pitchstage.match(/Live/g)) {
                                        var clientSince = new Date();
                                        $("#update_clientsince").val(clientSince);
                                } else {
                                        if(clientsince != '') {
                                                var clientSince = new Date(clientsince);
                                        } else {
                                                var clientSince = new Date();
                                        }
                                        $("#update_clientsince").val(clientSince);
                                }
                                rules.push(validator.clientsince);

                        if(pitchstage == 'Current client') {
                                $("#divLostDate").text('No');
                        } else {
                                $("#divLostDate").html('');
                                var inpLostDate = $("<div id=\"update_lostdate\"></div>");
                                $("#divLostDate").append(inpLostDate);
                                $("#update_lostdate").jqxDateTimeInput({ formatString: 'MM/yyyy', width: 100, height: 25 });
                                if(lostdate != '') {
                                        var lostDate = new Date(lostdate);
                                } else {
                                        var lostDate = new Date();
                                }
                                $("#update_lostdate").val(lostDate);
                                rules.push(validator.lostdate);
                        }
                        if(service != null) {
                                $("#divService").html('');
                                var inpService = $("<div id=\"update_service\"></div>");
                                $("#divService").append(inpService);
                                $("#update_service").jqxDropDownList({ source: services }).val(service);
                                rules.push(validator.service);
                        } else {
                                $("#divService").html('');
                                var inpService = $("<div id=\"update_service\"></div>");
                                $("#divService").append(inpService);
                                $("#update_service").jqxDropDownList({ source: services }).val(service);
                        }
                        if(marketscope != null) {
                                $("#update_marketscope").jqxDropDownList({ source: scopes }).val(marketscope);
                        } else {
                                $("#update_marketscope").jqxDropDownList({ source: scopes, selectedIndex: -1 });
                                rules.push(validator.marketscope);
                        }
                        $("#update_activemarket").jqxDropDownList('uncheckAll');
                        $("#update_activemarket").jqxDropDownList({ source: countries, checkboxes: true });
                        var entities = activemarkets.split(',');
                        for(key in entities) {
                                if(arrCountries.indexOf(entities[key]) != -1) {
                                       index = arrCountries.indexOf(entities[key]);
                                       $("#update_activemarket").jqxDropDownList('checkIndex', index);
                                }
                        }
                        rules.push(validator.activemarkets);
                        if(currency != null) {
                                $("#divCurrency").html('');
                                var inpCurrency = $("<div id=\"update_currency\"></div>");
                                $("#divCurrency").append(inpCurrency);
                                $("#update_currency").jqxDropDownList({ source: currencies }).val(currency);
                                rules.push(validator.currency);
                        } else {
                                $("#divCurrency").html('');
                                var inpCurrency = $("<div id=\"update_currency\"></div>");
                                $("#divCurrency").append(inpCurrency);
                                $("#update_currency").jqxDropDownList({ source: currencies }).val(currency);
                        }
                        if(pitchstage.match(/Lost/g)) {
                                $("#divEstRevenue").text(estimatedrevenue);
                                $("#divActualRevenue").text(actualrevenue);
                                $("#divFiscRevenue").text(fiscalrevenue);
                        } else {
                                $("#divEstRevenue").html('');
                                var inpEstRevenue = $("<input type=\"text\" id=\"update_estrevenue\" />");
                                $("#divEstRevenue").append(inpEstRevenue);
                                $("#update_estrevenue").jqxInput({ height: 25, width: 150, rtl:true }).val(estimatedrevenue);
                                if(pitchstage.match(/Won/g) || pitchstage == 'Current client') {
                                        rules.push(validator.estrevenueRequired);
                                        rules.push(validator.estrevenueNumeric);
                                }
                                $("#divFiscRevenue").html('');
                                var inpFiscalRevenue = $("<input type=\"text\" id=\"update_fiscrevenue\" />");
                                $("#divFiscRevenue").append(inpFiscalRevenue);
                                $("#update_fiscrevenue").jqxInput({ height: 25, width: 150, rtl:true }).val(fiscalrevenue);
                                
                                $("#divActualRevenue").html('');
                                var inpActualRevenue = $("<input type=\"text\" id=\"update_actualrevenue\" />");
                                $("#divActualRevenue").append(inpActualRevenue);
                                $("#update_actualrevenue").jqxInput({ height: 25, width: 150, rtl:true }).val(actualrevenue);
                        }
                        $("#update_notes").jqxInput({ height: 25, width: 200 }).val(comments);
                        // show the popup window.
                        $("#updateWindow").jqxWindow('open');
                        $("#update_region").bind('select', function (event) {
                            var args = event.args;
                            var item = $('#update_region').jqxDropDownList('getItem', args.index);
                            if(item != null) {
                                arrRegionCountries = markets[item.label];
                                $("#update_nameofentity").jqxDropDownList({ source: arrRegionCountries, checkboxes: false, selectedIndex: -1 });
                            }
                        });
                        $("#update_nameofentity").bind('select', function (event) {
                            var args = event.args;
                            var item = $('#update_nameofentity').jqxDropDownList('getItem', args.index);
                            if(item != null) {
                                arrCities = cities[item.label];
                                $("#update_city").jqxDropDownList({ source: arrCities, checkboxes: false, selectedIndex: -1 });
                            }
                        });
                        $("#update_pitchstage").bind('select', function (event) {
                                var args = event.args;
                                var item = $('#update_pitchstage').jqxDropDownList('getItem', args.index);
                                if(item != null) {
                                        if(item.label.match(/Won/g) || item.label == "Current client") {
                                                $("#trUpdateClientSince").show();
                                                $("#trUpdatePitchedDate").show();

                                                $("#trUpdateLostSince").hide();
                                        }
                                        else if(item.label.match(/Live/g)) {
                                                $("#trUpdatePitchedDate").show();

                                                $("#trUpdateClientSince").hide();
                                                $("#trUpdateLostSince").hide();
                                        }
                                        else if(item.label.match(/Lost/g)) {
                                                $("#trUpdateLostSince").show();
                                                $("#trUpdatePitchedDate").show();
                                                 if (item.label.match(/current/g)) {
                                                        $("#trUpdateClientSince").show();
                                                 } else {
                                                        $("#trUpdateClientSince").hide();
                                                 }
                                        }
                                        else if(item.label == 'Cancelled' || item.label == 'Declined') {
                                                $("#trUpdateLostSince").show();
                                                $("#trUpdatePitchedDate").show();

                                                $("#trUpdateClientSince").hide();
                                        }
                                }
                        });
                        if(pitchstage == "Current client") {
                                $("#trUpdateClientSince").show();

                                $("#trUpdateLostSince").hide();
                        }
                        $('#updateForm').jqxValidator({ position: 'right', rules: rules});
                }
                duplicateClick = function(event) {
                        var target = $(event.target);
                        // get button's value.
                        var value = target.val();
                        // get clicked row.
                        var rowIndex = parseInt(event.target.getAttribute('data-row'));
                        if (isNaN(rowIndex)) {
                            return;
                        }
                        // begin duplicate.
                        var data = $('#jqxgrid').jqxGrid('getrowdata', rowIndex);
                        var recordid = data.RecordId;
                        var parentrecordid = data.ParentId;
                        var clientname = data.ClientName;
                        var parentcompany = data.ParentCompany;
                        var region = data.Region;
                        var country = data.Country;
                        var city = data.City;
                        var leadagency = data.LeadAgency;
                        var clientcategory = data.ClientCategory;
                        var pitchstart = data.PitchStart;
                        var pitchstage = data.PitchStage;
                        var clientsincemonth = data.ClientMonth;
                        var clientsinceyear = data.ClientYear;
                        var lostdate = data.Lost;
                        var marketscope = data.MarketScope;
                        var activemarkets = data.ActiveMarkets;
                        var currency = data.Currency;
                        var comments = data.Comments;

                        var offset = $("#jqxgrid").offset();
                        $("#popupWindow").jqxWindow({ position: { x: 'center', y: 'top' }, height: "750px", maxWidth: 700, isModal: true });
                        if(parentrecordid == 0 || parentrecordid == null || parentrecordid == '') {
                                $("#parentrecordid").val(recordid);
                        } else {
                                $("#parentrecordid").val(parentrecordid);
                        }
                        $("#region").jqxDropDownList({ source: regions }).val(region);
                        arrRegionCountries = markets[region];
                        $("#nameofentity").jqxDropDownList({ source: arrRegionCountries }).val(country);
                        if(country == "Global") {
                                $("#city").jqxDropDownList({ source: ['Global'], checkboxes: false, selectedIndex: 0 });
                        } else if(country.match(/Regional/g)) {
                                $("#city").jqxDropDownList({ source: [country], checkboxes: false, selectedIndex: 0 });
                        } else {
                                arrCities = cities[country];
                                $("#city").jqxDropDownList({ source: arrCities, checkboxes: false, selectedIndex: -1 });
                        }
                        $("#city").val(city);
                        $("#agency").jqxDropDownList({ source: agencies }).val(leadagency);
                        $("#advertisername").jqxInput({ height: 25, width: 200 }).val(clientname);
                        $("#parentcompany").jqxInput({ height: 25, width: 175 }).val(parentcompany);
                        $("#category").jqxDropDownList({ source: categories }).val(clientcategory);
                        $("#pitchstart").jqxDateTimeInput({ formatString: 'MM/yyyy', width: 100, height: 25 });
                        $("#pitchstage").jqxDropDownList({ source: stages }).val(pitchstage);
                        $("#clientsince").jqxDateTimeInput({ formatString: 'MM/yyyy', width: 100, height: 25 });
                        $("#lostdate").jqxDateTimeInput({ formatString: 'MM/yyyy', width: 100, height: 25 });
                        var lostDate = new Date(lostdate);
                        $("#lostdate").val(lostDate);
                        $("#service").jqxDropDownList({ source: services, selectedIndex: -1 });
                        $("#marketscope").jqxDropDownList({ source: scopes }).val(marketscope);
                        $("#activemarket").jqxDropDownList({ source: countries, checkboxes: true });
                        var entities = activemarkets.split(',');
                        for(key in entities) {
                                if(arrCountries.indexOf(entities[key]) != -1) {
                                       index = arrCountries.indexOf(entities[key]);
                                       $("#activemarket").jqxDropDownList('checkIndex', index);
                                }
                        }
                        $("#currency").jqxDropDownList({ source: currencies }).val(currency);
                        $("#estrevenue").jqxInput({ height: 25, width: 100, rtl:true }).val('');
                        $("#fiscrevenue").jqxInput({ height:25,width:100,rtl:true}).val('');
                        $("#notes").jqxInput({ height: 25, width: 200 }).val(comments);
                        // show the popup window.
                        $("#popupWindow").jqxWindow('open');
                        $("#region").bind('select', function (event) {
                            var args = event.args;
                            var item = $('#region').jqxDropDownList('getItem', args.index);
                            if(item != null) {
                                arrRegionCountries = markets[item.label];
                                $("#nameofentity").jqxDropDownList({ source: arrRegionCountries, checkboxes: false, selectedIndex: -1 });
                            }
                        });
                        $("#nameofentity").bind('select', function (event) {
                            var args = event.args;
                            var item = $('#nameofentity').jqxDropDownList('getItem', args.index);
                            if(item != null) {
                                arrCities = cities[item.label];
                                $("#city").jqxDropDownList({ source: arrCities, checkboxes: false, selectedIndex: -1 });
                            }
                        });
                        $("#pitchstage").bind('select', function (event) {
                                var args = event.args;
                                var item = $('#pitchstage').jqxDropDownList('getItem', args.index);
                                if(item != null) {
                                        if(item.label == "Current client") {
                                                $("#trClientSince").show();
                                                $("#trPitchedDate").show();

                                                $("#trLostSince").hide();
                                        }
                                        else if(item.label.match(/Live/g)) {
                                                $("#trPitchedDate").show();

                                                $("#trClientSince").hide();
                                                $("#trLostSince").hide();
                                        }
                                        else if (item.label.match(/current/g)) {
                                                        $("#trClientSince").show();
                                        }
                                }
                        });
                        if( pitchstage == "Current client") {
                                $("#trClientSince").show();

                                $("#trLostSince").hide();
                        }
                        
                        else if (pitchstage.match(/current/g)) {
                                        $("#trClientSince").show();
                                
                        }
                }
                deleteClick = function (event) {
                    var target = $(event.target);
                    // get button's value.
                    var value = target.val();
                    // get clicked row.
                    var rowIndex = parseInt(event.target.getAttribute('data-row'));
                    if (isNaN(rowIndex)) {
                        return;
                    }
                    var id = $("#jqxgrid").jqxGrid('getrowid', rowIndex);
                    var recordid = $("#jqxgrid").jqxGrid('getCellValue', rowIndex, 'RecordId');
                    var row = { RecordId: recordid };
                    if(confirm('Are you sure to delete this record?')) {
                        $('#jqxgrid').jqxGrid('showloadelement');
                        $.ajax({
                            type: "POST",
                            url: "/reports/delete_client_record/",
                            data: JSON.stringify(row),
                            contentType: "application/json; charset=utf-8",
                            dataType: "json",
                            success : function(result) {
                                if(result.success == true) {
                                    var commit = $("#jqxgrid").jqxGrid('deleterow', id);
                                    $('#jqxgrid').jqxGrid('hideloadelement');
                                } else {
                                    alert(result.errors);
                                    return false;
                                }
                            }
                        });
                    }
                }

                $("#revenueWindow").jqxWindow({position:'center',
                        height:200, width: 400, resizable: false,  isModal: true, autoOpen: false, showCloseButton: true
                });

                expandClick = function (event) {
                        var target = $(event.target);
                        // get button's value.
                        var value = target.val();
                        // get clicked row.
                        var rowIndex = parseInt(event.target.getAttribute('data-row'));
                        if (isNaN(rowIndex)) {
                                return;
                        }
                        var data = $('#jqxgrid').jqxGrid('getrowdata', rowIndex);
                        $('#revClientname').text(data.ClientName);
                        $("#revService").text(data.Service);
                        $('#revCurrency').text(data.Currency);

                        var row = {RecordId: data.RecordId};
                        $("#actualRevenue span").empty();
                        $.ajax({
                                type: 'POST',
                                data:JSON.stringify(row),
                                url: "/reports/get_actual_revenue/",
                                contentType: "application/json; charset=utf-8",
                                dataType: 'json',
                                success: function (result) {
                                        if (result.success==true) {
                                                if(result.data=='') {
                                                        alert("No data found");
                                                } else {
                                                        var table = $('<table>').css({"margin-left" : "4px", "border-collapse" :"collapse"}).attr('border', 1).attr('width', 300);
                                                        $.each(result.data, function (index, value) {
                                                                var tr ='<tr><td>iP '+index+' Actual Revenue</td><td align="right">'+Math.round(value*100)/100 +'</td></tr>';
                                                                $(table).prepend(tr);
                                                        });
                                                        $("#actualRevenue span").append(table);
                                                        //Appending the actual revenue table
                                                        $("#revenueWindow").jqxWindow('open');
                                                }
                                        }
                                }
                        });
                }

            $("#popupWindow").jqxWindow({
                width: 600, resizable: false,  isModal: true, autoOpen: false, cancelButton: $("#CancelNew"), maxWidth: 700, maxHeight: 750, showCloseButton: false
            });
            $("#updateWindow").jqxWindow({
                width: 600, resizable: false,  isModal: true, autoOpen: false, cancelButton: $("#CancelUpdate"), maxWidth: 700, maxHeight: 750, showCloseButton: false
            });
            $(".createNew").jqxButton({ theme: theme });
            $(".createNew").click(function () {
                var offset = $("#jqxgrid").offset();
                $("#popupWindow").jqxWindow({ position: { x: 'center', y: 'top' }, height: "750px", maxWidth: 700, isModal: true });
                $("#parentrecordid").val('');
                $("#region").jqxDropDownList({ source: regions, selectedIndex: -1 });
                $("#nameofentity").jqxDropDownList();
                $("#city").jqxDropDownList();
                $("#agency").jqxDropDownList({ source: agencies, selectedIndex: -1 });
                $("#advertisername").jqxInput({ placeHolder: "Enter a Name", height: 25, width: 200, minLength: 1,
                        source: function (query, response) {
                                var dataAdapter = new $.jqx.dataAdapter
                                (
                                        {
                                                datatype: "json",
                                                type: "POST",
                                                datafields:
                                                [
                                                        { name: 'advertiser_name' },
                                                        { name: 'parent_company' }
                                                ],
                                                url: "/reports/search_client/",
                                                data:
                                                {
                                                        maxRows: 20
                                                }
                                        },
                                        {
                                                autoBind: true,
                                                formatData: function (data) {
                                                        data.name_startsWith = query;
                                                        return data;
                                                },
                                                loadComplete: function (data) {
                                                        if (data.length > 0) {
                                                                response($.map(data, function (item) {
                                                                        return {
                                                                                label: item.advertiser_name + (item.parent_company ? ", " + item.parent_company : ""),
                                                                                value: item.advertiser_name + ", " + item.parent_company
                                                                        }
                                                                }));
                                                        }
                                                }
                                        }
                                );
                        }
                }).val('');
                $("#advertisername").on('select', function (event) {
                    if (event.args) {
                        var item = event.args.item;
                        if (item) {
                            var terms = item.value.split(/,\s*/);
                            $("#advertisername").jqxInput('val', terms[0]);
                            $("#parentcompany").jqxInput('val', terms[1]);
                        }
                    }
                });
                $("#parentcompany").jqxInput({ height: 25, width: 175 }).val('');
                $("#category").jqxDropDownList({ source: categories, selectedIndex: -1 });
                $("#pitchstart").jqxDateTimeInput({ formatString: 'MM/yyyy', width: 100, height: 25 });
                $("#pitchstage").jqxDropDownList({ source: stages, selectedIndex: -1 });
                $("#clientsince").jqxDateTimeInput({ formatString: 'MM/yyyy', width: 100, height: 25 });
                $("#lostdate").jqxDateTimeInput({ formatString: 'MM/yyyy', width: 100, height: 25 });
                $("#service").jqxDropDownList({ source: services, selectedIndex: -1 });
                $("#marketscope").jqxDropDownList({ source: scopes, selectedIndex: -1 });
                $("#activemarket").jqxDropDownList({ source: countries, checkboxes: true, selectedIndex: -1});
                $("#currency").jqxDropDownList({ source: currencies, selectedIndex: -1 });
                $("#estrevenue").jqxInput({ height: 25, width: 100, rtl:true }).val('');
                $("#fiscrevenue").jqxInput({ height: 25, width: 100, rtl:true }).val('');
                $("#notes").jqxInput({ height: 25, width: 200 }).val('');
                // show the popup window.
                $("#popupWindow").jqxWindow('open');
                $("#region").bind('select', function (event) {
                    var args = event.args;
                    var item = $('#region').jqxDropDownList('getItem', args.index);
                    if(item != null) {
                        arrRegionCountries = markets[item.label];
                        $("#nameofentity").jqxDropDownList({ source: arrRegionCountries, checkboxes: false, selectedIndex: -1 });
                    }
                });
                $("#nameofentity").bind('select', function (event) {
                    var args = event.args;
                    var item = $('#nameofentity').jqxDropDownList('getItem', args.index);
                    if(item != null) {
                        arrCities = cities[item.label];
                        $("#city").jqxDropDownList({ source: arrCities, checkboxes: false, selectedIndex: -1 });
                    }
                });
                $("#pitchstage").bind('select', function (event) {
                        var args = event.args;
                        var item = $('#pitchstage').jqxDropDownList('getItem', args.index);
                        if(item != null) {
                                if(item.label == "Current client") {
                                        $("#trClientSince").show();
                                        $("#trPitchedDate").show();
                                        $("#trLostSince").hide();
                                }
                                else if (item.label.match(/current/g)) {
                                                $("#trClientSince").show();
                                }
                        }
                });
            });

            $('#testForm').jqxValidator({ position: 'right', rules: [
                        { input: '#advertisername', message: 'Advertiser name is required!', action: 'keyup, blur', rule: 'required' },
                        { input: '#parentcompany', message: 'Parent company is required!', action: 'keyup, blur', rule: 'required' },
                        { input: '#region', message: 'Region is required!', action: 'change', rule: function (input) {
                                if (input.val() != '') {
                                        return true;
                                }
                                return false;
                            }
                        },
                        { input: '#city', message: 'City is required!', action: 'change', rule: function (input) {
                                if (input.val() != '') {
                                        return true;
                                }
                                return false;
                            }
                        },
                        { input: '#agency', message: 'Lead agency is required!', action: 'change', rule: function (input) {
                                if (input.val() != '') {
                                        return true;
                                }
                                return false;
                            }
                        },
                        { input: '#nameofentity', message: 'Entity is required!', action: 'change', rule: function (input) {
                                if (input.val() != '') {
                                        return true;
                                }
                                return false;
                            }
                        },
                        { input: '#category', message: 'Category is required!', action: 'change', rule: function (input) {
                                if (input.val() != '') {
                                        return true;
                                }
                                return false;
                            }
                        },
                        { input: '#pitchstage', message: 'Stage is required!', action: 'change', rule: function (input) {
                                if (input.val() != '') {
                                        return true;
                                }
                                return false;
                            }
                        },
                        { input: '#clientsince', message: 'Client Since is required!', action: 'change', rule: function (input) {
                                var pitchstage = $('#pitchstage').val();
                                if (( pitchstage == 'Current client') && input.val() == '') {
                                        return false;
                                }
                                return true;
                            }
                        },
                        { input: '#lostdate', message: 'Lost Date is required!', action: 'change', rule: function (input) {
                                var pitchstage = $('#pitchstage').val();
                                if (pitchstage.match(/Lost/g) && input.val() == '') {
                                        return false;
                                }
                                return true;
                            }
                        },
                        { input: '#service', message: 'Service is required!', action: 'change', rule: function (input) {
                                if (input.val() != '') {
                                        return true;
                                }
                                return false;
                            }
                        },
                        { input: '#marketscope', message: 'Scope is required!', action: 'change', rule: function (input) {
                                if (input.val() != '') {
                                        return true;
                                }
                                return false;
                            }
                        },
                        { input: '#activemarket', message: 'Active Market is required!', action: 'change', rule: function (input) {
                                if (input.val() != '') {
                                        return true;
                                }
                                return false;
                            }
                        },
                        { input: '#currency', message: 'Currency is required!', action: 'change', rule: function (input) {
                                if (input.val() != '') {
                                        return true;
                                }
                                return false;
                            }
                        },
                        { input: '#estrevenue', message: 'iP estimated revenue is required!', action: 'keyup, blur', rule: 'required' },
                        { input: '#estrevenue', message: 'iP estimated revenue should be numeric!', action: 'keyup, blur', rule: function (input) {
                                if (!isNaN(parseFloat(input.val())) && isFinite(input.val())) {
                                        return true;
                                }
                                return false;
                            }
                        }
                ]
            });
            $('#clearfilteringbutton').jqxButton({ theme: theme });
            $("#CancelNew").jqxButton({ theme: theme });
            $("#SaveNew").jqxButton({ theme: theme });
            // update the edited row when the user clicks the 'Save' button.
            $('#clearfilteringbutton').click(function () {
                $("#jqxgrid").jqxGrid('clearfilters');
                if(clientNameFilterInput)
                        clientNameFilterInput.val("");
                if(parentCompanyFilterInput)
                        parentCompanyFilterInput.val("");
                $.ajax({
                            type: "POST",
                            url: "/reports/delete_grid_preferences/",
                            contentType: "application/json; charset=utf-8",
                            dataType: "json",
                            data: JSON.stringify({
                                formname: 'current_client_data'
                            })
                      });
                      $('#jqxgrid').jqxGrid('loadstate', defaultState);
            });
            $("#SaveNew").click(function () {
                if(!$('#testForm').jqxValidator('validate')) {
                        return false;
                }
                $("#SaveNew").jqxButton({ disabled: true });
                var state = $("#jqxgrid").jqxGrid('savestate');

                var row = { ClientName: $("#advertisername").val(), ParentCompany: $("#parentcompany").val(), Region: $("#region").val(),
                    Country: $("#nameofentity").val(), City: $("#city").val(), LeadAgency: $("#agency").val(), ClientCategory: $("#category").val(),
                    PitchStart: $("#pitchstart").val(),PitchStage: $("#pitchstage").val(),
                    ClientSince: $("#clientsince").val(), LostDate: $("#lostdate").val(), Service: $("#service").val(),
                    MarketScope: $("#marketscope").val(), ActiveMarkets: $("#activemarket").val(), Currency: $("#currency").val(),
                    EstimatedRevenue: $("#estrevenue").val(),FiscalRevenue: $("#fiscrevenue").val(), Comments: $("#notes").val(), parentId: $('#parentrecordid').val()
                };
                $.ajax({
                    type: "POST",
                    url: "/reports/save_client_record/",
                    data: JSON.stringify(row),
                    contentType: "application/json; charset=utf-8",
                    dataType: "json",
                    success : function(result) {
                        if(result.success == true) {
                            $("#jqxgrid").jqxGrid('updateBoundData');
                            if (state) {
                                $("#jqxgrid").jqxGrid('loadstate', state);
                            }
                            $("#SaveNew").attr('disabled', false);
                            $("#popupWindow").jqxWindow('hide');
                        } else {
                            alert(result.errors);
                            return false;
                        }
                    }
                });

            });

            var validator = {

                agency : {
                        input: '#update_agency', message: 'Lead agency is required!', action: 'change', rule: function (input) {
                            if (input.val() != '') {
                                    return true;
                            }
                            return false;
                        }
                },
                category: {
                        input: '#update_category', message: 'Category is required!', action: 'change', rule: function (input) {
                            if (input.val() != '') {
                                    return true;
                            }
                            return false;
                        }
                },
                service : {
                        input: '#update_service', message: 'Service is required!', action: 'change', rule: function (input) {
                            if (input.val() != '') {
                                    return true;
                            }
                            return false;
                        }
                },
                pitchstage : {
                        input: '#update_pitchstage', message: 'Stage is required!', action: 'change', rule: function (input) {
                            if (input.val() != '') {
                                    return true;
                            }
                            return false;
                        }
                },
                clientsince: { input: '#update_clientsince', message: 'Client Since is required!', action: 'change', rule: function (input) {
                        if($('#update_pitchstage').val()) {
                                var pitchstage = $('#update_pitchstage').val();
                        } else {
                                var pitchstage = $('#update_pitchstage').text();
                        }
                        if (( pitchstage == 'Current client') && input.val() == '') {
                                return false;
                        }
                        return true;
                    }
                },
                lostdate: { input: '#update_lostdate', message: 'Lost Date is required!', action: 'change', rule: function (input) {
                        if($('#update_pitchstage').val()) {
                                var pitchstage = $('#update_pitchstage').val();
                        } else {
                                var pitchstage = $('#update_pitchstage').text();
                        }
                        if (pitchstage.match(/Lost/g) && input.val() == '') {
                                return false;
                        }
                        return true;
                    }
                },
                marketscope: { input: '#update_marketscope', message: 'Scope is required!', action: 'change', rule: function (input) {
                        if (input.val() != '') {
                                return true;
                        }
                        return false;
                    }
                },
                activemarkets: { input: '#update_activemarket', message: 'Active Market is required!', action: 'change', rule: function (input) {
                        if (input.val() != '') {
                                return true;
                        }
                        return false;
                    }
                },
                currency: {
                        input: '#update_currency', message: 'Currency is required!', action: 'change', rule: function (input) {
                            if (input.val() != '') {
                                    return true;
                            }
                            return false;
                        }
                },
                estrevenueRequired: { input: '#update_estrevenue', message: 'iP estimated revenue is required!', action: 'keyup, blur', rule: function (input) {
                        if($('#update_pitchstage').val()) {
                                var pitchstage = $('#update_pitchstage').val();
                        } else {
                                var pitchstage = $('#update_pitchstage').text();
                        }
                        if ((pitchstage == 'Current client') && input.val() == '') {
                                return false;
                        }
                        return true;
                    }
                },
                estrevenueNumeric: { input: '#update_estrevenue', message: 'iP estimated revenue should be numeric!', action: 'keyup, blur', rule: function (input) {
                        if($('#update_pitchstage').val()) {
                                var pitchstage = $('#update_pitchstage').val();
                        } else {
                                var pitchstage = $('#update_pitchstage').text();
                        }
                        if ((pitchstage == 'Current client')) {
                                if(!isNaN(parseFloat(input.val())) && isFinite(input.val())) {
                                        return true;
                                }
                        } else {
                                return true;
                        }
                        return false;
                    }
                },
                actualrevenueRequired: { input: '#update_actualrevenue', message: 'iP Actual revenue is required!', action: 'keyup, blur', rule: function (input) {
                        if($('#update_pitchstage').val()) {
                                var pitchstage = $('#update_pitchstage').val();
                        } else {
                                var pitchstage = $('#update_pitchstage').text();
                        }
                        if ((pitchstage == 'Current client') && input.val() == '') {
                                return false;
                        }
                        return true;
                    }
                },
                actualrevenueNumeric: { input: '#update_actualrevenue', message: 'iP Actual revenue should be numeric!', action: 'keyup, blur', rule: function (input) {
                        if($('#update_pitchstage').val()) {
                                var pitchstage = $('#update_pitchstage').val();
                        } else {
                                var pitchstage = $('#update_pitchstage').text();
                        }
                        if ((pitchstage == 'Current client')) {
                                if (!isNaN(parseFloat(input.val())) && isFinite(input.val())) {
                                        return true;
                                }
                        } else {
                                return true;
                        }
                        return false;
                    }
                }
            };

            $("#UpdateClient").jqxButton({ theme: theme });
            $("#CancelUpdate").jqxButton({ theme: theme });
            // update the edited row when the user clicks the 'Save' button.
            $("#UpdateClient").click(function () {
                if(!$('#updateForm').jqxValidator('validate')) {
                        return false;
                }
                var state = $("#jqxgrid").jqxGrid('savestate');

                var recordid = $("#recordid").val();
                var parentrecordid = $("#update_parentrecordid").val();
                var clientname = $("#divAdvertiser").text();
                if($('#update_parentcompany').val()) {
                        var parentcompany = $('#update_parentcompany').val();
                } else {
                        var parentcompany = $("#divParentCompany").text();
                }
                if($('#update_region').val()) {
                        var region = $('#update_region').val();
                } else {
                        var region = $('#divRegion').text();
                }
                if($('#update_nameofentity').val()) {
                        var country = $('#update_nameofentity').val();
                } else {
                        var country = $('#divEntity').text();
                }
                if($('#update_city').val()) {
                        var city = $('#update_city').val();
                } else {
                        var city = $('#divCity').text();
                }
                if($('#update_agency').val()) {
                        var leadagency = $('#update_agency').val();
                } else {
                        var leadagency = $('#divAgency').text();
                }
                if($('#update_category').val()) {
                        var clientcategory = $('#update_category').val();
                } else {
                        var clientcategory = $('#divCategory').text();
                }
                if($('#update_pitchstart').val()) {
                        var pitchstart = $('#update_pitchstart').val();
                } else {
                        var pitchstart = $('#divPitchStart').text();
                }
                if($('#update_pitchstage').val()) {
                        var pitchstage = $('#update_pitchstage').val();
                } else {
                        var pitchstage = $('#divPitchStage').text();
                }
                if($('#update_clientsince').val()) {
                        var clientsince = $('#update_clientsince').val();
                } else {
                        var clientsince = $('#divClientSince').text();
                }
                if($('#update_lostdate').val()) {
                        var lostdate = $('#update_lostdate').val();
                } else {
                        var lostdate = $('#divLostDate').text();
                }
                if($('#update_service').val()) {
                        var service = $('#update_service').val();
                } else {
                        var service = $('#divService').text();
                }
                var marketscope = $('#update_marketscope').val();
                var activemarkets = $('#update_activemarket').val();
                if($('#update_currency').val()) {
                        var currency = $('#update_currency').val();
                } else {
                        var currency = $('#divCurrency').text();
                }
                if($('#update_estrevenue').val()) {
                        var estimatedrevenue = $('#update_estrevenue').val();
                } else {
                        var estimatedrevenue = $('#divEstRevenue').text();
                }
                if($('#update_fiscrevenue').val()) {
                        var fiscalrevenue = $('#update_fiscrevenue').val();
                } else {
                        var fiscalrevenue = $('#divFiscRevenue').text();
                }
                if($('#update_actualrevenue').val()) {
                        var actualrevenue = $('#update_actualrevenue').val();
                } else {
                        var actualrevenue = $('#divActualRevenue').text();
                }
                var comments = $("#update_notes").val();

                var row = { RecordId: recordid, ClientName: clientname, ParentCompany: parentcompany, Region: region,
                    Country: country, City: city, LeadAgency: leadagency, ClientCategory: clientcategory,
                    PitchStart: pitchstart,PitchStage: pitchstage,
                    ClientSince: clientsince, LostDate: lostdate, Service: service,
                    MarketScope: marketscope, ActiveMarkets: activemarkets, Currency: currency,
                    EstimatedRevenue: estimatedrevenue,FiscalRevenue: fiscalrevenue, ActualRevenue: actualrevenue, Comments: comments, ParentId: parentrecordid
                };

                var updateRow = { RecordId: recordid, ClientName: clientname, ParentCompany: parentcompany, Region: region,
                    Country: country, City: city, LeadAgency: leadagency, ClientCategory: clientcategory,
                    PitchStart: pitchstart, PitchStage: pitchstage,
                    ClientSince: clientsince, LostDate: lostdate,
                    Service: service, ActiveMarkets: activemarkets, Currency: currency,
                    EstimatedRevenue: estimatedrevenue,FiscalRevenue: fiscalrevenue, ActualRevenue: actualrevenue, Comments: comments, ParentId: parentrecordid
                };

                $.ajax({
                    type: "POST",
                    url: "/reports/update_client_record/",
                    data: JSON.stringify(row),
                    contentType: "application/json; charset=utf-8",
                    dataType: "json",
                    success : function(result) {
                        if(result.success == true) {
                            $("#jqxgrid").jqxGrid('updateBoundData');
                            if (state) {
                                $("#jqxgrid").jqxGrid('loadstate', state);
                            }
                            $("#updateWindow").jqxWindow('hide');
                        } else {
                            alert(result.errors);
                            return false;
                        }
                    }
                });

            });

        });
    </script>
    <div id="tab-menu" align="left">
            <div id="-reports-current-client-report" class="light-grey">
                    <a href="/reports/current_client_report">SEARCH</a>
            </div>
            <div id="-reports-current-client-data" class="light-grey selected">
                    <a href="/reports/current_client_data">CREATE/UPDATE YOUR RECORDS</a>
            </div>

            <div style="float: right; margin-top: 35px; padding-right: 7px;">
                <button value="Reset" id="clearfilteringbutton" title="Reset filters">RESET</button>
                <button value="Add a new record" class='createNew'>ADD A NEW RECORD</button>
            </div>
    </div>
<script type="text/javascript">
        $(document).ready(function() {
                $('#tab-menu div#-<?php echo $this->params['controller'].'-'.$this->params['action']; ?>').addClass('selected');
                $('#nav-menu div#-reports-current-client_report').addClass('selected');
        });
</script>

<div id='jqxWidget'>
        <div id="jqxgrid"></div>
        <div style='margin-top: 20px;'></div>
        <div style='float: right; padding-right: 7px; padding-bottom: 30px'>
            <button value="Add a new record" class='createNew'>ADD A NEW RECORD</button>
        </div>

    <div id="popupWindow">
        <div>Add a new record</div>
        <div style="overflow: hidden;">
        <div style="padding-bottom: 10px;" align="right"><button style="margin-right: 15px;" id="CancelNew" value="Cancel">CANCEL</button></div>
        <form id="testForm" action="./">
            <table>
                <tr>
                    <td align="right" style="width: 200px;">Region</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="region"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">Country</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="nameofentity"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">City</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="city"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">Lead Agency</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="agency"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">Advertiser Name</td>
                    <td align="left" style="padding-bottom: 5px;"><input type="text" id="advertisername" autocomplete="off"/></td>
                    <td style="width: 150px"><input type="hidden" id="parentrecordid"/></td>
                </tr>
                <tr>
                    <td align="right">Parent Company</td>
                    <td align="left" style="padding-bottom: 5px;"><input type="text" id="parentcompany"/></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">Category</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="category"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">Status</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="pitchstage"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">Service</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="service"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr id="trClientSince" style="display: none">
                    <td align="right">Client Since (M-Y)</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="clientsince"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr id="trLostSince" style="display: none">
                    <td align="right">Lost Since (M-Y)</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="lostdate"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">Pitched (M-Y)</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="pitchstart"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">Scope</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="marketscope"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">Active Market</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="activemarket"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">Currency</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="currency"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">iP estimated revenue</td>
                    <td align="left" style="padding-bottom: 5px;"><input type="text" id="estrevenue"/></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">Fiscal year Revenue</td>
                    <td align="left" style="padding-bottom: 5px;"><input type="text" id="fiscrevenue"/></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right">Notes</td>
                    <td align="left" style="padding-bottom: 5px;"><input type="text" id="notes"/></td>
                    <td style="width: 150px"></td>
                </tr>
            </table>
        </form>
        <div style="padding-top: 10px;" align="right"><button style="margin-right: 15px;" id="SaveNew" value="Add to existing records">ADD TO EXISTING RECORDS</button></div>
        </div>
   </div>

    <div id="updateWindow">
        <div>Edit record</div>
        <div style="overflow: hidden;">
        <div style="padding-bottom: 10px;" align="right"><button style="margin-right: 15px;" id="CancelUpdate" value="Cancel">CANCEL</button></div>
        <form id="updateForm" action="./">
            <table>
                <tr>
                    <td align="right" style="width: 200px; padding-bottom: 5px; padding-right: 5px">Region</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divRegion"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Country</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divEntity"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">City</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divCity"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Lead Agency</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divAgency"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Advertiser Name</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divAdvertiser"></div>
                            <input type="hidden" id="recordid"/>
                            <input type="hidden" id="update_parentrecordid"/>
                    </td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Parent Company</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divParentCompany"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Category</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divCategory"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Status</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divPitchStage"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Service</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divService"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr id="trUpdateClientSince" style="display: none">
                    <td align="right">Client Since (M-Y)</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divClientSince"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr id="trUpdateLostSince" style="display: none">
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Lost Since (M-Y)</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divLostDate"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Pitched (M-Y)</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divPitchStart"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Scope</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="update_marketscope"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Active Market</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="update_activemarket"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Currency</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divCurrency"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">iP estimated revenue</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divEstRevenue"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Fiscal year Revenue</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divFiscRevenue"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">iP <?php echo (date('Y')-1); ?> actual revenue</td>
                    <td align="left" style="padding-bottom: 5px;"><div id="divActualRevenue"></div></td>
                    <td style="width: 150px"></td>
                </tr>
                <tr>
                    <td align="right" style="padding-bottom: 5px; padding-right: 5px">Notes</td>
                    <td align="left" style="padding-bottom: 5px;"><input type="text" id="update_notes"/></td>
                    <td style="width: 150px"></td>
                </tr>
            </table>
        </form>

        <div style="padding-top: 20px;" align="right"><button style="margin-right: 15px;" id="UpdateClient">UPDATE EXISTING RECORD</button></div>
        </div>
    </div>
    <div id="revenueWindow">
        <div>Revenue values for Previous years</div>
        <div style="overflow: hidden;" align="center">
        <div style="padding-bottom: 10px;" align="right">
                <table align="center">
                    <tr>
                        <td align="right" style="padding-bottom: 5px; padding-right: 5px">Client Name</td>
                        <td align="left" style="padding-bottom: 5px;"><div id="revClientname"></div></td>
                        <td style="width: 150px"></td>
                    </tr>
                    <tr>
                        <td align="right" style="padding-bottom: 5px; padding-right: 5px">Service</td>
                        <td align="left" style="padding-bottom: 5px;"><div id="revService"></div></td>
                        <td style="width: 150px"></td>
                    </tr>
                    <tr>
                        <td align="right" style="padding-bottom: 5px; padding-right: 5px">Currency</td>
                        <td align="left" style="padding-bottom: 5px;"><div id="revCurrency"></div></td>
                        <td style="width: 150px"></td>
                    </tr>
                    <tr><td colspan="3"><div id="actualRevenue"><span style="width:150px;"></span></div></td></tr>
               </table>
        </div>
        </div>
    </div>
</div>