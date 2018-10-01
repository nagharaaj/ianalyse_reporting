<?php
App::uses('CakeEmail', 'Network/Email');

class DanReconciliationShell extends AppShell {
        //public $components = array('RequestHandler');

        public $uses = array(
            'City',
            'ClientCategory',
            'Country',
            'Currency',
            'LeadAgency',
            'Market',
            'Region',
            'Service',
            'PitchStage',
            'ClientRevenueByService',
            'ClientDeleteLog',
            'UserLoginRole'
        );

        public $unwanted_array = array( 'Š'=>'S', 'š'=>'s', 'Ž'=>'Z', 'ž'=>'z', 'À'=>'A', 'Á'=>'A', 'Â'=>'A', 'Ã'=>'A', 'Ä'=>'A', 'Å'=>'A', 'Æ'=>'A', 'Ç'=>'C', 'È'=>'E', 'É'=>'E',
                            'Ê'=>'E', 'Ë'=>'E', 'Ì'=>'I', 'Í'=>'I', 'Î'=>'I', 'Ï'=>'I', 'Ñ'=>'N', 'Ò'=>'O', 'Ó'=>'O', 'Ô'=>'O', 'Õ'=>'O', 'Ö'=>'O', 'Ø'=>'O', 'Ù'=>'U',
                            'Ú'=>'U', 'Û'=>'U', 'Ü'=>'U', 'Ý'=>'Y', 'Þ'=>'B', 'ß'=>'Ss', 'à'=>'a', 'á'=>'a', 'â'=>'a', 'ã'=>'a', 'ä'=>'a', 'å'=>'a', 'æ'=>'a', 'ç'=>'c',
                            'è'=>'e', 'é'=>'e', 'ê'=>'e', 'ë'=>'e', 'ì'=>'i', 'í'=>'i', 'î'=>'i', 'ï'=>'i', 'ð'=>'o', 'ñ'=>'n', 'ò'=>'o', 'ó'=>'o', 'ô'=>'o', 'õ'=>'o',
                            'ö'=>'o', 'ø'=>'o', 'ù'=>'u', 'ú'=>'u', 'û'=>'u', 'ý'=>'y', 'þ'=>'b', 'ÿ'=>'y', '\''=>'', '"'=>'', ' '=>'', '`'=>'', '-' => '', '_' => '');

        public $nbrCountries = array();
        public $nbrCountryData = array();

        public function main() {
                set_time_limit(0);
                ini_set('memory_limit', '-1');

                $this->out('Reconciliation in progress....');
                $currDt = date('Y-m-d h:i:s');
                $lastDayDt = date('Y') . '-01-01';
                $currTime = date('m/d/Y H:i:s');
                $emailList = $this->mailList();

                //the target url of NBR system.
                $siteUrl = 'team.dentsuaegis.com/sites/nbr/';
                $userpwd = 'MEDIA\sysSP-P-NBR:Jfo829/K!';

                // curl object for read requests
                $ch = curl_init();
                //curl_setopt( $ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.7.3) Gecko/20041001 Firefox/0.10.1" );
                //curl_setopt( $ch, CURLOPT_COOKIEJAR, $cookie );
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 25 );
                curl_setopt( $ch, CURLOPT_TIMEOUT, 25 );
                curl_setopt($ch, CURLOPT_USERPWD, $userpwd);
                curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_NTLM);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("accept: application/json;odata=verbose"));

                // curl object for write requests
                $ch1 = curl_init();
                curl_setopt($ch1, CURLOPT_RETURNTRANSFER, true);
                curl_setopt( $ch1, CURLOPT_CONNECTTIMEOUT, 25 );
                curl_setopt( $ch1, CURLOPT_TIMEOUT, 25 );
                curl_setopt($ch1, CURLOPT_USERPWD, $userpwd);
                curl_setopt($ch1, CURLOPT_HTTPAUTH, CURLAUTH_NTLM);
                curl_setopt($ch1, CURLOPT_HTTPHEADER, array("content-type: application/json;odata=verbose", "accept: application/json;odata=verbose"));
                curl_setopt($ch1, CURLOPT_POST, true);

                // curl object for update requests
                $ch2 = curl_init();
                curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true);
                curl_setopt( $ch2, CURLOPT_CONNECTTIMEOUT, 25 );
                curl_setopt( $ch2, CURLOPT_TIMEOUT, 25 );
                curl_setopt($ch2, CURLOPT_USERPWD, $userpwd);
                curl_setopt($ch2, CURLOPT_HTTPAUTH, CURLAUTH_NTLM);
                curl_setopt($ch2, CURLOPT_HTTPHEADER, array("content-type: application/json;odata=verbose", "accept: application/json;odata=verbose", "If-Match: *"));
                curl_setopt($ch2, CURLOPT_CUSTOMREQUEST, 'MERGE');

                //array of iProspect pitch status mappings with NBR
                $pitchStatusMappings = $this->PitchStage->find('list', array('fields' => array('PitchStage.pitch_stage', 'PitchStage.dan_mapping')));
                //array of currencies and conversion rates
                $currencies = $this->Currency->find('list', array('fields' => array('Currency.id', 'Currency.currency')));
                $services = $this->Service->find('list', array('fields' => array('Service.id', 'Service.dan_mapping')));
                $cities = $this->City->find('list', array('fields' => array('City.id', 'City.city')));

                // NBR pitch status array id => pitch status
                $arrPitchStatus = array();
                $offensivePitchId = null;
                $defensivePitchId = null;
                $pitchStatusUrl = $siteUrl . "_api/web/lists(guid'c47bb064-faa5-4ab7-812c-3b005843314d')/items";
                curl_setopt( $ch, CURLOPT_URL, $pitchStatusUrl );
                $pitchStatusContent = json_decode(curl_exec( $ch ));
                $pitchStatusResult = $pitchStatusContent->d->results;
                foreach($pitchStatusResult as $result) {
                        $arrPitchStatus[$result->Id] = $result->Title;
                        if($result->Title == 'Offensive Pitch' && $result->DAParentStatus == 'New') {
                                $offensivePitchId = $result->Id;
                        }
                        if($result->Title == 'Defensive Pitch' && $result->DAParentStatus == 'New') {
                                $defensivePitchId = $result->Id;
                        }
                }
                // NBR pitch stage array id => pitch stage
                $arrPitchStage = array();
                $pitchStageUrl = $siteUrl . "_api/web/lists(guid'eb47971c-2bf9-4ace-90f9-67d5117d9e31')/items";
                curl_setopt( $ch, CURLOPT_URL, $pitchStageUrl );
                $pitchStageContent = json_decode(curl_exec( $ch ));
                $pitchStageResult = $pitchStageContent->d->results;
                foreach($pitchStageResult as $result) {
                        $arrPitchStage[$result->Id] = $result->Title;
                }
                // NBR network brands array id => network brand
                $arrNetworkBrand = array();
                $networkBrandUrl = $siteUrl . "_api/web/lists(guid'b7171029-1237-4412-b507-2bd2e0ae4942')/items" . '?$filter=' . urlencode("Title eq 'iProspect'");
                curl_setopt( $ch, CURLOPT_URL, $networkBrandUrl );
                $networkBrandContent = json_decode(curl_exec( $ch ));
                $networkBrandResult = $networkBrandContent->d->results;
                foreach($networkBrandResult as $result) {
                        $arrNetworkBrand[$result->Id] = $result->Title;
                }
                // NBR industry category array id => industry category
                $arrIndustryCategory = array();
                $industryCategoryUrl = $siteUrl . "_api/web/lists(guid'172fc1ba-d15d-497b-8965-09025f005beb')/items";
                curl_setopt( $ch, CURLOPT_URL, $industryCategoryUrl );
                $industryCategoryContent = json_decode(curl_exec( $ch ));
                $industryCategoryResult = $industryCategoryContent->d->results;
                foreach($industryCategoryResult as $result) {
                        $arrIndustryCategory[$result->Id] = $result->Title;
                }

                // NBR currencies array id => currency
                $arrNbrCurrencies = array();
                // NBR Euros => USD conversion rates
                $arrEuroCurrency = array();
                // NBR Pounds => USD conversion rates
                $arrPoundCurrency = array();
                // NBR USD => Pounds conversion rates
                $arrUSDCurrency = array();
                $currencyUrl = $siteUrl . "_api/web/lists(guid'39819ab1-12f9-4d07-bf2d-5f53273668fb')/items";
                curl_setopt( $ch, CURLOPT_URL, $currencyUrl );
                $currencyContent = json_decode(curl_exec( $ch ));
                $currencyResult = $currencyContent->d->results;
                foreach($currencyResult as $result) {
                        $arrNbrCurrencies[$result->Id] = array ('currency' => $result->Title,
                                                           'gbp_rate' => $result->DASterlingRate,
                                                           'usd_rate' => $result->DADollarRate,
                                                           'currency_code' => $result->DACurrencyCode
                                                    );
                        if($result->Title == 'Euros') {
                                $arrEuroCurrency['currency'] = $result->Title;
                                $arrEuroCurrency['gbp_rate'] = $result->DASterlingRate;
                                $arrEuroCurrency['usd_rate'] = $result->DADollarRate;
                                $arrEuroCurrency['currency_code'] = $result->DACurrencyCode;
                        }
                        if($result->Title == 'British Pound') {
                                $arrPoundCurrency['currency'] = $result->Title;
                                $arrPoundCurrency['usd_rate'] = $result->DADollarRate;
                                $arrPoundCurrency['currency_code'] = $result->DACurrencyCode;
                        }
                        if($result->Title == 'United States Dollar') {
                                $arrUSDCurrency['currency'] = $result->Title;
                                $arrUSDCurrency['gbp_rate'] = $result->DASterlingRate;
                                $arrUSDCurrency['currency_code'] = $result->DACurrencyCode;
                        }
                }
                // NBR countries array id => country
                $this->nbrCountries = array();
                $arrNbrCountry = $this->getNbrCountry($siteUrl . "_api/web/lists(guid'100f63e1-6845-4fa8-b3f3-0ee87c1dbdd5')/items");

                // query to aggregate client revenue by services data in iProspect grouped by country, client name, pitch status
                $this->ClientRevenueByService->query("SET SESSION group_concat_max_len = 1000000");
                $clients = $this->ClientRevenueByService->find('all', array(
                    'fields' => array(
                        'ClientRevenueByService.pitch_stage',
                        'group_concat(IFNULL(ClientRevenueByService.estimated_revenue,0)) as estimated_revenue', 'group_concat(IFNULL(ClientRevenueByService.currency_id,"")) as currency_id',
                        'Country.country'
                    ),
                    'conditions' => array(
                        "((pitch_stage like 'Live%' or pitch_stage like 'Won%' or pitch_stage like 'Lost%' or pitch_stage='Cancelled' or pitch_stage='Declined') and pitch_stage != 'Lost - archive')",
                        "(ClientRevenueByService.created between '" . $lastDayDt . "' and '" . $currDt . "' or ClientRevenueByService.modified between '" . $lastDayDt . "' and '" . $currDt . "')"
                    ),
                    'group' => array('Country.country', 'ClientRevenueByService.pitch_stage'),
                    'order' => 'Country.country, ClientRevenueByService.pitch_stage asc'
                    //'limit' => 10
                ));
                //echo '<pre>'; print_r($clients);

                $totalRevenue = 0;
                $totalRevenueByCountry = array();
                $totalRevenueByPitchStatus = array();
                $arrCountry = array();
                $arrConnectCountries = array();
                foreach($clients as $client) {
                        if($client['Country']['country'] == 'United States') {
                                $country = 'United States of America';
                        } elseif($client['Country']['country'] == 'United Arab Emirates') {
                                $country = 'UAE';
                        } elseif($client['Country']['country'] == 'Serbia and Montenegro') {
                                $country = 'Serbia';
                        } elseif($client['Country']['country'] == 'Burma') {
                                $country = 'Myanmar';
                        } else {
                                $country = $client['Country']['country'];
                        }
                        $pitchStatus = $pitchStatusMappings[$client['ClientRevenueByService']['pitch_stage']];

                        $estimatedRevenueUSD = 0;
                        $arrEstRevenue = explode(',', $client[0]['estimated_revenue']);
                        $arrCurrency = explode(',', $client[0]['currency_id']);
                        foreach($arrEstRevenue as $index => $estRevenue) {
                                if($estRevenue != 0) {
                                        if($arrCurrency[$index] != null) {
                                                if($currencies[$arrCurrency[$index]] == 'USD') {
                                                        $estimatedRevenueUSD += $estRevenue;
                                                } elseif($currencies[$arrCurrency[$index]] == 'British Pounds') {
                                                        $estimatedRevenueUSD += ($arrPoundCurrency['usd_rate'] != 0) ? ($estRevenue * $arrPoundCurrency['usd_rate']) : $estRevenue;
                                                } else {
                                                        $estimatedRevenueUSD += ($arrEuroCurrency['usd_rate'] != 0) ? ($estRevenue * $arrEuroCurrency['usd_rate']) : $estRevenue;
                                                }
                                        } else {
                                                $estimatedRevenueUSD += $estRevenue;
                                        }
                                }
                        }
                        $totalRevenue += $estimatedRevenueUSD;
                        if(isset($totalRevenueByCountry[$country]) === false) {
                                $totalRevenueByCountry[$country] = $estimatedRevenueUSD;
                        } else {
                                $totalRevenueByCountry[$country] += $estimatedRevenueUSD;
                        }
                        if(isset($totalRevenueByPitchStatus[$pitchStatus]) === false) {
                                $totalRevenueByPitchStatus[$pitchStatus] = $estimatedRevenueUSD;
                        } else {
                                $totalRevenueByPitchStatus[$pitchStatus] += $estimatedRevenueUSD;
                        }

                        if(array_search($country, $arrCountry) === false) {
                                $arrCountry[] = $country;
                                $arrConnectCountries[$country] = $client['Country']['country'];
                        }
                }

                $networkBrandId = array_search('iProspect', $arrNetworkBrand);
                $noOfRecords = 0;
                $totalNbrRevenue = 0;
                $totalNbrRevenueByCountry = array();
                $totalNbrRevenueByPitchStatus = array();
                foreach($arrCountry as $country) {
                        // request to pull country information like id, name and country code from NBR
                        $countryCodeUrl = $siteUrl . '_api/web/lists/getbytitle(\'Country\')/items?$select=Id,Title,DACountryCode,DACurrencyId&$filter=' . urlencode('Title eq \'' . $country . '\'');
                        curl_setopt( $ch, CURLOPT_URL, $countryCodeUrl );
                        $countryCodeData = json_decode(curl_exec( $ch ));
                        if(isset($countryCodeData->d) && empty($countryCodeData->d->results)) {
                        // if a country does not exists in NBR country list, stop the execution of the script
                                // send an email notification to admins
                                $responseStatus = array();
                                $responseStatus['date_n_time'] = $currTime;
                                $responseStatus['reason'] = 'A country \''.$country.'\' not found in NBR';
                                $email = new CakeEmail('gmail');
                                $email->viewVars(array('title_for_layout' => 'Connect < > NBRT reconciliation failed', 'type' => 'Client data', 'data' => $responseStatus));
                                $email->template('nbr_reconciliation_fail', 'default')
                                    ->emailFormat('html')
                                    ->to($emailList)
                                    ->from(array('connectiprospect@gmail.com' => 'Connect iProspect'))
                                    ->subject('Connect < > NBRT reconciliation failed')
                                    ->send();

                                CakeLog::write('error', 'NBRT reconciliation failed. A country \''.$country.'\' not found in NBRT.', 'reconciliation');
                                // closing all the curl sessions at the end
                                curl_close ( $ch );
                                exit(0);
                        } else {
                                $countryCode = $countryCodeData->d->results[0]->DACountryCode;
                                $countryId = $countryCodeData->d->results[0]->Id;
                        }
                        //request to get pitches under the country pitch list
                        $this->nbrCountryData = array();
                        $countryPitchUrl = $siteUrl . $countryCode .'/_api/web/lists/getbytitle(\'Pitch\')/items';
                        $countryPitchFilter = urlencode('DALeadCountry eq ' . $countryId . ' and DANetworkBrand eq ' . $networkBrandId . ' and DAArchivePitch eq 0');
                        $countryPitchUrl = $countryPitchUrl . '?$filter=' . $countryPitchFilter;
                        $countryPitchResult = $this->getNbrCountryData($countryPitchUrl);
                        if(!empty($countryPitchResult)) {
                                foreach($countryPitchResult['results'] as $result) {
                                        $estimatedRevenueUSD = $result->DAEstimatedAnnualRevenueUSD;
                                        $pitchStatus = $arrPitchStatus[$result->DAPitchStatusId];

                                        $totalNbrRevenue += $estimatedRevenueUSD;
                                        if(isset($totalNbrRevenueByCountry[$country]) === false) {
                                                $totalNbrRevenueByCountry[$country] = $estimatedRevenueUSD;
                                        } else {
                                                $totalNbrRevenueByCountry[$country] += $estimatedRevenueUSD;
                                        }
                                        if(isset($totalNbrRevenueByPitchStatus[$pitchStatus]) === false) {
                                                $totalNbrRevenueByPitchStatus[$pitchStatus] = $estimatedRevenueUSD;
                                        } else {
                                                $totalNbrRevenueByPitchStatus[$pitchStatus] += $estimatedRevenueUSD;
                                        }
                                        $noOfRecords++;
                                }
                        } else {
                                $totalNbrRevenueByCountry[$country] = 0;
                        }
                }
                // array to store countrycodes for generating request on country wise pitch list
                $arrCountryCode = array();
                // NBR country id array country name => id
                $arrCountryId = array();
                // array to store country's local currency, gbp and usd conversion rates details
                $arrCountryCurrency = array();
                $noOfRecordsSynced = 0;
                $arrRecordsCorrected = array();
                //try to resolve the difference by checking the values for each country
                foreach($arrCountry as $country) {
                        if(array_key_exists($country, $arrCountryCode) === false) {
                        // check if country code already exists in array
                                // request to pull country information like id, name and country code from NBR
                                $countryCodeUrl = $siteUrl . '_api/web/lists/getbytitle(\'Country\')/items?$select=Id,Title,DACountryCode,DACurrencyId&$filter=' . urlencode('Title eq \'' . $country . '\' and DAArchivePitch eq 0');
                                curl_setopt( $ch, CURLOPT_URL, $countryCodeUrl );
                                $countryCodeData = json_decode(curl_exec( $ch ));
                                if(isset($countryCodeData->d) && empty($countryCodeData->d->results)) {
                                // if a country does not exists in NBR country list, stop the execution of the script
                                        // send an email notification to admins
                                        $responseStatus = array();
                                        $responseStatus['date_n_time'] = $currTime;
                                        $responseStatus['reason'] = 'A country \''.$country.'\' not found in NBR';
                                        $email = new CakeEmail('gmail');
                                        $email->viewVars(array('title_for_layout' => 'Connect < > NBRT reconciliation failed', 'type' => 'Client data', 'data' => $responseStatus));
                                        $email->template('nbr_reconciliation_fail', 'default')
                                            ->emailFormat('html')
                                            ->to($emailList)
                                            ->from(array('connectiprospect@gmail.com' => 'Connect iProspect'))
                                            ->subject('Connect < > NBRT reconciliation failed')
                                            ->send();

                                        CakeLog::write('error', 'NBRT reconciliation failed. A country \''.$country.'\' not found in NBRT.', 'reconciliation');
                                        // closing all the curl sessions at the end
                                        curl_close ( $ch );
                                        curl_close ( $ch1 );
                                        curl_close ( $ch2 );
                                        exit(0);
                                } else {
                                        $arrCountryCode[$country] = $countryCodeData->d->results[0]->DACountryCode;
                                        $arrCountryId[$country] = $countryCodeData->d->results[0]->Id;
                                        $arrCountryCurrency[$country] = $arrNbrCurrencies[$countryCodeData->d->results[0]->DACurrencyId];
                                }
                        }
                        $countryCode = $arrCountryCode[$country];
                        $countryId = $arrCountryId[$country];
                        $countryCurrency = $arrCountryCurrency[$country];
                        if($totalRevenueByCountry[$country] != $totalNbrRevenueByCountry[$country]) {
                                // query to aggregate client revenue by services data in iProspect grouped by country, client name, pitch status
                                $this->ClientRevenueByService->query("SET SESSION group_concat_max_len = 1000000");
                                $clients = $this->ClientRevenueByService->find('all', array(
                                    'fields' => array(
                                        'ClientRevenueByService.client_name', 'ClientRevenueByService.parent_company', 'ClientRevenueByService.pitch_date',
                                        'ClientRevenueByService.pitch_stage', 'ClientRevenueByService.client_since_month', 'ClientRevenueByService.client_since_year',
                                        'ClientRevenueByService.lost_date', 'ClientRevenueByService.agency_id', 'group_concat(NULLIF(ClientRevenueByService.comments,"")) as comments',
                                        'date_format(ClientRevenueByService.created, "%Y-%m-%d") as created',
                                        'date_format(ClientRevenueByService.modified, "%Y-%m-%d") as modified',
                                        'group_concat(IFNULL(ClientRevenueByService.estimated_revenue,0)) as estimated_revenue', 'group_concat(IFNULL(ClientRevenueByService.currency_id,"")) as currency_id',
                                        'group_concat(NULLIF(ClientRevenueByService.active_markets,"")) as active_markets', 'group_concat(ClientRevenueByService.service_id) as service_id',
                                        'group_concat(NULLIF(ClientRevenueByService.city_id,"")) as city_id',
                                        'group_concat(NULLIF(ClientRevenueByService.market_scope,"")) as market_scope',
                                        'LeadAgency.agency',
                                        'Country.country',
                                        'ClientCategory.dan_mapping',
                                    ),
                                    'conditions' => array(
                                                'AND' => array(
                                                    'OR' => array("pitch_stage LIKE 'Live%'", "pitch_stage LIKE 'Won%'", "pitch_stage LIKE 'Lost%'", "pitch_stage='Cancelled'", "pitch_stage='Declined'"),
                                                    "pitch_stage != 'Lost - archive'"
                                                ),
                                                'OR' => array("ClientRevenueByService.created BETWEEN ? AND ?" => array($lastDayDt, $currDt),
                                                        "ClientRevenueByService.modified BETWEEN ? AND ?" => array($lastDayDt, $currDt)
                                                ),
                                                "Country.country = '".$arrConnectCountries[$country]."'"
                                    ),
                                    'group' => array('Country.country', 'ClientRevenueByService.client_name', 'ClientRevenueByService.pitch_stage'),
                                    'order' => 'Country.country', 'ClientRevenueByService.client_name asc, ClientRevenueByService.pitch_stage asc, ClientRevenueByService.pitch_date desc',
                                    //'limit' => 10
                                ));
                                //echo '<pre>'; print_r($clients); exit(0);

                                foreach($clients as $client) {
                                        // request to check whether the client name already exists in NBR client list
                                        $clientSearchUrl = $siteUrl . '_api/web/lists/GetByTitle(\'Client\')/items';
                                        $clientSearchSelect = 'Id,Title,DACltHoldCompany,DAIndustryCateogry/Id';
                                        $clientSearchExpand = 'DAIndustryCateogry';
                                        $exactCientName = $client['ClientRevenueByService']['client_name']; // exact client name to search
                                        $rowClientName = strtr( $client['ClientRevenueByService']['client_name'], $this->unwanted_array ); // client name to search without special, accented characters
                                        $clientSearchFilter = urlencode("((Title eq '" . str_replace("'", "''", $exactCientName) . "' or substringof('" . $rowClientName . "', Title)) or (DACltHoldCompany eq '" . str_replace("'", "''", $exactCientName) . "' or substringof('" . $rowClientName . "', DACltHoldCompany)))");
                                        $clientSearchUrl = $clientSearchUrl. '?$select=' . $clientSearchSelect. '&$expand=' . $clientSearchExpand . '&$filter=' . $clientSearchFilter;
                                        curl_setopt( $ch, CURLOPT_URL, $clientSearchUrl );
                                        $clientSearchContent = json_decode(curl_exec( $ch ));
                                        $clientSearchResult = $clientSearchContent->d;
                                        //echo '<pre>'; print_r($clientSearchContent); echo '</pre>';
                                        if(empty($clientSearchResult->results)) {
                                        // if client name does not exists in NBR client list, create new entry
                                                $industryCategoryId = array_search($client['ClientCategory']['dan_mapping'], $arrIndustryCategory);
                                                if($industryCategoryId) {
                                                        $newClientData = array(
                                                            'Title' => $client['ClientRevenueByService']['client_name'],
                                                            'ClientHolidngCompany' => $client['ClientRevenueByService']['parent_company'],
                                                            'CountryId' => $countryId,
                                                            'IndustryCateogryId' => $industryCategoryId,
                                                            'TypeOfNetworkValue' => 'Digital and Creative'
                                                        );
                                                        $newClientUrl = $siteUrl . '_vti_bin/listdata.svc/Client';
                                                        curl_setopt($ch1, CURLOPT_POSTFIELDS, json_encode($newClientData));
                                                        curl_setopt( $ch1, CURLOPT_URL, $newClientUrl );
                                                        $newClientContent = json_decode(curl_exec( $ch1 ));
                                                        //echo '<pre>'; print_r($newClientContent); echo '</pre>';

                                                        $clientId = $newClientContent->d->Id;
                                                        $clientHolidngCompany = $client['ClientRevenueByService']['parent_company'];
                                                } else {
                                                // if industry category does not map, stop the execution of the script
                                                        // send an email notification to admins
                                                        $responseStatus = array();
                                                        $responseStatus['date_n_time'] = $currTime;
                                                        $responseStatus['reason'] = 'Mapping for industry category \''.$client['ClientCategory']['dan_mapping'].'\' not found in NBR';
                                                        $email = new CakeEmail('gmail');
                                                        $email->viewVars(array('title_for_layout' => 'Connect < > NBRT reconciliation failed', 'type' => 'Client data', 'data' => $responseStatus));
                                                        $email->template('nbr_reconciliation_fail', 'default')
                                                            ->emailFormat('html')
                                                            ->to($emailList)
                                                            ->from(array('connectiprospect@gmail.com' => 'Connect iProspect'))
                                                            ->subject('Connect < > NBRT reconciliation failed')
                                                            ->send();

                                                        CakeLog::write('error', 'NBRT reconciliation failed. Mapping for industry category \''.$client['ClientCategory']['dan_mapping'].'\' not found in NBRT.', 'reconciliation');
                                                        // closing all the curl sessions at the end
                                                        curl_close ( $ch );
                                                        curl_close ( $ch1 );
                                                        curl_close ( $ch2 );
                                                        exit(0);
                                                }
                                        } else {
                                        // else read existing client entry for client is, holding company and industry category
                                                if(count($clientSearchResult->results) > 0) {
                                                // if more than one matching client name found
                                                        $percent1 = 0;
                                                        foreach($clientSearchResult->results as $clientResult) {
                                                        // do case-sensetive string match to find best matching client name
                                                                similar_text(strtr($clientResult->Title, $this->unwanted_array), $rowClientName, $percent2);
                                                                if($percent2 > $percent1) {
                                                                // if the client name is most similar than the previous client name in list
                                                                        $clientId = $clientResult->Id;
                                                                        $clientHolidngCompany = $clientResult->DACltHoldCompany;
                                                                        $percent1 = $percent2;
                                                                }
                                                        }
                                                } else {
                                                        $clientId = $clientSearchResult->results[0]->Id;
                                                        $clientHolidngCompany = $clientSearchResult->results[0]->DACltHoldCompany;
                                                }
                                                $industryCategoryId = array_search($client['ClientCategory']['dan_mapping'], $arrIndustryCategory);
                                        }

                                        if($clientId != null) {
                                        // if a valid client id, process the other details
                                                $responseStatus = array();
                                                $arrComments = array_unique(explode(',', $client[0]['comments']));
                                                $pitchStatus = $pitchStatusMappings[$client['ClientRevenueByService']['pitch_stage']];
                                                // if pitch status is live then pitch stage should be empty, send closed otherwise
                                                if (preg_match('/Live/', $client['ClientRevenueByService']['pitch_stage'])) {
                                                        $pitchStage = 'RFI';
                                                } else {
                                                        $pitchStage = 'Closed';
                                                }
                                                if($client[0]['created'] != '0000-00-00' && $client[0]['created'] != null) {
                                                        $arrDtCreated = explode('-', $client[0]['created']);
                                                        $dtCreated = date('c', mktime(0, 0, 0, $arrDtCreated[1], $arrDtCreated[2], $arrDtCreated[0]));
                                                } else {
                                                        $dtCreated = date('c');
                                                }
                                                if($client['ClientRevenueByService']['pitch_date'] != '0000-00-00') {
                                                        $arrPitchDate = explode('-', $client['ClientRevenueByService']['pitch_date']);
                                                        $pitchDate = date('c', mktime(0, 0, 0, $arrPitchDate[1], $arrPitchDate[2], $arrPitchDate[0]));
                                                } else {
                                                        $pitchDate = null;
                                                }
                                                if(preg_match('/Won/', $client['ClientRevenueByService']['pitch_stage'])) {
                                                        // if pitch status is won, pitch close date should be client since date
                                                        if($client['ClientRevenueByService']['client_since_year'] != null) {
                                                                if($client['ClientRevenueByService']['client_since_month'] != null) {
                                                                        $pitchCloseDate = date('c', mktime(0, 0, 0, $client['ClientRevenueByService']['client_since_month'], 1, $client['ClientRevenueByService']['client_since_year']));
                                                                } else {
                                                                        $pitchCloseDate = date('c', mktime(0, 0, 0, 1, 1, $client['ClientRevenueByService']['client_since_year']));
                                                                }
                                                        } else {
                                                                $pitchCloseDate = null;
                                                        }
                                                } elseif(preg_match('/Lost/', $client['ClientRevenueByService']['pitch_stage']) || $client['ClientRevenueByService']['pitch_stage'] == 'Cancelled' || $client['ClientRevenueByService']['pitch_stage'] == 'Declined') {
                                                        // if pitch status is lost, pitch close date should be client lost date
                                                        if($client['ClientRevenueByService']['lost_date'] != '0000-00-00') {
                                                                $arrPitchCloseDate = explode('-', $client['ClientRevenueByService']['lost_date']);
                                                                $pitchCloseDate = date('c', mktime(0, 0, 0, $arrPitchCloseDate[1], $arrPitchCloseDate[2], $arrPitchCloseDate[0]));
                                                        } else {
                                                                $pitchCloseDate = null;
                                                        }
                                                } else {
                                                        $pitchCloseDate = null;
                                                }
                                                if($client['ClientRevenueByService']['agency_id'] == null || $client['LeadAgency']['agency'] == 'iProspect') {
                                                        $supportNetwork = '';
                                                        $multipleNetworksInvolved = false;
                                                } else {
                                                // if lead agency is other than iProspect
                                                        $supportNetwork = $client['LeadAgency']['agency'];
                                                        $multipleNetworksInvolved = true;
                                                }
                                                $estimatedRevenue = 0;
                                                $estimatedRevenueUSD = 0;
                                                $estimatedRevenueGBP = 0;
                                                $arrEstRevenue = explode(',', $client[0]['estimated_revenue']);
                                                $arrCurrency = explode(',', $client[0]['currency_id']);
                                                foreach($arrEstRevenue as $index => $estRevenue) {
                                                        if($estRevenue != 0) {
                                                                if($arrCurrency[$index] != null) {
                                                                        if($currencies[$arrCurrency[$index]] == 'USD') {
                                                                                $estimatedRevenueUSD += $estRevenue;
                                                                                $estimatedRevenueGBP += ($arrUSDCurrency['gbp_rate'] != 0) ? ($estRevenue * $arrUSDCurrency['gbp_rate']) : $estRevenue;
                                                                                $estRevenue = ($countryCurrency['usd_rate'] != 0) ? ($estRevenue / $countryCurrency['usd_rate']) : $estRevenue;
                                                                                $estimatedRevenue += $estRevenue;
                                                                        } elseif($currencies[$arrCurrency[$index]] == 'British Pounds') {
                                                                                $estimatedRevenueGBP += $estRevenue;
                                                                                $estimatedRevenueUSD += ($arrPoundCurrency['usd_rate'] != 0) ? ($estRevenue * $arrPoundCurrency['usd_rate']) : $estRevenue;
                                                                                $estRevenue = ($countryCurrency['gbp_rate'] != 0) ? ($estRevenue / $countryCurrency['gbp_rate']) : $estRevenue;
                                                                                $estimatedRevenue += $estRevenue;
                                                                        } else {
                                                                                $estimatedRevenueGBP += ($arrEuroCurrency['gbp_rate'] != 0) ? ($estRevenue * $arrEuroCurrency['gbp_rate']) : $estRevenue;
                                                                                $estRevenue = ($arrEuroCurrency['usd_rate'] != 0) ? ($estRevenue * $arrEuroCurrency['usd_rate']) : $estRevenue;
                                                                                $estimatedRevenueUSD += $estRevenue;
                                                                                $estRevenue = ($countryCurrency['usd_rate'] != 0) ? ($estRevenue / $countryCurrency['usd_rate']) : $estRevenue;
                                                                                $estimatedRevenue += $estRevenue;
                                                                        }
                                                                } else {
                                                                        $estimatedRevenue += $estRevenue;
                                                                        $estimatedRevenueUSD += ($countryCurrency['usd_rate'] != 0) ? ($estRevenue * $countryCurrency['usd_rate']) : $estRevenue;
                                                                        $estimatedRevenueGBP += ($countryCurrency['gbp_rate'] != 0) ? ($estRevenue * $countryCurrency['gbp_rate']) : $estRevenue;
                                                                }
                                                        }
                                                }
                                                //echo $estimatedRevenue ."\n". $estimatedRevenueGBP ."\n". $estimatedRevenueUSD;
                                                $activeMarkets = array();
                                                $scope = '';
                                                if($client[0]['active_markets'] != null) {
                                                        $client[0]['active_markets'] = str_replace(array('United States', 'United Arab Emirates', 'Serbia and Montenegro', 'Burma'), array('United States of America', 'UAE', 'Serbia', 'Myanmar'), $client[0]['active_markets']);
                                                        $activeMarkets = array_unique(explode(',', $client[0]['active_markets']));
                                                        if (($key = array_search($country, $activeMarkets)) !== false) {
                                                                unset($activeMarkets[$key]);
                                                        }
                                                        foreach($activeMarkets as &$activeMarket) {
                                                                $activeMarket = html_entity_decode($activeMarket);
                                                                if(array_search(trim($activeMarket), $arrNbrCountry) == false) {
                                                                        $responseStatus['reason'] = 'A country \''.$activeMarket.'\' under Other countries involved not found in NBR';
                                                                }
                                                        }
                                                }
                                                if($client[0]['market_scope'] != null) {
                                                        $scopeValue = array_unique(explode(',', $client[0]['market_scope']));
                                                        if(in_array('Global', $scopeValue)) {
                                                                $scope = 'Global';
                                                        } else if(in_array('Regional',$scopeValue)) {
                                                                $scope = 'Regional';
                                                        } else if(in_array('Multi-Market',$scopeValue)){
                                                                $scope = 'Multi-Market';
                                                        } else {
                                                                $scope = 'Local';
                                                        }
                                                } else {
                                                        if(count($activeMarkets) > 1) {
                                                                $scope = 'Multi-Market';
                                                        } else {
                                                                $scope = 'Local';
                                                        }
                                                }
                                                $arrServices = array();
                                                $arrServiceId = array_unique(explode(',', $client[0]['service_id']));
                                                foreach($arrServiceId as $serviceId) {
                                                        $arrServices[] = $services[$serviceId];
                                                }
                                                $arrCities = array();
                                                $arrCityId = array_unique(explode(',', $client[0]['city_id']));
                                                foreach($arrCityId as $cityId) {
                                                        if($cityId != null) {
                                                                $arrCities[] = $cities[$cityId];
                                                        }
                                                }
                                                $typeOfPitch = 'Contract';
                                                $networkBrand = 'iProspect';
                                                $typeOfNetwork = 'Digital and Creative';
                                                $holdingBrand = 'iProspect';
                                                $isArchivePitch = false;
                                                if($pitchStatus == 'Defensive Pitch') {
                                                        $pitchStatusId = $defensivePitchId;
                                                } elseif ($pitchStatus == 'Offensive Pitch') {
                                                        $pitchStatusId = $offensivePitchId;
                                                } else {
                                                        $pitchStatusId = array_search($pitchStatus, $arrPitchStatus);
                                                }
                                                $pitchStageId = (!empty($pitchStage) ? array_search($pitchStage, $arrPitchStage) : 0);
                                                $networkBrandId = array_search($networkBrand, $arrNetworkBrand);
                                                // abort the script if any of the pitch stage, pitch status or network brand mappings not found.
                                                if(!$pitchStatusId) {
                                                        $responseStatus['reason'] = 'Mapping for pitch status \''.$pitchStatus.'\' not found in NBRT';
                                                }
                                                if(!$pitchStageId) {
                                                        $responseStatus['reason'] = 'Mapping for pitch stage \''.$pitchStage.'\' not found in NBRT';
                                                }
                                                if(!$networkBrandId) {
                                                        $responseStatus['reason'] = 'Mapping for network brand \''.$networkBrand.'\' not found in NBRT';
                                                }
                                                if(!empty($responseStatus)) {
                                                        $responseStatus['date_n_time'] = $currTime;
                                                        $email = new CakeEmail('gmail');
                                                        $email->viewVars(array('title_for_layout' => 'Connect < > NBRT reconciliation failed', 'type' => 'Client data', 'data' => $responseStatus));
                                                        $email->template('nbr_reconciliation_fail', 'default')
                                                            ->emailFormat('html')
                                                            ->to($emailList)
                                                            ->from(array('connectiprospect@gmail.com' => 'Connect iProspect'))
                                                            ->subject('Connect < > NBRT reconciliation failed')
                                                            ->send();

                                                        CakeLog::write('error', 'NBRT reconciliation failed. '. $responseStatus['reason'] .'.', 'reconciliation');
                                                        // closing all the curl sessions at the end
                                                        curl_close ( $ch );
                                                        curl_close ( $ch1 );
                                                        curl_close ( $ch2 );
                                                        exit(0);
                                                }

                                                //request to check whether entry of a pitch for the client exists under the country pitch list
                                                $pitchExistsUrl = $siteUrl . $countryCode .'/_api/web/lists/getbytitle(\'Pitch\')/items';
                                                $pitchExistsFilter = urlencode('DACLient eq ' . $clientId . ' and DALeadCountry eq ' . $countryId . ' and DANetworkBrand eq ' . $networkBrandId . ' and DAPitchStatus eq ' . $pitchStatusId . ' and DAArchivePitch eq 0'); // and DATypeOfNetwork eq \'Digital and Creative\'
                                                $pitchExistsUrl = $pitchExistsUrl . '?$filter=' . $pitchExistsFilter;
                                                curl_setopt( $ch, CURLOPT_URL, $pitchExistsUrl );
                                                $pitchExistsContent = json_decode(curl_exec( $ch ));
                                                //echo '<pre>'; print_r($pitchExistsContent); echo '</pre>';
                                                if(isset($pitchExistsContent->error)) {
                                                        $errorMsg = $pitchExistsContent->error->message->value;
                                                        if(strstr($errorMsg, 'Access denied') !== false) {
                                                                // send an email notification to admins
                                                                $responseStatus = array();
                                                                $responseStatus['date_n_time'] = $currTime;
                                                                $responseStatus['reason'] = 'Access to a country \''.$country.'\' denied in NBR. Please grant access ASAP.';
                                                                $email = new CakeEmail('gmail');
                                                                $email->viewVars(array('title_for_layout' => 'Connect < > NBRT reconciliation failed', 'type' => 'Client data', 'data' => $responseStatus));
                                                                $email->template('nbr_reconciliation_fail', 'default')
                                                                    ->emailFormat('html')
                                                                    ->to($emailList)
                                                                    ->from(array('connectiprospect@gmail.com' => 'Connect iProspect'))
                                                                    ->subject('Connect < > NBRT reconciliation failed')
                                                                    ->send();

                                                                CakeLog::write('error', 'NBRT reconciliation failed. Access to a country \''.$country.'\' denied in NBR.', 'reconciliation');
                                                                // closing all the curl sessions at the end
                                                                curl_close ( $ch );
                                                                curl_close ( $ch1 );
                                                                curl_close ( $ch2 );
                                                                exit(0);
                                                        }
                                                }
                                                $pitchExistsResult = (isset($pitchExistsContent->d)) ? $pitchExistsContent->d : null;
                                                //echo '<pre>'; print_r($pitchExistsContent); echo '</pre>';
                                                if(empty($pitchExistsResult->results)) {
                                                // if entry does not exist, create new entry
                                                        $data = array (
                                                            'ClientId' => $clientId,
                                                            'CountryId' => $countryId,
                                                            'IndustryCateogryId' => $industryCategoryId,
                                                            'ClientNotes' => implode(', ', $arrComments),
                                                            'TypeOfPitchValue' => $typeOfPitch,
                                                            'DatePitchRaised' => $dtCreated,
                                                            'EstAnnualRevenue' => $estimatedRevenue,
                                                            'EstAnnualRevenueGBP' => $estimatedRevenueGBP,
                                                            'EstAnnualRevenueUSD' => $estimatedRevenueUSD,
                                                            'PitchStatusId' => $pitchStatusId,
                                                            'PitchStageId' => $pitchStageId,
                                                            'PitchStartDate' => $pitchDate,
                                                            'NetworkBrandId' => $networkBrandId,
                                                            'LeadCountryId' => $countryId,
                                                            'Cities' => implode(', ', $arrCities),
                                                            'ClientHolidngCompany' => $clientHolidngCompany,
                                                            'PitchClosedDate' => $pitchCloseDate,
                                                            'HoldingBrandName' => $holdingBrand,
                                                            'MultipleNetworksInvolved' => $multipleNetworksInvolved,
                                                            'ScopeValue' => $scope,
                                                            'SupportNetwork' => $supportNetwork,
                                                            'TypeOfNetworkValue' => $typeOfNetwork,
                                                            'ArchivePitch' => $isArchivePitch,
                                                            'OtherCountrySInvolved' => implode(', ', $activeMarkets),
                                                            'Services' => implode(', ', $arrServices)
                                                        );
                                                        //echo json_encode($data) . "<br/>";
                                                        $url1 = $siteUrl . $countryCode .'/_vti_bin/listdata.svc/Pitch';
                                                        curl_setopt($ch1, CURLOPT_POSTFIELDS, json_encode($data));
                                                        curl_setopt( $ch1, CURLOPT_URL, $url1 );
                                                        $savedContent = json_decode(curl_exec( $ch1 ));
                                                        //echo '<pre>'; print_r($savedContent); echo '</pre>';
                                                        $arrRecordsCorrected[] = array(
                                                            'country' => $country,
                                                            'client_name' => $client['ClientRevenueByService']['client_name'],
                                                            'pitch_status' => $pitchStatus,
                                                            'services' => implode(', ', $arrServices),
                                                            'revenue' => $estimatedRevenueUSD
                                                        );
                                                        $totalNbrRevenue += $estimatedRevenueUSD;
                                                        $totalNbrRevenueByCountry[$country] += $estimatedRevenueUSD;
                                                        $totalNbrRevenueByPitchStatus[$pitchStatus] += $estimatedRevenueUSD;
                                                        $noOfRecordsSynced++;
                                                } else {
                                                // if entry already exists
                                                        $diffRevenueUSD = $estimatedRevenueUSD - $pitchExistsResult->results[0]->DAEstimatedAnnualRevenueUSD;
                                                        if($diffRevenueUSD > 1 || $diffRevenueUSD < -1) {
                                                                $data = array (
                                                                        'ClientId' => $clientId,
                                                                        'CountryId' => $countryId,
                                                                        'IndustryCateogryId' => $industryCategoryId,
                                                                        'ClientNotes' => implode(', ', $arrComments),
                                                                        'TypeOfPitchValue' => $typeOfPitch,
                                                                        'DatePitchRaised' => $dtCreated,
                                                                        'EstAnnualRevenue' => $estimatedRevenue,
                                                                        'EstAnnualRevenueGBP' => $estimatedRevenueGBP,
                                                                        'EstAnnualRevenueUSD' => $estimatedRevenueUSD,
                                                                        'PitchStatusId' => $pitchStatusId,
                                                                        'PitchStageId' => $pitchStageId,
                                                                        'PitchStartDate' => $pitchDate,
                                                                        'NetworkBrandId' => $networkBrandId,
                                                                        'LeadCountryId' => $countryId,
                                                                        'Cities' => implode(', ', $arrCities),
                                                                        'ClientHolidngCompany' => $clientHolidngCompany,
                                                                        'PitchClosedDate' => $pitchCloseDate,
                                                                        'HoldingBrandName' => $holdingBrand,
                                                                        'MultipleNetworksInvolved' => $multipleNetworksInvolved,
                                                                        'ScopeValue' => $scope,
                                                                        'SupportNetwork' => $supportNetwork,
                                                                        'TypeOfNetworkValue' => $typeOfNetwork,
                                                                        'ArchivePitch' => $isArchivePitch,
                                                                        'OtherCountrySInvolved' => implode(', ', $activeMarkets),
                                                                        'Services' => implode(', ', $arrServices)
                                                                );
                                                                // request to update revenue value for the existing entry
                                                                $url2 = $siteUrl . $countryCode .'/_vti_bin/listdata.svc/Pitch('.$pitchExistsResult->results[0]->Id.')';
                                                                curl_setopt($ch2, CURLOPT_POSTFIELDS, json_encode($data));
                                                                curl_setopt( $ch2, CURLOPT_URL, $url2 );
                                                                $updatedContent = json_decode(curl_exec( $ch2 ));
                                                                //echo '<pre>'; print_r($updatedContent); echo '</pre>';
                                                                $arrRecordsCorrected[] = array(
                                                                    'country' => $country,
                                                                    'client_name' => $client['ClientRevenueByService']['client_name'],
                                                                    'pitch_status' => $pitchStatus,
                                                                    'services' => implode(', ', $arrServices),
                                                                    'revenue' => $estimatedRevenueUSD
                                                                );
                                                                $totalNbrRevenue += $diffRevenueUSD;
                                                                $totalNbrRevenueByCountry[$country] += $diffRevenueUSD;
                                                                $totalNbrRevenueByPitchStatus[$pitchStatus] += $diffRevenueUSD;
                                                                $noOfRecordsSynced++;
                                                        }
                                                }
                                        }
                                }
                        }
                }
                // closing all the curl sessions at the end
                curl_close ( $ch );
                curl_close ( $ch1 );
                curl_close ( $ch2 );

                // mail notification on successful execution of reconciliation
                $responseStatus = array();
                $responseStatus['date_n_time'] = $currTime;
                $responseStatus['no_of_records_checked'] = $noOfRecords;
                $responseStatus['totals'] = array('connect' => $totalRevenue, 'nbr' => $totalNbrRevenue);
                $responseStatus['country_totals'] = array('connect' => $totalRevenueByCountry, 'nbr' => $totalNbrRevenueByCountry);
                $responseStatus['pitch_totals'] = array('connect' => $totalRevenueByPitchStatus, 'nbr' => $totalNbrRevenueByPitchStatus);
                $responseStatus['no_of_records_corrected'] = $noOfRecordsSynced;
                $responseStatus['records_corrected'] = $arrRecordsCorrected;
                $email = new CakeEmail('gmail');
                $email->viewVars(array('title_for_layout' => 'Connect < > NBRT reconciliation completed', 'type' => 'Client data', 'data' => $responseStatus));
                $email->template('nbr_reconciliation_success', 'default')
                    ->emailFormat('html')
                    ->to($emailList)
                    ->from(array('connectiprospect@gmail.com' => 'Connect iProspect'))
                    ->subject('Connect < > NBRT reconciliation completed successfully')
                    ->send();

                CakeLog::write('info', 'NBRT reconciliation completed successfully. time of execution : ' .$currTime. '.', 'reconciliation');
                $this->out('Reconciliation completed....');
        }

        public function mailList() {
                $this->UserLoginRole->Behaviors->attach('Containable');
                $globalUsers = $this->UserLoginRole->find('all', array('fields' => array('User.display_name', 'User.email_id'), 'contain' => array('User', 'LoginRole'), 'conditions' => array('LoginRole.name' => 'Global', 'User.daily_sync_mail' => 1), 'order' => 'User.display_name'));

                $emailTo = array('sam.pitcher@dentsuaegis.com');
                foreach($globalUsers as $globalUser) {
                        $emailTo[] = $globalUser['User']['email_id'];
                }

                return $emailTo;
        }

        public function getNbrCountry($countryUrl) {
                $userpwd = 'MEDIA\sysSP-P-NBR:Jfo829/K!';
                // curl object for read requests
                $ch = curl_init();
                //curl_setopt( $ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.7.3) Gecko/20041001 Firefox/0.10.1" );
                //curl_setopt( $ch, CURLOPT_COOKIEJAR, $cookie );
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 25 );
                curl_setopt( $ch, CURLOPT_TIMEOUT, 25 );
                curl_setopt($ch, CURLOPT_USERPWD, $userpwd);
                curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_NTLM);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("accept: application/json;odata=verbose"));

                curl_setopt( $ch, CURLOPT_URL, $countryUrl );
                $countryContent = json_decode(curl_exec( $ch ));
                $countryResult = $countryContent->d->results;
                foreach($countryResult as $result) {
                        $this->nbrCountries[$result->Id] = $result->Title;
                }
                if(isset($countryContent->d->__next)) {
                        $this->getNbrCountry($countryContent->d->__next);
                }

                return $this->nbrCountries;
        }

        public function getNbrCountryData($countryPitchUrl) {
                $userpwd = 'MEDIA\sysSP-P-NBR:Jfo829/K!';
                // curl object for read requests
                $ch = curl_init();
                //curl_setopt( $ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.7.3) Gecko/20041001 Firefox/0.10.1" );
                //curl_setopt( $ch, CURLOPT_COOKIEJAR, $cookie );
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 25 );
                curl_setopt( $ch, CURLOPT_TIMEOUT, 25 );
                curl_setopt($ch, CURLOPT_USERPWD, $userpwd);
                curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_NTLM);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("accept: application/json;odata=verbose"));

                curl_setopt( $ch, CURLOPT_URL, $countryPitchUrl );
                $countryPitchContent = json_decode(curl_exec( $ch ));
                //echo '<pre>'; print_r($countryPitchContent); echo '</pre>'; exit(0);
                $countryPitchResult = (isset($countryPitchContent->d)) ? $countryPitchContent->d : null;
                //echo '<pre>'; print_r($countryPitchResult); echo '</pre>'; exit(0);
                if($countryPitchResult != null) {
                        foreach($countryPitchResult->results as $result) {
                                $this->nbrCountryData['results'][] = $result;
                        }
                }
                if(isset($countryPitchContent->d->__next)) {
                        $this->getNbrCountryData($countryPitchContent->d->__next);
                }

                return $this->nbrCountryData;
        }
}
