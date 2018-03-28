<?php
App::uses('CakeEmail', 'Network/Email');

class ReportsController extends AppController {
	public $helpers = array('Html', 'Form');

        public $components = array('RequestHandler');

        public $uses = array(
            'City',
            'ClientCategory',
            'Country',
            'Currency',
            'LeadAgency',
            'Market',
            'Region',
            'Service',
            'ClientRevenueByService',
            'UserMarket',
            'Office',
            'OfficeAttribute',
            'OfficeKeyContact',
            'OfficeServiceContact',
            'OfficeLanguage',
            'OfficeEmployeeCountByDepartment',
            'Language',
            'PitchStage',
            'UserLoginRole',
            'ClientDeleteLog',
            'UserMailNotificationClient',
            'ClientActualRevenueByYear',
            'UserGridPreference',
            'UpdatePitchNotification'
        );

        //public $serviceMap = array(1 => 'Affiliates', 19 => 'Attribution', 2 => 'Content', 3 => 'Conversion', 4 => 'Data', 5 => 'Development', 6 => 'Display', 7 => 'Feeds', 8 => 'Lead', 9 => 'Mobile', 10 => 'RTB', 11 => 'Search', 12 => 'SEO', 13 => 'SocialPaid', 14 => 'SocialManagement', 15 => 'Strategy', 16 => 'Technology', 17 => 'Video');

        public $unwanted_array = array( 'Š'=>'S', 'š'=>'s', 'Ž'=>'Z', 'ž'=>'z', 'À'=>'A', 'Á'=>'A', 'Â'=>'A', 'Ã'=>'A', 'Ä'=>'A', 'Å'=>'A', 'Æ'=>'A', 'Ç'=>'C', 'È'=>'E', 'É'=>'E',
                            'Ê'=>'E', 'Ë'=>'E', 'Ì'=>'I', 'Í'=>'I', 'Î'=>'I', 'Ï'=>'I', 'Ñ'=>'N', 'Ò'=>'O', 'Ó'=>'O', 'Ô'=>'O', 'Õ'=>'O', 'Ö'=>'O', 'Ø'=>'O', 'Ù'=>'U',
                            'Ú'=>'U', 'Û'=>'U', 'Ü'=>'U', 'Ý'=>'Y', 'Þ'=>'B', 'ß'=>'Ss', 'à'=>'a', 'á'=>'a', 'â'=>'a', 'ã'=>'a', 'ä'=>'a', 'å'=>'a', 'æ'=>'a', 'ç'=>'c',
                            'è'=>'e', 'é'=>'e', 'ê'=>'e', 'ë'=>'e', 'ì'=>'i', 'í'=>'i', 'î'=>'i', 'ï'=>'i', 'ð'=>'o', 'ñ'=>'n', 'ò'=>'o', 'ó'=>'o', 'ô'=>'o', 'õ'=>'o',
                            'ö'=>'o', 'ø'=>'o', 'ù'=>'u', 'ú'=>'u', 'û'=>'u', 'ý'=>'y', 'þ'=>'b', 'ÿ'=>'y', '\''=>'', '"'=>'', ' '=>'', '`'=>'', '’'=>'', '-'=>'' );


        public $months = array(1 => 'Jan (1)', 'Feb (2)', 'Mar (3)', 'Apr (4)', 'May (5)', 'Jun (6)', 'Jul (7)', 'Aug (8)', 'Sep (9)', 'Oct (10)', 'Nov (11)', 'Dec (12)');

        public function beforeFilter() {

                $this->Auth->loginAction = array(
                  'controller' => 'users',
                  'action' => 'login'
                );
                $this->Auth->logoutRedirect = array(
                  'controller' => 'users',
                  'action' => 'login'
                );
                $this->Auth->loginRedirect = array(
                  'controller' => 'dashboard',
                  'action' => 'index'
                );
                $this->Auth->loginRedirect = array(
                  'controller' => 'dashboard',
                  'action' => 'index'
                );
        }

        public function beforeRender() {
                $this->set('admNavLinks', parent::generateNav($this->arrNav, $this->Auth->user()));
        }

        public function client_data() {

                $this->set('userRole', $this->Auth->user('role'));
                $this->set('categories', json_encode($this->ClientCategory->find('list', array('fields' => array('ClientCategory.category', 'ClientCategory.category'), 'order' => 'ClientCategory.category Asc'))));
                $countries = $this->Country->find('list', array('fields' => array('Country.country', 'Country.country'), 'order' => 'Country.country Asc'));
                $this->set('countries', json_encode($countries, JSON_HEX_APOS));
                $this->set('currencies', json_encode($this->Currency->find('list', array('fields' => array('Currency.currency', 'Currency.currency'), 'order' => 'Currency.currency Asc'))));
                $this->set('agencies', json_encode($this->LeadAgency->find('list', array('fields' => array('LeadAgency.agency', 'LeadAgency.agency'), 'order' => 'LeadAgency.agency Asc'))));
                $this->set('stages', json_encode($this->PitchStage->find('list', array('conditions' => array('NOT' => array('PitchStage.id' => array(11)))),array('fields' => array('PitchStage.pitch_stage', 'PitchStage.pitch_stage'), 'order' => 'PitchStage.id Asc'))));
                $arrMarkets = array();
                $arrRegions = array();
                $arrCities = array();
                if ($this->Auth->user('role') == 'Regional') {
                        $userRegion = $this->UserMarket->find('list', array('fields' => array('UserMarket.id', 'UserMarket.market_id'), 'conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $regions = $this->Region->find('all', array('conditions' => array('Region.id IN (' . implode(',', $userRegion) . ')'), 'order' => 'Region.region Asc'));
                } elseif($this->Auth->user('role') == 'Country' || $this->Auth->user('role') == 'Country - Viewer') {
                        $userCountry = $this->UserMarket->find('list', array('fields' => array('UserMarket.id', 'UserMarket.market_id'), 'conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $userRegion = $this->Market->find('list', array('fields' => array('Market.id', 'Market.region_id'), 'conditions' => array('Market.country_id IN (' . implode(',', $userCountry) . ')'), 'order' => 'Market.region_id Asc', 'group' => 'Market.region_id'));
                        $regions = $this->Region->find('all', array('conditions' => array('Region.id IN (' . implode(',', $userRegion) . ')'), 'order' => 'Region.region Asc'));
                } else {
                        $regions = $this->Region->find('all', array('order' => 'Region.region Asc'));
                }
                foreach ($regions as $region) {
                        //$arrMarkets[$region['Region']['region']] = 'Regional - ' . $region['Region']['region'];
                        $arrRegions[$region['Region']['region']] = $region['Region']['region'];
                        if($this->Auth->user('role') == 'Country' || $this->Auth->user('role') == 'Country - Viewer') {
                                $markets = $this->Market->find('list', array('fields' => array('Market.country_id', 'Market.market'), 'conditions' => array('Market.region_id' => $region['Region']['id'], 'Market.country_id IN (' . implode(',', $userCountry) . ')'), 'order' => 'Market.market Asc'));
                        } else {
                                $markets = $this->Market->find('list', array('fields' => array('Market.country_id', 'Market.market'), 'conditions' => array('Market.region_id' => $region['Region']['id']), 'order' => 'Market.market Asc'));
                        }
                        if(!empty($markets)) {
                                foreach ($markets as $countryId => $market) {
                                        $arrMarkets[$region['Region']['region']][$market] = $market;
                                        $cities = $this->City->find('list', array('fields' => array('City.city', 'City.city'), 'conditions' => array('City.country_id' => $countryId), 'order' => 'City.city Asc'));
                                        if(!empty($cities)) {
                                                $arrCities[$market] = $cities;
                                        }
                                }
                        }
                }
                $arrPreference = $this->UserGridPreference->find('first', array('fields' =>array('UserGridPreference.preference'),'conditions' => array('UserGridPreference.user_id' => $this->Auth->user('id'),'UserGridPreference.formname' =>'client_data')));
                if(!empty($arrPreference)) {
                        $this->set('widthPreferences_client_data', $arrPreference['UserGridPreference']['preference']);
                } else {
                        $this->set('widthPreferences_client_data', '{}');
                }
                $arrClientSinceYear = array();
                $clientsinceyears = $this->ClientRevenueByService->find('all',array('fields' => array('ClientRevenueByService.client_since_year'), 'conditions' => array("client_since_year != '0000-00-00'"),'order' => 'ClientRevenueByService.client_since_year Asc', 'group' => 'client_since_year'));
                foreach($clientsinceyears as $clientsinceyear) {
                    $arrClientSinceYear[] = $clientsinceyear['ClientRevenueByService']['client_since_year'];
                }
                $this->set('clientSinceYear',json_encode($arrClientSinceYear));
                $arrLostYear = array();
                $lostsinceyears = $this->ClientRevenueByService->find('all',array('fields' => array('YEAR(ClientRevenueByService.lost_date) as lost_year'), 'conditions' => array("lost_date != '0000-00-00'"), 'order' => 'ClientRevenueByService.lost_date Asc', 'group' => 'lost_year'));
                foreach($lostsinceyears as $lostsinceyear) {
                    $arrLostYear[] = $lostsinceyear[0]['lost_year'];
                }
                $this->set('lostsinceyear',json_encode($arrLostYear));
                $arrPitchedYear = array();
                $pitchedyears = $this->ClientRevenueByService->find('all',array('fields' => array('YEAR(ClientRevenueByService.pitch_date) as pitch_year'), 'conditions' => array("pitch_date != '0000-00-00'"), 'order' => 'ClientRevenueByService.pitch_date Asc', 'group' => 'pitch_year'));
                foreach($pitchedyears as $pitchedyears) {
                    $arrPitchedYear[] = $pitchedyears[0]['pitch_year'];
                }
                $this->set('pitchyear',json_encode($arrPitchedYear));
                $this->set('regions', json_encode($arrRegions));
                $this->set('markets', json_encode($arrMarkets));
                $this->set('cities', json_encode($arrCities));
                $this->set('services', json_encode($this->Service->find('list', array('fields' => array('Service.service_name', 'Service.service_name'), 'order' => 'Service.service_name Asc'))));
                $this->set('currMonth', date('n'));
                $this->set('currYear', date('Y'));
	}
        
        public function current_client_data(){
            
                $this->set('userRole', $this->Auth->user('role'));
                $this->set('categories', json_encode($this->ClientCategory->find('list', array('fields' => array('ClientCategory.category', 'ClientCategory.category'), 'order' => 'ClientCategory.category Asc'))));
                $countries = $this->Country->find('list', array('fields' => array('Country.country', 'Country.country'), 'order' => 'Country.country Asc'));
                $this->set('countries', json_encode($countries, JSON_HEX_APOS));
                $this->set('currencies', json_encode($this->Currency->find('list', array('fields' => array('Currency.currency', 'Currency.currency'), 'order' => 'Currency.currency Asc'))));
                $this->set('agencies', json_encode($this->LeadAgency->find('list', array('fields' => array('LeadAgency.agency', 'LeadAgency.agency'), 'order' => 'LeadAgency.agency Asc'))));
                $this->set('stages', json_encode($this->PitchStage->find('list', array('conditions' => array('PitchStage.id' => array(7))),array('fields' => array('PitchStage.pitch_stage', 'PitchStage.pitch_stage'), 'order' => 'PitchStage.id Asc'))));
                //$arrMarkets = array('Global' => 'Global');
                $arrMarkets = array();
                $arrRegions = array();
                $arrCities = array();
                if ($this->Auth->user('role') == 'Regional') {
                        $userRegion = $this->UserMarket->find('list', array('fields' => array('UserMarket.id', 'UserMarket.market_id'), 'conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $regions = $this->Region->find('all', array('conditions' => array('Region.id IN (' . implode(',', $userRegion) . ')'), 'order' => 'Region.region Asc'));
                } elseif($this->Auth->user('role') == 'Country' || $this->Auth->user('role') == 'Country - Viewer') {
                        $userCountry = $this->UserMarket->find('list', array('fields' => array('UserMarket.id', 'UserMarket.market_id'), 'conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $userRegion = $this->Market->find('list', array('fields' => array('Market.id', 'Market.region_id'), 'conditions' => array('Market.country_id IN (' . implode(',', $userCountry) . ')'), 'order' => 'Market.region_id Asc', 'group' => 'Market.region_id'));
                        $regions = $this->Region->find('all', array('conditions' => array('Region.id IN (' . implode(',', $userRegion) . ')'), 'order' => 'Region.region Asc'));
                } else {
                        $regions = $this->Region->find('all', array('order' => 'Region.region Asc'));
                }
                foreach ($regions as $region) {
                        //$arrMarkets[$region['Region']['region']] = 'Regional - ' . $region['Region']['region'];
                        $arrRegions[$region['Region']['region']] = $region['Region']['region'];
                        if($this->Auth->user('role') == 'Country' || $this->Auth->user('role') == 'Country - Viewer') {
                                $markets = $this->Market->find('list', array('fields' => array('Market.country_id', 'Market.market'), 'conditions' => array('Market.region_id' => $region['Region']['id'], 'Market.country_id IN (' . implode(',', $userCountry) . ')'), 'order' => 'Market.market Asc'));
                        } else {
                                $markets = $this->Market->find('list', array('fields' => array('Market.country_id', 'Market.market'), 'conditions' => array('Market.region_id' => $region['Region']['id']), 'order' => 'Market.market Asc'));
                        }
                        if(!empty($markets)) {
                                foreach ($markets as $countryId => $market) {
                                        $arrMarkets[$region['Region']['region']][$market] = $market;
                                        $cities = $this->City->find('list', array('fields' => array('City.city', 'City.city'), 'conditions' => array('City.country_id' => $countryId), 'order' => 'City.city Asc'));
                                        if(!empty($cities)) {
                                                $arrCities[$market] = $cities;
                                        }
                                }
                        }
                }
                $arrPreference = $this->UserGridPreference->find('first', array('fields' =>array('UserGridPreference.preference'),'conditions' => array('UserGridPreference.user_id' => $this->Auth->user('id'),'UserGridPreference.formname' =>'current_client_data')));
                if(!empty($arrPreference)) {
                        $this->set('widthPreferences_client_data', $arrPreference['UserGridPreference']['preference']);
                } else {
                        $this->set('widthPreferences_client_data', '{}');
                }
                $this->set('regions', json_encode($arrRegions));
                $this->set('markets', json_encode($arrMarkets));
                $this->set('cities', json_encode($arrCities));
                $this->set('services', json_encode($this->Service->find('list', array('fields' => array('Service.service_name', 'Service.service_name'), 'order' => 'Service.service_name Asc'))));
                $this->set('currMonth', date('n'));
                $this->set('currYear', date('Y'));
  
        }
        
        function search_client() {

                $this->autoRender=false;

                $arrData = $this->request->data;

                $searchResult = array();
                if (!empty($arrData['name_startsWith'])) {
                        $clients = $this->ClientRevenueByService->find('all', array('fields' => array('DISTINCT client_name', 'parent_company'), 'conditions' => ('client_name like \'' . $arrData['name_startsWith'] . '%\''), 'order' => 'client_name ASC'));
                        foreach ($clients as $client) {
                                $searchResult[] = array('advertiser_name' => $client['ClientRevenueByService']['client_name'], 'parent_company' => $client['ClientRevenueByService']['parent_company']);
                        }
                }
                return json_encode($searchResult);
        }

        public function save_client_record() {

                if ($this->request->isPost()) {
                        if($this->RequestHandler->isAjax()) {
                                $this->autoRender=false;
                        }

                        $arrData = $this->request->data;

                        $category = $this->ClientCategory->findByCategory(trim($arrData['ClientCategory']));
                        $region = $this->Region->findByRegion(trim($arrData['Region']));
                        if(trim($arrData['Country']) == 'Global') {
                                $managingEntity = 'Global';
                                $country = null;
                                $city = null;
                        } elseif(strpos(trim($arrData['Country']), 'Regional') !== false) {
                                $managingEntity = 'Regional';
                                $country = null;
                                $city = null;
                        } else {
                                $managingEntity = 'Country';
                                $country = $this->Market->findByMarket(trim($arrData['Country']));
                                $city = $this->City->findByCity(trim($arrData['City']));
                        }
                        $agency = $this->LeadAgency->findByAgency(trim($arrData['LeadAgency']));
                        $currency = $this->Currency->findByCurrency(trim($arrData['Currency']));
                        $service = $this->Service->findByServiceName(trim($arrData['Service']));

                        if(!empty($category)) {
                                $categoryId = $category['ClientCategory']['id'];
                        } else {
                                $categoryId = 0;
                        }
                        if(!empty($region)) {
                                $regionId = $region['Region']['id'];
                        } else {
                                $regionId = 0;
                        }
                        if(!empty($country)) {
                                $countryId = $country['Market']['country_id'];
                        } else {
                                $countryId = 0;
                        }
                        if(!empty($city)) {
                                $cityId = $city['City']['id'];
                        } else {
                                $cityId = 0;
                        }
                        if(!empty($agency) > 0) {
                                $agencyId = $agency['LeadAgency']['id'];
                        } else {
                                $agencyId = 0;
                        }
                        if(!empty($currency) > 0) {
                                $currencyId = $currency['Currency']['id'];
                        } else {
                                $currencyId = 0;
                        }
                        if(!empty($service) > 0) {
                                $serviceId = $service['Service']['id'];
                        } else {
                                $serviceId = 0;
                        }
                        $pitchStage = $arrData['PitchStage'];
                        $pitchStart = explode('/', $arrData['PitchStart']);
                        $pitchDate = $pitchStart[1] . '-' . $pitchStart[0] . '-01';
                        //$pitchLeader = $arrData['PitchLeader'];
                        $clientSinceMonth = null;
                        $clientSinceYear = null;
                        if(!preg_match('/Live/', $pitchStage) && $pitchStage != 'Cancelled' && $pitchStage != 'Declined') {
                            if(preg_match('/Lost - new/', $pitchStage)) {
                                    $clientSinceMonth = null;
                                    $clientSinceYear = null;
                            } else {
                                    $clientSince = explode('/', $arrData['ClientSince']);
                                    $clientSinceMonth = $clientSince[0];
                                    $clientSinceYear = $clientSince[1];
                            }
                        }
                        if(preg_match('/Lost/', $pitchStage) || $pitchStage == 'Cancelled' || $pitchStage == 'Declined') {
                                $lost = explode('/', $arrData['LostDate']);
                                $lostDate = $lost[1] . '-' . $lost[0] . '-01';
                        } else {
                                $lostDate = '0000-00-00';
                        }
                        $marketScope = $arrData['MarketScope'];
                        $activeMarkets = $arrData['ActiveMarkets'];
                        $companyName = $arrData['ParentCompany'];
                        $clientName = $arrData['ClientName'];
                        $estimatedRevenue = $arrData['EstimatedRevenue'];
                        $fiscalRevenue = $arrData['FiscalRevenue'];
                        $comments = $arrData['Comments'];
                        $parentId = $arrData['parentId'];

                        $this->ClientRevenueByService->create();
                        $this->ClientRevenueByService->save(
                                array(
                                        'ClientRevenueByService' => array(
                                                'pitch_date' => $pitchDate,
                                                //'pitch_leader' => $pitchLeader,
                                                'pitch_stage' => $pitchStage,
                                                'client_name' => $clientName,
                                                'parent_company' => $companyName,
                                                'comments' => $comments,
                                                'category_id' => $categoryId,
                                                'client_since_month' => $clientSinceMonth,
                                                'client_since_year' => $clientSinceYear,
                                                'lost_date' => $lostDate,
                                                'agency_id' => $agencyId,
                                                'region_id' => $regionId,
                                                'managing_entity' => $managingEntity,
                                                'country_id' => $countryId,
                                                'city_id' => $cityId,
                                                'market_scope' => $marketScope,
                                                'active_markets' => $activeMarkets,
                                                'service_id' => $serviceId,
                                                'currency_id' => $currencyId,
                                                'estimated_revenue' => $estimatedRevenue,
                                                'fiscal_revenue'=> $fiscalRevenue,
                                                'year' => date('Y'),
                                                'parent_id' => $parentId,
                                                'created' => date('Y-m-d H:i:s')
                                        )
                                )
                        );
                }
                $result = array();
                if ($arrData) {
                // script to send new pitch notification to users opted for notifications for specific clients
                        $this->UserLoginRole->Behaviors->attach('Containable');
                        $globalUsers = $this->UserLoginRole->find('all', array('fields' => array('User.display_name', 'User.email_id', 'User.id'), 'contain' => array('User', 'LoginRole'), 'conditions' => array('LoginRole.name' => 'Global', 'User.client_specific_mail' => 1), 'order' => 'User.display_name'));

                        $emailTo = array();
                        foreach($globalUsers as $globalUser) {
                                $isSpecificClientAlert = $this->UserMailNotificationClient->find('count', array('conditions' => array('user_id' => $globalUser['User']['id'])));
                                if($isSpecificClientAlert > 0) {
                                        $isClientAlert = $this->UserMailNotificationClient->find('count', array('conditions' => array('user_id' => $globalUser['User']['id'], 'client_name' => $arrData['ClientName'])));
                                        if($isClientAlert > 0) {
                                                $emailTo[] = $globalUser['User']['email_id'];
                                        }
                                }
                        }

                        if(!empty($emailTo)) {
                                try {
                                        $email = new CakeEmail('gmail');
                                        $email->viewVars(array('title_for_layout' => 'Client & New Business data', 'type' => 'New Pitch', 'data' => $arrData));
                                        $email->template('new_pitch', 'default')
                                            ->emailFormat('html')
                                            ->to($emailTo)
                                            ->from(array('connectiprospect@gmail.com' => 'Connect iProspect'))
                                            ->subject('New pitch added for ' . $arrData['ClientName'])
                                            ->send();
                                } catch (Exception $e) {
                                        $result['mailError'] = $e->getMessage();
                                }
                        }
                }
                $result['success'] = true;
                return json_encode($result);
        }

        public function delete_client_record() {
                if ($this->request->isPost()) {
                        if($this->RequestHandler->isAjax()) {
                                $this->autoRender=false;
                        }

                        $result = array();
                        $arrData = $this->request->data;
                        $clientRecord = $this->ClientRevenueByService->findById($arrData['RecordId']);
                        $clientRecord['loggedUser']['display_name'] = $this->Session->read('loggedUser.displayName');

                        if ($this->ClientRevenueByService->delete($arrData['RecordId'])) {
                                if ($clientRecord) {
                                        $this->ClientDeleteLog->create();
                                        $this->ClientDeleteLog->save(
                                                array(
                                                        'ClientDeleteLog' => array(
                                                                'record_id' => $clientRecord['ClientRevenueByService']['id'],
                                                                'pitch_date' => $clientRecord['ClientRevenueByService']['pitch_date'],
                                                                'pitch_stage' => $clientRecord['ClientRevenueByService']['pitch_stage'],
                                                                'lost_date' => $clientRecord['ClientRevenueByService']['lost_date'],
                                                                'parent_id' => $clientRecord['ClientRevenueByService']['parent_id'],
                                                                'client_name' => $clientRecord['ClientRevenueByService']['client_name'],
                                                                'parent_company' => $clientRecord['ClientRevenueByService']['parent_company'],
                                                                'comments' => $clientRecord['ClientRevenueByService']['comments'],
                                                                'category_id' => $clientRecord['ClientRevenueByService']['category_id'],
                                                                'client_since_month' => $clientRecord['ClientRevenueByService']['client_since_month'],
                                                                'client_since_year' => $clientRecord['ClientRevenueByService']['client_since_year'],
                                                                'agency_id' => $clientRecord['ClientRevenueByService']['agency_id'],
                                                                'region_id' => $clientRecord['ClientRevenueByService']['region_id'],
                                                                'managing_entity' => $clientRecord['ClientRevenueByService']['managing_entity'],
                                                                'country_id' => $clientRecord['ClientRevenueByService']['country_id'],
                                                                'city_id' => $clientRecord['ClientRevenueByService']['city_id'],
                                                                'market_scope' => $clientRecord['ClientRevenueByService']['market_scope'],
                                                                'active_markets' => $clientRecord['ClientRevenueByService']['active_markets'],
                                                                'service_id' => $clientRecord['ClientRevenueByService']['service_id'],
                                                                'currency_id' => $clientRecord['ClientRevenueByService']['currency_id'],
                                                                'estimated_revenue' => $clientRecord['ClientRevenueByService']['estimated_revenue'],
                                                                'fiscal_revenue' => $clientRecord['ClientRevenueByService']['fiscal_revenue'],
                                                                'actual_revenue' => $clientRecord['ClientRevenueByService']['actual_revenue'],
                                                                'year' => $clientRecord['ClientRevenueByService']['year'],
                                                                'created' => ($clientRecord['ClientRevenueByService']['created'] != '') ? $clientRecord['ClientRevenueByService']['created'] : 'NULL',
                                                                'modified' => ($clientRecord['ClientRevenueByService']['modified'] != '') ? $clientRecord['ClientRevenueByService']['modified'] : 'NULL',
                                                                'deleted_by' => $this->Auth->user('id'),
                                                                'deleted' => date('Y-m-d H:i:s')
                                                        )
                                                )
                                        );
                                }

                                $result['success'] = true;
                                return json_encode($result);
                        }
                }
        }

        public function get_client_data() {
                $this->autoRender=false;
                set_time_limit(0);
                ini_set('memory_limit', '-1');

                $clientData = array();
                $i = 0;
                $condition = 'ClientRevenueByService.pitch_stage != "Current client"';
                if ($this->Auth->user('role') == 'Regional') {
                        $regions = $this->UserMarket->find('all', array('conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $arrRegions = array();
                        foreach ($regions as $region) {
                                $arrRegions[] = $region['UserMarket']['market_id'];
                        }
                        $condition = 'ClientRevenueByService.region_id IN (' . implode(',', $arrRegions) . ')' .' AND '. 'ClientRevenueByService.pitch_stage != "Current client"';
                }
                if ($this->Auth->user('role') == 'Country') {
                        $countries = $this->UserMarket->find('all', array('conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $arrCountries = array();
                        foreach ($countries as $country) {
                                $arrCountries[] = $country['UserMarket']['market_id'];
                        }
                        $condition = 'ClientRevenueByService.country_id IN (' . implode(',', $arrCountries) . ')' .' AND '. 'ClientRevenueByService.pitch_stage != "Current client"';
                }
                $clients = $this->ClientRevenueByService->query("CALL allClientsWithFilter('{$condition}');");
            
                foreach ($clients as $client) {
                        $clientData[$i]['id'] = $client['ClientRevenueByService']['id'];
                        $clientData[$i]['RecordId'] = $client['ClientRevenueByService']['id'];
                        $clientData[$i]['Region'] = $client[0]['region'];
                        if ($client['ClientRevenueByService']['managing_entity'] == 'Global') {
                                $clientData[$i]['Country'] = 'Global';
                                $clientData[$i]['City'] = 'Global';
                        } elseif ($client['ClientRevenueByService']['managing_entity'] == 'Regional') {
                                $clientData[$i]['Country'] = 'Regional - ' . $client[0]['region'];
                                $clientData[$i]['City'] = 'Regional - ' . $client[0]['region'];
                        } else {
                                $clientData[$i]['Country'] = $client[0]['country'];
                                $clientData[$i]['City'] = $client[0]['city'];
                        }
                        $clientData[$i]['LeadAgency'] = $client[0]['agency'];
                        $clientData[$i]['ClientName'] = $client['ClientRevenueByService']['client_name'];
                        $clientData[$i]['SearchClientName'] = strtr( $client['ClientRevenueByService']['client_name'], $this->unwanted_array );
                        $clientData[$i]['ParentCompany'] = $client['ClientRevenueByService']['parent_company'];
                        $clientData[$i]['SearchParentCompany'] = strtr( $client['ClientRevenueByService']['parent_company'], $this->unwanted_array );
                        $clientData[$i]['ClientCategory'] = $client[0]['category'];
                        if ($client['ClientRevenueByService']['pitch_date'] != '0000-00-00') {
                                $pitchDate = explode('-', $client['ClientRevenueByService']['pitch_date']);
                                $clientData[$i]['PitchStart'] = $pitchDate[1] . '/' . $pitchDate[0];
                        } else {
                                $clientData[$i]['PitchStart'] = '';
                        }
                        //$clientData[$i]['PitchLeader'] = $client['ClientRevenueByService']['pitch_leader'];
                        $clientData[$i]['PitchStage'] = $client['ClientRevenueByService']['pitch_stage'];
                       if ($client['ClientRevenueByService']['lost_date'] != '0000-00-00') {
                                $lostDate = explode('-', $client['ClientRevenueByService']['lost_date']);
                                $clientData[$i]['Lost'] = $lostDate[1] . '/' . $lostDate[0];
                        } else {
                                $clientData[$i]['Lost'] = '';
                        }
                        $clientData[$i]['ClientMonth'] = ($client['ClientRevenueByService']['client_since_month'] != 0 && $client['ClientRevenueByService']['client_since_month'] != null) ? $this->months[$client['ClientRevenueByService']['client_since_month']] : '';
                        $clientData[$i]['ClientYear'] = $client['ClientRevenueByService']['client_since_year'];
                        if ($client['ClientRevenueByService']['client_since_month'] != 0 && $client['ClientRevenueByService']['client_since_year'] != 0) {
                                $clientData[$i]['ClientSince'] = $client['ClientRevenueByService']['client_since_month']. '/' .$client['ClientRevenueByService']['client_since_year'];
                        } elseif ($client['ClientRevenueByService']['client_since_month'] == 0 && $client['ClientRevenueByService']['client_since_year'] != 0) {
                                $clientData[$i]['ClientSince'] = '01/' .$client['ClientRevenueByService']['client_since_year'];
                        } else {
                                $clientData[$i]['ClientSince'] = '';
                        }
                        $clientData[$i]['Service'] = $client[0]['service_name'];
                        $clientData[$i]['MarketScope'] = $client['ClientRevenueByService']['market_scope'];
                        $clientData[$i]['ActiveMarkets'] = $client['ClientRevenueByService']['active_markets'];
                        $clientData[$i]['Currency'] = $client[0]['currency'];
                        $clientData[$i]['EstimatedRevenue'] = (($client['ClientRevenueByService']['estimated_revenue'] == 0) ? '' : $client['ClientRevenueByService']['estimated_revenue']);
                        $clientData[$i]['FiscalRevenue'] = (($client['ClientRevenueByService']['fiscal_revenue'] == 0) ? '' : $client['ClientRevenueByService']['fiscal_revenue']);
                        $clientData[$i]['ActualRevenue'] = $client['ClientRevenueByService']['actual_revenue'];
                        $clientData[$i]['Comments'] = $client['ClientRevenueByService']['comments'];
                        $clientData[$i]['Year'] = $client['ClientRevenueByService']['year'];
                        $clientData[$i]['ParentId'] = $client['ClientRevenueByService']['parent_id'];

                        $i++;
                }
                echo json_encode($clientData);
        }
        
        public function get_current_client_data(){
                $this->autoRender = false;
                set_time_limit(0);
                ini_set('memory_limit', '-1');

                $clientData = array();
                $i = 0;
                $condition = 'ClientRevenueByService.pitch_stage = "Current client"';
                if ($this->Auth->user('role') == 'Regional') {
                        $regions = $this->UserMarket->find('all', array('conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $arrRegions = array();
                        foreach ($regions as $region) {
                                $arrRegions[] = $region['UserMarket']['market_id'];
                        }
                        $condition = 'ClientRevenueByService.region_id IN (' . implode(',', $arrRegions) . ')' .' AND '. 'ClientRevenueByService.pitch_stage = "Current client"';;
                }
                if ($this->Auth->user('role') == 'Country') {
                        $countries = $this->UserMarket->find('all', array('conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $arrCountries = array();
                        foreach ($countries as $country) {
                                $arrCountries[] = $country['UserMarket']['market_id'];
                        }
                        $condition = 'ClientRevenueByService.country_id IN (' . implode(',', $arrCountries) . ')' .' AND '. 'ClientRevenueByService.pitch_stage = "Current client"';;
                }
                                
                $clients = $this->ClientRevenueByService->query("CALL allClientsWithFilter('{$condition}');");
                foreach ($clients as $client) {
                        $clientData[$i]['id'] = $client['ClientRevenueByService']['id'];
                        $clientData[$i]['RecordId'] = $client['ClientRevenueByService']['id'];
                        $clientData[$i]['Region'] = $client[0]['region'];
                        if ($client['ClientRevenueByService']['managing_entity'] == 'Global') {
                                $clientData[$i]['Country'] = 'Global';
                                $clientData[$i]['City'] = 'Global';
                        } elseif ($client['ClientRevenueByService']['managing_entity'] == 'Regional') {
                                $clientData[$i]['Country'] = 'Regional - ' . $client[0]['region'];
                                $clientData[$i]['City'] = 'Regional - ' . $client[0]['region'];
                        } else {
                                $clientData[$i]['Country'] = $client[0]['country'];
                                $clientData[$i]['City'] = $client[0]['city'];
                        }
                        $clientData[$i]['LeadAgency'] = $client[0]['agency'];
                        $clientData[$i]['ClientName'] = $client['ClientRevenueByService']['client_name'];
                        $clientData[$i]['SearchClientName'] = strtr( $client['ClientRevenueByService']['client_name'], $this->unwanted_array );
                        $clientData[$i]['ParentCompany'] = $client['ClientRevenueByService']['parent_company'];
                        $clientData[$i]['SearchParentCompany'] = strtr( $client['ClientRevenueByService']['parent_company'], $this->unwanted_array );
                        $clientData[$i]['ClientCategory'] = $client[0]['category'];
                        if ($client['ClientRevenueByService']['pitch_date'] != '0000-00-00') {
                                $pitchDate = explode('-', $client['ClientRevenueByService']['pitch_date']);
                                $clientData[$i]['PitchStart'] = $pitchDate[1] . '/' . $pitchDate[0];
                        } else {
                                $clientData[$i]['PitchStart'] = '';
                        }
                        //$clientData[$i]['PitchLeader'] = $client['ClientRevenueByService']['pitch_leader'];
                        $clientData[$i]['PitchStage'] = $client['ClientRevenueByService']['pitch_stage'];
                        if ($client['ClientRevenueByService']['lost_date'] != '0000-00-00') {
                                $lostDate = explode('-', $client['ClientRevenueByService']['lost_date']);
                                $clientData[$i]['Lost'] = $lostDate[1] . '/' . $lostDate[0];
                        } else {
                                $clientData[$i]['Lost'] = '';
                        }
                        $clientData[$i]['ClientMonth'] = ($client['ClientRevenueByService']['client_since_month'] != 0 && $client['ClientRevenueByService']['client_since_month'] != null) ? $this->months[$client['ClientRevenueByService']['client_since_month']] : '';
                        $clientData[$i]['ClientYear'] = $client['ClientRevenueByService']['client_since_year'];
                        if ($client['ClientRevenueByService']['client_since_month'] != 0 && $client['ClientRevenueByService']['client_since_year'] != 0) {
                                $clientData[$i]['ClientSince'] = $client['ClientRevenueByService']['client_since_month']. '/' .$client['ClientRevenueByService']['client_since_year'];
                        } elseif ($client['ClientRevenueByService']['client_since_month'] == 0 && $client['ClientRevenueByService']['client_since_year'] != 0) {
                                $clientData[$i]['ClientSince'] = '01/' .$client['ClientRevenueByService']['client_since_year'];
                        } else {
                                $clientData[$i]['ClientSince'] = '';
                        }
                        $clientData[$i]['Service'] = $client[0]['service_name'];
                        $clientData[$i]['MarketScope'] = $client['ClientRevenueByService']['market_scope'];
                        $clientData[$i]['ActiveMarkets'] = $client['ClientRevenueByService']['active_markets'];
                        $clientData[$i]['Currency'] = $client[0]['currency'];
                        $clientData[$i]['EstimatedRevenue'] = (($client['ClientRevenueByService']['estimated_revenue'] == 0) ? '' : $client['ClientRevenueByService']['estimated_revenue']);
                        $clientData[$i]['FiscalRevenue'] = (($client['ClientRevenueByService']['fiscal_revenue'] == 0) ? '' : $client['ClientRevenueByService']['fiscal_revenue']);
                        $clientData[$i]['ActualRevenue'] = $client['ClientRevenueByService']['actual_revenue'];
                        $clientData[$i]['Comments'] = $client['ClientRevenueByService']['comments'];
                        $clientData[$i]['Year'] = $client['ClientRevenueByService']['year'];
                        $clientData[$i]['ParentId'] = $client['ClientRevenueByService']['parent_id'];

                        $i++;
                }
                echo json_encode($clientData);
           
        }

        public function get_client_report_data() {
                $this->autoRender=false;
                set_time_limit(0);
                ini_set('memory_limit', '-1');

                $clientData = array();
                $i = 0;
                $condition = 'ClientRevenueByService.pitch_stage != "Current client"';
                $revenueCurrency = isset($_GET['revenue_currency']) ? $_GET['revenue_currency'] : 'Actual currencies';
                $currencies = $this->Currency->find('list', array('fields' => array('Currency.convert_rate', 'Currency.currency'), 'order' => 'Currency.currency Asc'));
                $convertRatio = array_search($revenueCurrency, $currencies);
                if ($this->Auth->user('role') == 'Regional') {
                        $regions = $this->UserMarket->find('all', array('conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $arrRegions = array();
                        foreach ($regions as $region) {
                                $arrRegions[] = $region['UserMarket']['market_id'];
                        }
                   $condition = 'ClientRevenueByService.pitch_stage != "Current client"';
                }
                if ($this->Auth->user('role') == 'Country' || $this->Auth->user('role') == 'Country - Viewer') {
                        $countries = $this->UserMarket->find('all', array('conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $arrCountries = array();
                        foreach ($countries as $country) {
                                $arrCountries[] = $country['UserMarket']['market_id'];
                        }
                   $condition = 'ClientRevenueByService.pitch_stage != "Current client"';
                }
                $this->ClientRevenueByService->Behaviors->attach('Containable');
                $clients = $this->ClientRevenueByService->query("CALL allClientsWithFilter('{$condition}');");

                foreach ($clients as $client) {
                        $clientData[$i]['id'] = $client['ClientRevenueByService']['id'];
                        $clientData[$i]['RecordId'] = $client['ClientRevenueByService']['id'];
                        $clientData[$i]['Region'] = $client[0]['region'];
                        if ($client['ClientRevenueByService']['managing_entity'] == 'Global') {
                                $clientData[$i]['Country'] = 'Global';
                                $clientData[$i]['City'] = 'Global';
                        } elseif ($client['ClientRevenueByService']['managing_entity'] == 'Regional') {
                                $clientData[$i]['Country'] = 'Regional - ' . $client[0]['region'];
                                $clientData[$i]['City'] = 'Regional - ' . $client[0]['region'];
                        } else {
                                $clientData[$i]['Country'] = $client[0]['country'];
                                $clientData[$i]['City'] = $client[0]['city'];
                        }
                        $clientData[$i]['LeadAgency'] = $client[0]['agency'];
                        $clientData[$i]['ClientName'] = $client['ClientRevenueByService']['client_name'];
                        $clientData[$i]['SearchClientName'] = strtr( $client['ClientRevenueByService']['client_name'], $this->unwanted_array );
                        $clientData[$i]['ParentCompany'] = $client['ClientRevenueByService']['parent_company'];
                        $clientData[$i]['SearchParentCompany'] = strtr( $client['ClientRevenueByService']['parent_company'], $this->unwanted_array );
                        $clientData[$i]['ClientCategory'] = $client[0]['category'];
                        if ($client['ClientRevenueByService']['pitch_date'] != '0000-00-00') {
                                $pitchDate = explode('-', $client['ClientRevenueByService']['pitch_date']);
                                $clientData[$i]['PitchStart'] = $pitchDate[1] . '/' . $pitchDate[0];
                        } else {
                                $clientData[$i]['PitchStart'] = '';
                        }
                        $clientData[$i]['PitchStage'] = $client['ClientRevenueByService']['pitch_stage'];
                        if ($client['ClientRevenueByService']['lost_date'] != '0000-00-00') {
                                $lostDate = explode('-', $client['ClientRevenueByService']['lost_date']);
                                $clientData[$i]['Lost'] = $lostDate[1] . '/' . $lostDate[0];
                        } else {
                                $clientData[$i]['Lost'] = '';
                        }
                        $clientData[$i]['ClientMonth'] = ($client['ClientRevenueByService']['client_since_month'] != 0 && $client['ClientRevenueByService']['client_since_month'] != null) ? $this->months[$client['ClientRevenueByService']['client_since_month']] : '';
                        $clientData[$i]['ClientYear'] = $client['ClientRevenueByService']['client_since_year'];
                        if ($client['ClientRevenueByService']['client_since_month'] != 0 && $client['ClientRevenueByService']['client_since_year'] != 0) {
                                $clientData[$i]['ClientSince'] = $client['ClientRevenueByService']['client_since_month']. '/' .$client['ClientRevenueByService']['client_since_year'];
                        } elseif ($client['ClientRevenueByService']['client_since_month'] == 0 && $client['ClientRevenueByService']['client_since_year'] != 0) {
                                $clientData[$i]['ClientSince'] = '01/' .$client['ClientRevenueByService']['client_since_year'];
                        } else {
                                $clientData[$i]['ClientSince'] = '';
                        }
                        $clientData[$i]['Service'] = $client[0]['service_name'];
                        $clientData[$i]['MarketScope'] = $client['ClientRevenueByService']['market_scope'];
                        $clientData[$i]['ActiveMarkets'] = $client['ClientRevenueByService']['active_markets'];

                        $estimatedRevenue = 0;
                        $actualRevenue = 0;
                        $fiscalRevenue = 0;
                        $currency = '';
                        if($revenueCurrency == "Actual currencies") {
                                $estimatedRevenue = $client['ClientRevenueByService']['estimated_revenue'];
                                $actualRevenue = $client['ClientRevenueByService']['actual_revenue'];
                                $fiscalRevenue = $client['ClientRevenueByService']['fiscal_revenue'];
                                $currency = $client[0]['currency'];
                        } else {
                                $currency = $revenueCurrency;
                                if(is_numeric($client['ClientRevenueByService']['estimated_revenue'])) {
                                        if($client[0]['currency'] == $revenueCurrency) {
                                                $estimatedRevenue = $client['ClientRevenueByService']['estimated_revenue'];
                                        } else {
                                                $dollarConvertRatio = array_search($client[0]['currency'], $currencies);
                                                if($revenueCurrency == "USD") {
                                                     $estimatedRevenue = ($client['ClientRevenueByService']['estimated_revenue'] * $dollarConvertRatio);
                                                } else {
                                                     $dollarEstRevenue = ($client['ClientRevenueByService']['estimated_revenue'] * $dollarConvertRatio);
                                                     $estimatedRevenue = ($dollarEstRevenue / $convertRatio);
                                                }
                                        }
                                }
                                if(is_numeric($client['ClientRevenueByService']['actual_revenue'])) {
                                        if($client[0]['currency'] == $revenueCurrency) {
                                                $actualRevenue = $client['ClientRevenueByService']['actual_revenue'];
                                        } else {
                                                $dollarConvertRatio = array_search($client[0]['currency'], $currencies);
                                                if($revenueCurrency == "USD") {
                                                     $actualRevenue = ($client['ClientRevenueByService']['actual_revenue'] * $dollarConvertRatio);
                                                } else {
                                                     $dollarEstRevenue = ($client['ClientRevenueByService']['actual_revenue'] * $dollarConvertRatio);
                                                     $actualRevenue = ($dollarEstRevenue / $convertRatio);
                                                }
                                        }
                                }
                                if(is_numeric($client['ClientRevenueByService']['fiscal_revenue'])) {
                                        if($client[0]['currency'] == $revenueCurrency) {
                                                $fiscalRevenue = $client['ClientRevenueByService']['fiscal_revenue'];
                                        } else {
                                                $dollarConvertRatio = array_search($client[0]['currency'], $currencies);
                                                if($revenueCurrency == "USD") {
                                                     $fiscalRevenue = ($client['ClientRevenueByService']['fiscal_revenue'] * $dollarConvertRatio);
                                                } else {
                                                     $dollarEstRevenue = ($client['ClientRevenueByService']['fiscal_revenue'] * $dollarConvertRatio);
                                                     $fiscalRevenue = ($dollarEstRevenue / $convertRatio);
                                                }
                                        }
                                }
                        }
                        if ($this->Auth->user('role') == 'Viewer') {
                                $clientData[$i]['EstimatedRevenue'] = '';
                                $clientData[$i]['ActualRevenue'] = '';
                                $clientData[$i]['FiscalRevenue'] = '';
                                $clientData[$i]['Currency'] = '';
                        } else {
                                if ($this->Auth->user('role') == 'Regional') {
                                        if (in_array($client['ClientRevenueByService']['region_id'], $arrRegions)) {
                                                $clientData[$i]['EstimatedRevenue'] = (($estimatedRevenue == 0) ? '' : $estimatedRevenue);
                                                $clientData[$i]['ActualRevenue'] = $actualRevenue;
                                                $clientData[$i]['FiscalRevenue'] = $fiscalRevenue;
                                                $clientData[$i]['Currency'] = $currency;
                                        } else {
                                                $clientData[$i]['EstimatedRevenue'] = '';
                                                $clientData[$i]['ActualRevenue'] = '';
                                                $clientData[$i]['FiscalRevenue'] = '';
                                                $clientData[$i]['Currency'] = '';
                                        }
                                } elseif ($this->Auth->user('role') == 'Country' || $this->Auth->user('role') == 'Country - Viewer') {
                                        if (in_array($client['ClientRevenueByService']['country_id'], $arrCountries)) {
                                                $clientData[$i]['EstimatedRevenue'] = (($estimatedRevenue == 0) ? '' : $estimatedRevenue);
                                                $clientData[$i]['ActualRevenue'] = $actualRevenue;
                                                $clientData[$i]['FiscalRevenue'] = $fiscalRevenue;
                                                $clientData[$i]['Currency'] = $currency;
                                        } else {
                                                $clientData[$i]['EstimatedRevenue'] = '';
                                                $clientData[$i]['ActualRevenue'] = '';
                                                $clientData[$i]['FiscalRevenue'] = '';
                                                $clientData[$i]['Currency'] = '';
                                        }
                                } else {
                                        $clientData[$i]['EstimatedRevenue'] = (($estimatedRevenue == 0) ? '' : $estimatedRevenue);
                                        $clientData[$i]['ActualRevenue'] = $actualRevenue;
                                        $clientData[$i]['FiscalRevenue'] = (($fiscalRevenue == 0) ? '' : $fiscalRevenue);
                                        $clientData[$i]['Currency'] = $currency;
                                }
                        }
                        $clientData[$i]['Comments'] = $client['ClientRevenueByService']['comments'];
                        $clientData[$i]['Year'] = $client['ClientRevenueByService']['year'];
                        $clientData[$i]['ParentId'] = $client['ClientRevenueByService']['parent_id'];
                        $clientData[$i]['Created'] = $client['ClientRevenueByService']['created'];
                        $clientData[$i]['Modified'] = $client['ClientRevenueByService']['modified'];

                        $i++;
                }
                echo json_encode($clientData);
        }

        public function get_currentclient_report_data(){            
            $this->autoRender=false;
                set_time_limit(0);
                ini_set('memory_limit', '-1');

                $clientData = array();
                $i = 0;
                $condition = 'ClientRevenueByService.pitch_stage = "Current client"';
                $revenueCurrency = isset($_GET['revenue_currency']) ? $_GET['revenue_currency'] : 'Actual currencies';
                $currencies = $this->Currency->find('list', array('fields' => array('Currency.convert_rate', 'Currency.currency'), 'order' => 'Currency.currency Asc'));
                $convertRatio = array_search($revenueCurrency, $currencies);
                if ($this->Auth->user('role') == 'Regional') {
                        $regions = $this->UserMarket->find('all', array('conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $arrRegions = array();
                        foreach ($regions as $region) {
                                $arrRegions[] = $region['UserMarket']['market_id'];
                        }
                        $condition = 'ClientRevenueByService.pitch_stage = "Current client"';
                }
                if ($this->Auth->user('role') == 'Country' || $this->Auth->user('role') == 'Country - Viewer') {
                        $countries = $this->UserMarket->find('all', array('conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $arrCountries = array();
                        foreach ($countries as $country) {
                                $arrCountries[] = $country['UserMarket']['market_id'];
                        }
                        $condition = 'ClientRevenueByService.pitch_stage = "Current client"';
                }
                $this->ClientRevenueByService->Behaviors->attach('Containable');
                $clients = $this->ClientRevenueByService->query("CALL allClientsWithFilter('{$condition}');");
                //print_r($clients);
                foreach ($clients as $client) {
                        $clientData[$i]['id'] = $client['ClientRevenueByService']['id'];
                        $clientData[$i]['RecordId'] = $client['ClientRevenueByService']['id'];
                        $clientData[$i]['Region'] = $client[0]['region'];
                        if ($client['ClientRevenueByService']['managing_entity'] == 'Global') {
                                $clientData[$i]['Country'] = 'Global';
                                $clientData[$i]['City'] = 'Global';
                        } elseif ($client['ClientRevenueByService']['managing_entity'] == 'Regional') {
                                $clientData[$i]['Country'] = 'Regional - ' . $client[0]['region'];
                                $clientData[$i]['City'] = 'Regional - ' . $client[0]['region'];
                        } else {
                                $clientData[$i]['Country'] = $client[0]['country'];
                                $clientData[$i]['City'] = $client[0]['city'];
                        }
                        $clientData[$i]['LeadAgency'] = $client[0]['agency'];
                        $clientData[$i]['ClientName'] = $client['ClientRevenueByService']['client_name'];
                        $clientData[$i]['SearchClientName'] = strtr( $client['ClientRevenueByService']['client_name'], $this->unwanted_array );
                        $clientData[$i]['ParentCompany'] = $client['ClientRevenueByService']['parent_company'];
                        $clientData[$i]['SearchParentCompany'] = strtr( $client['ClientRevenueByService']['parent_company'], $this->unwanted_array );
                        $clientData[$i]['ClientCategory'] = $client[0]['category'];
                        if ($client['ClientRevenueByService']['pitch_date'] != '0000-00-00') {
                                $pitchDate = explode('-', $client['ClientRevenueByService']['pitch_date']);
                                $clientData[$i]['PitchStart'] = $pitchDate[1] . '/' . $pitchDate[0];
                        } else {
                                $clientData[$i]['PitchStart'] = '';
                        }
                        $clientData[$i]['PitchStage'] = $client['ClientRevenueByService']['pitch_stage'];
                        if ($client['ClientRevenueByService']['lost_date'] != '0000-00-00') {
                                $lostDate = explode('-', $client['ClientRevenueByService']['lost_date']);
                                $clientData[$i]['Lost'] = $lostDate[1] . '/' . $lostDate[0];
                        } else {
                                $clientData[$i]['Lost'] = '';
                        }
                        $clientData[$i]['ClientMonth'] = ($client['ClientRevenueByService']['client_since_month'] != 0 && $client['ClientRevenueByService']['client_since_month'] != null) ? $this->months[$client['ClientRevenueByService']['client_since_month']] : '';
                        $clientData[$i]['ClientYear'] = $client['ClientRevenueByService']['client_since_year'];
                        if ($client['ClientRevenueByService']['client_since_month'] != 0 && $client['ClientRevenueByService']['client_since_year'] != 0) {
                                $clientData[$i]['ClientSince'] = $client['ClientRevenueByService']['client_since_month']. '/' .$client['ClientRevenueByService']['client_since_year'];
                        } elseif ($client['ClientRevenueByService']['client_since_month'] == 0 && $client['ClientRevenueByService']['client_since_year'] != 0) {
                                $clientData[$i]['ClientSince'] = '01/' .$client['ClientRevenueByService']['client_since_year'];
                        } else {
                                $clientData[$i]['ClientSince'] = '';
                        }
                        $clientData[$i]['Service'] = $client[0]['service_name'];
                        $clientData[$i]['MarketScope'] = $client['ClientRevenueByService']['market_scope'];
                        $clientData[$i]['ActiveMarkets'] = $client['ClientRevenueByService']['active_markets'];

                        $estimatedRevenue = 0;
                        $actualRevenue = 0;
                        $fiscalRevenue = 0;
                        $currency = '';
                        if($revenueCurrency == "Actual currencies") {
                                $estimatedRevenue = $client['ClientRevenueByService']['estimated_revenue'];
                                $actualRevenue = $client['ClientRevenueByService']['actual_revenue'];
                                $fiscalRevenue = $client['ClientRevenueByService']['fiscal_revenue'];
                                $currency = $client[0]['currency'];
                        } else {
                                $currency = $revenueCurrency;
                                if(is_numeric($client['ClientRevenueByService']['estimated_revenue'])) {
                                        if($client[0]['currency'] == $revenueCurrency) {
                                                $estimatedRevenue = $client['ClientRevenueByService']['estimated_revenue'];
                                        } else {
                                                $dollarConvertRatio = array_search($client[0]['currency'], $currencies);
                                                if($revenueCurrency == "USD") {
                                                     $estimatedRevenue = ($client['ClientRevenueByService']['estimated_revenue'] * $dollarConvertRatio);
                                                } else {
                                                     $dollarEstRevenue = ($client['ClientRevenueByService']['estimated_revenue'] * $dollarConvertRatio);
                                                     $estimatedRevenue = ($dollarEstRevenue / $convertRatio);
                                                }
                                        }
                                }
                                if(is_numeric($client['ClientRevenueByService']['actual_revenue'])) {
                                        if($client[0]['currency'] == $revenueCurrency) {
                                                $actualRevenue = $client['ClientRevenueByService']['actual_revenue'];
                                        } else {
                                                $dollarConvertRatio = array_search($client[0]['currency'], $currencies);
                                                if($revenueCurrency == "USD") {
                                                     $actualRevenue = ($client['ClientRevenueByService']['actual_revenue'] * $dollarConvertRatio);
                                                } else {
                                                     $dollarEstRevenue = ($client['ClientRevenueByService']['actual_revenue'] * $dollarConvertRatio);
                                                     $actualRevenue = ($dollarEstRevenue / $convertRatio);
                                                }
                                        }
                                }
                                if(is_numeric($client['ClientRevenueByService']['fiscal_revenue'])) {
                                        if($client[0]['currency'] == $revenueCurrency) {
                                                $fiscalRevenue = $client['ClientRevenueByService']['fiscal_revenue'];
                                        } else {
                                                $dollarConvertRatio = array_search($client[0]['currency'], $currencies);
                                                if($revenueCurrency == "USD") {
                                                     $fiscalRevenue = ($client['ClientRevenueByService']['fiscal_revenue'] * $dollarConvertRatio);
                                                } else {
                                                     $dollarEstRevenue = ($client['ClientRevenueByService']['fiscal_revenue'] * $dollarConvertRatio);
                                                     $fiscalRevenue = ($dollarEstRevenue / $convertRatio);
                        }
                                        }
                                }
                        }
                        if ($this->Auth->user('role') == 'Viewer') {
                                $clientData[$i]['EstimatedRevenue'] = '';
                                $clientData[$i]['ActualRevenue'] = '';
                                $clientData[$i]['FiscalRevenue'] = '';
                                $clientData[$i]['Currency'] = '';
                        } else {
                                if ($this->Auth->user('role') == 'Regional') {
                                        if (in_array($client['ClientRevenueByService']['region_id'], $arrRegions)) {
                                                $clientData[$i]['EstimatedRevenue'] = (($estimatedRevenue == 0) ? '' : $estimatedRevenue);
                                                $clientData[$i]['ActualRevenue'] = $actualRevenue;
                                                $clientData[$i]['FiscalRevenue'] = $fiscalRevenue;
                                                $clientData[$i]['Currency'] = $currency;
                                        } else {
                                                $clientData[$i]['EstimatedRevenue'] = '';
                                                $clientData[$i]['ActualRevenue'] = '';
                                                $clientData[$i]['FiscalRevenue'] = '';
                                                $clientData[$i]['Currency'] = '';
                                        }
                                } elseif ($this->Auth->user('role') == 'Country' || $this->Auth->user('role') == 'Country - Viewer') {
                                        if (in_array($client['ClientRevenueByService']['country_id'], $arrCountries)) {
                                                $clientData[$i]['EstimatedRevenue'] = (($estimatedRevenue == 0) ? '' : $estimatedRevenue);
                                                $clientData[$i]['ActualRevenue'] = $actualRevenue;
                                                $clientData[$i]['FiscalRevenue'] = $fiscalRevenue;
                                                $clientData[$i]['Currency'] = $currency;
                                        } else {
                                                $clientData[$i]['EstimatedRevenue'] = '';
                                                $clientData[$i]['ActualRevenue'] = '';
                                                $clientData[$i]['FiscalRevenue'] = '';
                                                $clientData[$i]['Currency'] = '';
                                        }
                                } else {
                                        $clientData[$i]['EstimatedRevenue'] = (($estimatedRevenue == 0) ? '' : $estimatedRevenue);
                                        $clientData[$i]['ActualRevenue'] = $actualRevenue;
                                         $clientData[$i]['FiscalRevenue'] = $fiscalRevenue;
                                        $clientData[$i]['Currency'] = $currency;
                                }
                        }
                        $clientData[$i]['Comments'] = $client['ClientRevenueByService']['comments'];
                        $clientData[$i]['Year'] = $client['ClientRevenueByService']['year'];
                        $clientData[$i]['ParentId'] = $client['ClientRevenueByService']['parent_id'];
                        $clientData[$i]['Created'] = $client['ClientRevenueByService']['created'];
                        $clientData[$i]['Modified'] = $client['ClientRevenueByService']['modified'];

                        $i++;
                }
                echo json_encode($clientData);
        }

        public function update_client_record() {
                if ($this->request->isPost()) {
                        if($this->RequestHandler->isAjax()) {
                                $this->autoRender=false;
                        }

                        $arrData = $this->request->data;

                        $recordId = $arrData['RecordId'];

                        $existingStatus = $this->ClientRevenueByService->find('first', array('fields' => array('pitch_stage'), 'conditions' => array('ClientRevenueByService.id' => $recordId)));

                        $category = $this->ClientCategory->findByCategory(trim($arrData['ClientCategory']));
                        $region = $this->Region->findByRegion(trim($arrData['Region']));
                        if(trim($arrData['Country']) == 'Global') {
                                $managingEntity = 'Global';
                                $country = null;
                                $city = null;
                        } elseif(strpos(trim($arrData['Country']), 'Regional') !== false) {
                                $managingEntity = 'Regional';
                                $country = null;
                                $city = null;
                        } else {
                                $managingEntity = 'Country';
                                $country = $this->Market->findByMarket(trim($arrData['Country']));
                                $city = $this->City->findByCity(trim($arrData['City']));
                        }
                        $agency = $this->LeadAgency->findByAgency(trim($arrData['LeadAgency']));
                        $currency = $this->Currency->findByCurrency(trim($arrData['Currency']));
                        $service = $this->Service->findByServiceName(trim($arrData['Service']));

                        if(!empty($category)) {
                                $categoryId = $category['ClientCategory']['id'];
                        } else {
                                $categoryId = 0;
                        }
                        if(!empty($region)) {
                                $regionId = $region['Region']['id'];
                        } else {
                                $regionId = 0;
                        }
                        if(!empty($country)) {
                                $countryId = $country['Market']['country_id'];
                        } else {
                                $countryId = 0;
                        }
                        if(!empty($city)) {
                                $cityId = $city['City']['id'];
                        } else {
                                $cityId = 0;
                        }
                        if(!empty($agency) > 0) {
                                $agencyId = $agency['LeadAgency']['id'];
                        } else {
                                $agencyId = 0;
                        }
                        if(!empty($currency) > 0) {
                                $currencyId = $currency['Currency']['id'];
                        } else {
                                $currencyId = 0;
                        }
                        if(!empty($service) > 0) {
                                $serviceId = $service['Service']['id'];
                        } else {
                                $serviceId = 0;
                        }
                        $pitchStage = trim($arrData['PitchStage']);
                        $pitchStart = explode('/', trim($arrData['PitchStart']));
                        $pitchDate = $pitchStart[1] . '-' . $pitchStart[0] . '-01';
                        $clientMonth = null;
                        $clientYear = null;
                        if(!preg_match('/Live/', $pitchStage) && $pitchStage != 'Cancelled' && $pitchStage != 'Declined') {
                                if (preg_match('/Lost - new/', $pitchStage)) {
                                        $clientMonth = null;
                                        $clientYear = null;
                                } else if($arrData['ClientSince'] != null) {
                                        $clientSince = explode('/', $arrData['ClientSince']);
                                        $clientMonth = $clientSince[0];
                                        $clientYear = $clientSince[1];
                                }
                        }
                        if(preg_match('/Lost/', $pitchStage) || $pitchStage == 'Cancelled' || $pitchStage == 'Declined') {
                                $lost = explode('/', trim($arrData['LostDate']));
                                $lostDate = $lost[1] . '-' . $lost[0] . '-01';
                        } else {
                                $lostDate = '';
                        }
                        $marketScope = trim($arrData['MarketScope']);
                        $activeMarkets = trim($arrData['ActiveMarkets']);
                        $companyName = trim($arrData['ParentCompany']);
                        $clientName = trim($arrData['ClientName']);
                        $estimatedRevenue = $arrData['EstimatedRevenue'];
                        $fiscalRevenue = $arrData['FiscalRevenue'];
                        $actualRevenue = $arrData['ActualRevenue'];
                        $comments = trim($arrData['Comments']);
                        $parentId = $arrData['ParentId'];

                        $this->ClientRevenueByService->id = $recordId;
                        $this->ClientRevenueByService->save(
                                array(
                                        'ClientRevenueByService' => array(
                                                'pitch_date' => $pitchDate,
                                                'pitch_stage' => $pitchStage,
                                                'client_name' => $clientName,
                                                'parent_company' => $companyName,
                                                'comments' => $comments,
                                                'category_id' => $categoryId,
                                                'agency_id' => $agencyId,
                                                'region_id' => $regionId,
                                                'managing_entity' => $managingEntity,
                                                'country_id' => $countryId,
                                                'city_id' => $cityId,
                                                'client_since_month' => $clientMonth,
                                                'client_since_year' => $clientYear,
                                                'lost_date' => $lostDate,
                                                'market_scope' => $marketScope,
                                                'active_markets' => $activeMarkets,
                                                'service_id' => $serviceId,
                                                'currency_id' => $currencyId,
                                                'estimated_revenue' => $estimatedRevenue,
                                                'fiscal_revenue' => $fiscalRevenue,
                                                'actual_revenue' => $actualRevenue,
                                                'year' => date('Y'),
                                                'modified' => date('Y-m-d H:i:s')
                                        )
                                )
                        );

                        if($parentId == 0 || $parentId == null || $parentId == '') {
                                $assocRecords = $this->ClientRevenueByService->find('all', array('fields' => array('ClientRevenueByService.id'), 'conditions' => array('ClientRevenueByService.parent_id' => $recordId)));
                                foreach($assocRecords as $assocRecord) {
                                        $this->ClientRevenueByService->id = $assocRecord['ClientRevenueByService']['id'];
                                        $this->ClientRevenueByService->save(
                                                array(
                                                        'ClientRevenueByService' => array(
                                                                'agency_id' => $agencyId,
                                                                'region_id' => $regionId,
                                                                'managing_entity' => $managingEntity,
                                                                'country_id' => $countryId,
                                                                'city_id' => $cityId,
                                                                'year' => date('Y'),
                                                                'modified' => date('Y-m-d H:i:s')
                                                        )
                                                )
                                        );
                                }
                        } else {
                                $assocRecords = $this->ClientRevenueByService->find('all', array('fields' => array('ClientRevenueByService.id'), 'conditions' => array('ClientRevenueByService.parent_id' => $parentId)));
                                foreach($assocRecords as $assocRecord) {
                                        $this->ClientRevenueByService->id = $assocRecord['ClientRevenueByService']['id'];
                                        $this->ClientRevenueByService->save(
                                                array(
                                                        'ClientRevenueByService' => array(
                                                                'agency_id' => $agencyId,
                                                                'region_id' => $regionId,
                                                                'managing_entity' => $managingEntity,
                                                                'country_id' => $countryId,
                                                                'city_id' => $cityId,
                                                                'year' => date('Y'),
                                                                'modified' => date('Y-m-d H:i:s')
                                                        )
                                                )
                                        );
                                }

                                $this->ClientRevenueByService->id = $parentId;
                                $this->ClientRevenueByService->save(
                                        array(
                                                'ClientRevenueByService' => array(
                                                        'agency_id' => $agencyId,
                                                        'region_id' => $regionId,
                                                        'managing_entity' => $managingEntity,
                                                        'country_id' => $countryId,
                                                        'city_id' => $cityId,
                                                        'year' => date('Y'),
                                                        'modified' => date('Y-m-d H:i:s')
                                                )
                                        )
                                );
                        }
                }
                $result = array();
                if ($arrData) {
                        if(preg_match('/Live/', $existingStatus['ClientRevenueByService']['pitch_stage']) && !preg_match('/Live/', $pitchStage)
                                && $existingStatus['ClientRevenueByService']['pitch_stage'] != $pitchStage) {
                                // add to update pitch notification log
                                $this->UpdatePitchNotification->create();
                                $this->UpdatePitchNotification->save(
                                        array(
                                            'UpdatePitchNotification' => array(
                                                'pitch_id' => $recordId,
                                                'pitch_date' => $pitchDate,
                                                'pitch_status' => $pitchStage,
                                                'client_name' => $clientName,
                                                'parent_company' => $companyName,
                                                'client_category' => trim($arrData['ClientCategory']),
                                                'city' => trim($arrData['City']),
                                                'country' => trim($arrData['Country']),
                                                'service' => trim($arrData['Service']),
                                                'active_markets' => $activeMarkets,
                                                'updated_by' => $this->Auth->user('id'),
                                                'updated_date' => date('Y-m-d H:i:s')
                                            )
                                        )
                                );

                                // script to send update pitch notification to users opted for notifications for specific client
                                if(preg_match('/Lost/', $pitchStage) || $pitchStage == 'Cancelled' || $pitchStage == 'Declined') {
                                        $subject = 'Pitch is lost for ' . $arrData['ClientName'];
                                        $template = 'lost_pitch';
                                } else {
                                        $subject = 'Pitch is won for ' . $arrData['ClientName'];
                                        $template = 'won_pitch';
                                }
                                $this->UserLoginRole->Behaviors->attach('Containable');
                                $globalUsers = $this->UserLoginRole->find('all', array('fields' => array('User.display_name', 'User.email_id'), 'contain' => array('User', 'LoginRole'), 'conditions' => array('LoginRole.name' => 'Global', 'User.client_specific_mail' => 1), 'order' => 'User.display_name'));

                                $emailTo = array();
                                foreach($globalUsers as $globalUser) {
                                        $isSpecificClientAlert = $this->UserMailNotificationClient->find('count', array('conditions' => array('user_id' => $globalUser['User']['id'])));
                                        if($isSpecificClientAlert > 0) {
                                                $isClientAlert = $this->UserMailNotificationClient->find('count', array('conditions' => array('user_id' => $globalUser['User']['id'], 'client_name' => $arrData['ClientName'])));
                                                if($isClientAlert > 0) {
                                                        $emailTo[] = $globalUser['User']['email_id'];
                                                }
                                        }
                                }

                                if(!empty($emailTo)) {
                                        try {
                                                $email = new CakeEmail('gmail');
                                                $email->viewVars(array('title_for_layout' => 'Client & New Business data', 'type' => 'Pitch updated', 'data' => $arrData));
                                                $email->template($template, 'default')
                                                    ->emailFormat('html')
                                                    ->to($emailTo)
                                                    ->from(array('connectiprospect@gmail.com' => 'iProspect Connect'))
                                                    ->subject('iProspect Connect: ' . $subject)
                                                    ->send();
                                        } catch (Exception $e) {
                                                $result['mailError'] = $e->getMessage();
                                        }
                                }
                        }
                }
                $result['success'] = true;
                return json_encode($result);
        }

        public function client_report() {

                $this->set('currencies', json_encode($this->Currency->find('list', array('fields' => array('Currency.convert_rate', 'Currency.currency'), 'order' => 'Currency.currency Asc'))));
                $arrClientSinceYear = array();
                $clientsinceyears = $this->ClientRevenueByService->find('all',array('fields' => array('ClientRevenueByService.client_since_year'), 'conditions' => array("client_since_year != '0000-00-00'"),'order' => 'ClientRevenueByService.client_since_year Asc', 'group' => 'client_since_year'));
                foreach($clientsinceyears as $clientsinceyear) {
                    $arrClientSinceYear[] = $clientsinceyear['ClientRevenueByService']['client_since_year'];
                }
                $this->set('clientSinceYear',json_encode($arrClientSinceYear));
                $arrLostYear = array();
                $lostsinceyears = $this->ClientRevenueByService->find('all',array('fields' => array('YEAR(ClientRevenueByService.lost_date) as lost_year'), 'conditions' => array("lost_date != '0000-00-00'"), 'order' => 'ClientRevenueByService.lost_date Asc', 'group' => 'lost_year'));
                foreach($lostsinceyears as $lostsinceyear) {
                    $arrLostYear[] = $lostsinceyear[0]['lost_year'];
                }
                $this->set('lostsinceyear',json_encode($arrLostYear));
                $arrPitchedYear = array();
                $pitchedyears = $this->ClientRevenueByService->find('all',array('fields' => array('YEAR(ClientRevenueByService.pitch_date) as pitch_year'), 'conditions' => array("pitch_date != '0000-00-00'"), 'order' => 'ClientRevenueByService.pitch_date Asc', 'group' => 'pitch_year'));
                foreach($pitchedyears as $pitchedyears) {
                    $arrPitchedYear[] = $pitchedyears[0]['pitch_year'];
                }
                $this->set('pitchyear',json_encode($arrPitchedYear));
                $this->set('current_year', date('Y'));
                $arrMarkets = array();
                $arrRegions = array();
                $arrCities = array();
                $regions = $this->Region->find('all', array('order' => 'Region.region Asc'));
                foreach ($regions as $region) {
                        $arrRegions[$region['Region']['region']] = $region['Region']['region'];
                        $markets = $this->Market->find('list', array('fields' => array('Market.country_id', 'Market.market'), 'conditions' => array('Market.region_id' => $region['Region']['id']), 'order' => 'Market.market Asc'));
                        if(!empty($markets)) {
                                foreach ($markets as $countryId => $market)
                                {
                                        $arrMarkets[$region['Region']['region']][$market] = $market;
                                        $cities = $this->City->find('list', array('fields' => array('City.city', 'City.city'), 'conditions' => array('City.country_id' => $countryId), 'order' => 'City.city Asc'));
                                        if(!empty($cities)) {
                                                $arrCities[$market] = $cities;
                                        }
                                }
                        }
                }
                $arrPreference = $this->UserGridPreference->find('first', array('fields' =>array('UserGridPreference.preference'),'conditions' => array('UserGridPreference.user_id' => $this->Auth->user('id'),'UserGridPreference.formname' =>'client_report')));
                if(!empty($arrPreference)) {
                        $this->set('widthPreferences', $arrPreference['UserGridPreference']['preference']);
                } else {
                        $this->set('widthPreferences', '{}');
                }
                $this->set('regions', json_encode($arrRegions));
                $this->set('markets', json_encode($arrMarkets));
                $this->set('cities', json_encode($arrCities));
                $this->set('loggedUser', $this->Auth->user());
                $this->set('userAcl', $this->Acl);
                $this->set('userRole', $this->Auth->user('role'));
        }

        public function current_client_report() {
            
            $this->set('currencies', json_encode($this->Currency->find('list', array('fields' => array('Currency.convert_rate', 'Currency.currency'), 'order' => 'Currency.currency Asc'))));
                $this->set('current_year', date('Y'));
                $arrMarkets = array();
                $arrRegions = array();
                $arrCities = array();
                $regions = $this->Region->find('all', array('order' => 'Region.region Asc'));
                foreach ($regions as $region) {
                        $arrRegions[$region['Region']['region']] = $region['Region']['region'];
                        $markets = $this->Market->find('list', array('fields' => array('Market.country_id', 'Market.market'), 'conditions' => array('Market.region_id' => $region['Region']['id']), 'order' => 'Market.market Asc'));
                        if(!empty($markets)) {
                                foreach ($markets as $countryId => $market)
                                {
                                        $arrMarkets[$region['Region']['region']][$market] = $market;
                                        $cities = $this->City->find('list', array('fields' => array('City.city', 'City.city'), 'conditions' => array('City.country_id' => $countryId), 'order' => 'City.city Asc'));
                                        if(!empty($cities)) {
                                                $arrCities[$market] = $cities;
                                        }
                                }
                        }
                }
                $arrPreference = $this->UserGridPreference->find('first', array('fields' =>array('UserGridPreference.preference'),'conditions' => array('UserGridPreference.user_id' => $this->Auth->user('id'),'UserGridPreference.formname' =>'current_client_report')));
                if(!empty($arrPreference)) {
                        $this->set('widthPreferences', $arrPreference['UserGridPreference']['preference']);
                } else {
                        $this->set('widthPreferences', '{}');
                }
                $this->set('regions', json_encode($arrRegions));
                $this->set('markets', json_encode($arrMarkets));
                $this->set('cities', json_encode($arrCities));
                $this->set('loggedUser', $this->Auth->user());
                $this->set('userAcl', $this->Acl);
                $this->set('userRole', $this->Auth->user('role'));
        }

        public function export_client_data() {
                set_time_limit(0);
                ini_set('memory_limit', '-1');

                if ($this->request->isPost()) {
                        if($this->RequestHandler->isAjax()){
                                $this->autoRender=false;
                        }
                        date_default_timezone_set($this->request->data['timezone']);

                        $arrData = $this->request->data['datarows'];
                        $exportCurrency = $this->request->data['currency'];
                        $exportFormat = $this->request->data['format'];
                        $exportRevenue = isset($this->request->data['revenue']) ? $this->request->data['revenue'] : 'NO';
                        $exportOption = isset($this->request->data['exportOpt']) ? $this->request->data['exportOpt'] : 'export_download';
                        $currencies = $this->Currency->find('list', array('fields' => array('Currency.convert_rate', 'Currency.currency'), 'order' => 'Currency.currency Asc'));
                        $convertRatio = array_search($exportCurrency, $currencies);

                        App::import('Vendor', 'PHPExcel', array('file' => 'PhpExcel/PHPExcel.php'));
                        if (!class_exists('PHPExcel')) {
                                throw new CakeException('Vendor class PHPExcel not found!');
                        }
                        if($exportFormat == 'csv') {
                                App::import('Vendor', 'PHPExcel_Writer_CSV', array('file' => 'PhpExcel/PHPExcel/Writer/CSV.php'));
                                if (!class_exists('PHPExcel_Writer_CSV')) {
                                        throw new CakeException('Vendor class PHPExcel not found!');
                                }
                        } else {
                                App::import('Vendor', 'PHPExcel_Writer_Excel2007', array('file' => 'PhpExcel/PHPExcel/Writer/Excel2007.php'));
                                if (!class_exists('PHPExcel_Writer_Excel2007')) {
                                        throw new CakeException('Vendor class PHPExcel not found!');
                                }
                        }
                        $objPHPExcel = new PHPExcel();
                        // Set properties
                        $objPHPExcel->getProperties()->setCreator("Siddharth Kulkarni");
                        $objPHPExcel->getProperties()->setLastModifiedBy("Siddharth Kulkarni");
                        $objPHPExcel->getProperties()->setTitle("Client Data by date " . date('m/d/Y'));
                        $objPHPExcel->getProperties()->setSubject("Client Data by date " . date('m/d/Y'));
                        $noYears= $this->ClientActualRevenueByYear->find('list', array('fields' => array('id', 'ClientActualRevenueByYear.fin_year'),'order' => 'ClientActualRevenueByYear.fin_year desc', 'group' => 'ClientActualRevenueByYear.fin_year'));

                        // Add some data
                        $objPHPExcel->setActiveSheetIndex(0);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("A")->setWidth(15);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("B")->setWidth(20);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("C")->setWidth(20);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("D")->setWidth(40);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("E")->setWidth(40);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("F")->setWidth(35);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("G")->setWidth(12);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("H")->setWidth(20);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("I")->setWidth(30);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("J")->setWidth(10);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("K")->setWidth(10);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("L")->setWidth(10);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("M")->setWidth(15);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("N")->setWidth(35);
                        if ($this->Auth->user('role') != 'Viewer') {
                                $objPHPExcel->getActiveSheet()->getColumnDimension("O")->setWidth(20);
                                $objPHPExcel->getActiveSheet()->getColumnDimension("P")->setWidth(20);
                                $objPHPExcel->getActiveSheet()->getColumnDimension("Q")->setWidth(20);
                                $objPHPExcel->getActiveSheet()->getColumnDimension("R")->setWidth(20);
                                $col=18;
                                if($exportRevenue=="YES"){
                                        foreach($noYears as $year){
                                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                                $objPHPExcel->getActiveSheet()->getColumnDimension($colName)->setWidth(14);
                                                $col++;
                                        }
                                }
                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                $objPHPExcel->getActiveSheet()->getColumnDimension($colName)->setWidth(14);
                                $col++;
                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                $objPHPExcel->getActiveSheet()->getColumnDimension($colName)->setWidth(14);
                                $col++;
                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                $objPHPExcel->getActiveSheet()->getColumnDimension($colName)->setWidth(14);
                        } else {
                                $objPHPExcel->getActiveSheet()->getColumnDimension("O")->setWidth(40);
                        }
                        if ($this->Auth->user('role') != 'Viewer') {
                                if($exportFormat != 'csv') {
                                        $objPHPExcel->getActiveSheet()->getStyle("A1:".$colName.'1')->applyFromArray(array("font" => array( "bold" => true, 'size'  => 12, 'name'  => 'Calibri'), 'alignment' => array('horizontal' => PHPExcel_Style_Alignment::HORIZONTAL_CENTER_CONTINUOUS, 'wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                                }
                        } else {
                                $objPHPExcel->getActiveSheet()->getStyle("A1:O1")->applyFromArray(array("font" => array( "bold" => true, 'size'  => 12, 'name'  => 'Calibri'), 'alignment' => array('horizontal' => PHPExcel_Style_Alignment::HORIZONTAL_CENTER_CONTINUOUS, 'wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                        }
                        $objPHPExcel->getActiveSheet()->getStyle('A1:E1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('CCC0DA');
                        $objPHPExcel->getActiveSheet()->getStyle('F1:L1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('C5D9F1');
                        if ($this->Auth->user('role') != 'Viewer') {
                                if($exportFormat != 'csv') {
                                        $objPHPExcel->getActiveSheet()->getStyle('M1:'.$colName.'1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('FCD5B4');
                                }
                        } else {
                                $objPHPExcel->getActiveSheet()->getStyle('M1:O1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('FCD5B4');
                        }
                        $objPHPExcel->getActiveSheet()->SetCellValue('A1', 'Region');
                        $objPHPExcel->getActiveSheet()->SetCellValue('B1', 'Country');
                        $objPHPExcel->getActiveSheet()->SetCellValue('C1', 'City');
                        $objPHPExcel->getActiveSheet()->SetCellValue('D1', 'Client');
                        $objPHPExcel->getActiveSheet()->SetCellValue('E1', 'Parent Company');
                        $objPHPExcel->getActiveSheet()->SetCellValue('F1', 'Client Category');
                        $objPHPExcel->getActiveSheet()->SetCellValue('G1', 'Lead Agency');
                        $objPHPExcel->getActiveSheet()->SetCellValue('H1', 'Status');
                        $objPHPExcel->getActiveSheet()->SetCellValue('I1', 'Service');
                        $objPHPExcel->getActiveSheet()->SetCellValue('J1', 'Client Since (M-Y)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('K1', 'Lost Since(M-Y)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('L1', 'Pitched (M-Y)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('M1', 'Scope');
                        $objPHPExcel->getActiveSheet()->SetCellValue('N1', 'Active Markets');
                        if ($this->Auth->user('role') == 'Viewer') {
                                $objPHPExcel->getActiveSheet()->SetCellValue('O1', 'Comments');
                        } else {
                                $objPHPExcel->getActiveSheet()->SetCellValue('O1', 'Currency');
                                $objPHPExcel->getActiveSheet()->SetCellValue('P1', 'iP '.date('Y').' Estimated Revenue');
                                $objPHPExcel->getActiveSheet()->SetCellValue('Q1', 'Fiscal Yr. ' .date('Y').' Revenue');
                                $objPHPExcel->getActiveSheet()->SetCellValue('R1', 'iP '.(date('Y')-1).' Actual Revenue');
                                $col = 18;
                                if($exportRevenue == "YES") {
                                        foreach($noYears as $year)
                                        {
                                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                                $objPHPExcel->getActiveSheet()->SetCellValue($colName.'1', 'iP'.$year.' Actual Revenue');
                                                $col++;
                                        }
                                }
                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                $objPHPExcel->getActiveSheet()->SetCellValue($colName.'1', 'Comments');
                                $col++;
                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                $objPHPExcel->getActiveSheet()->SetCellValue($colName.'1', 'Created on');
                                $col++;
                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                $objPHPExcel->getActiveSheet()->SetCellValue($colName.'1', 'Last modified on');
                        }
                        if($exportRevenue == "YES") {
                                $prevRevenue = $this->ClientActualRevenueByYear->find('list', array('fields' => array('ClientActualRevenueByYear.fin_year', 'ClientActualRevenueByYear.actual_revenue','ClientActualRevenueByYear.client_service_id'), 'order' => 'ClientActualRevenueByYear.fin_year desc'));
                        }
                        $i = 1;
                        $arrDataExcel = array();
                        foreach($arrData as $data) {
                                if($data['ClientSince'] != '') {
                                        $clientSince = date('m/Y', strtotime($data['ClientSince']));
                                } else {
                                        $clientSince = '';
                                }
                                if($data['Lost'] != '') {
                                        $lostDate = date('m/Y', strtotime($data['Lost']));
                                } else {
                                        $lostDate = '';
                                }
                                if($data['PitchStart'] != '') {
                                        $pitchDate = date('m/Y', strtotime($data['PitchStart']));
                                } else {
                                        $pitchDate = '';
                                }
                                if($exportCurrency == "Actual currencies") {
                                        $currency = $data['Currency'];
                                } else {
                                        $currency = $exportCurrency;
                                }
                                if($data['Created'] != '') {
                                        $createdDate = date('m/d/Y', strtotime($data['Created']));
                                } else {
                                        $createdDate = '01/01/2015';
                                }
                                if($data['Modified'] != '') {
                                        $modifiedDate = date('m/d/Y', strtotime($data['Modified']));
                                } else {
                                        $modifiedDate = '';
                                }
                                $estimatedRevenue = 0;
                                $actualRevenue = 0;
                                $fiscalRevenue = 0;
                                if ($this->Auth->user('role') != 'Viewer') {
                                        if($exportCurrency == "Actual currencies") {
                                                $estimatedRevenue = $data['EstimatedRevenue'];
                                                $actualRevenue = $data['ActualRevenue'];
                                                $fiscalRevenue = $data['FiscalRevenue'];
                                        } else {
                                                if(is_numeric($data['EstimatedRevenue'])) {
                                                        if($data['Currency'] == $exportCurrency) {
                                                                $estimatedRevenue = $data['EstimatedRevenue'];
                                                        } else {
                                                                $dollarConvertRatio = array_search($data['Currency'], $currencies);
                                                                if($exportCurrency == "USD") {
                                                                     $estimatedRevenue = ($data['EstimatedRevenue'] * $dollarConvertRatio);
                                                                } else {
                                                                     $dollarEstRevenue = ($data['EstimatedRevenue'] * $dollarConvertRatio);
                                                                     $estimatedRevenue = ($dollarEstRevenue / $convertRatio);
                                                                }
                                                        }
                                                }
                                                if(is_numeric($data['ActualRevenue'])) {
                                                        if($data['Currency'] == $exportCurrency) {
                                                                $actualRevenue = $data['ActualRevenue'];
                                                        } else {
                                                                $dollarConvertRatio = array_search($data['Currency'], $currencies);
                                                                if($exportCurrency == "USD") {
                                                                     $actualRevenue = ($data['ActualRevenue'] * $dollarConvertRatio);
                                                                } else {
                                                                     $dollarEstRevenue = ($data['ActualRevenue'] * $dollarConvertRatio);
                                                                     $actualRevenue = ($dollarEstRevenue / $convertRatio);
                                                                }
                                                        }
                                                }
                                                if(is_numeric($data['FiscalRevenue'])) {
                                                        if($data['Currency'] == $exportCurrency) {
                                                                $actualRevenue = $data['FiscalRevenue'];
                                                        } else {
                                                                $dollarConvertRatio = array_search($data['Currency'], $currencies);
                                                                if($exportCurrency == "USD") {
                                                                     $actualRevenue = ($data['FiscalRevenue'] * $dollarConvertRatio);
                                                                } else {
                                                                     $dollarEstRevenue = ($data['FiscalRevenue'] * $dollarConvertRatio);
                                                                     $actualRevenue = ($dollarEstRevenue / $convertRatio);
                                                                }
                                                        }
                                                }
                                        }

                                        $row = array($data['Region'], $data['Country'], $data['City'],
                                            $data['ClientName'], $data['ParentCompany'], $data['ClientCategory'], $data['LeadAgency'],
                                            $data['PitchStage'], $data['Service'],$clientSince, $lostDate, $pitchDate, $data['MarketScope'],
                                            html_entity_decode($data['ActiveMarkets']), $currency, (($estimatedRevenue == 0) ? '' : $estimatedRevenue), (($fiscalRevenue == 0) ? '' : $fiscalRevenue),(($actualRevenue == 0) ? '' : $actualRevenue));

                                        if($exportRevenue == "YES") {
                                                $recordId = $data['RecordId'];
                                                if(isset($prevRevenue[$recordId])){
                                                        $prevRevenueByYear = $prevRevenue[$recordId];
                                                        foreach($noYears as $year)
                                                        {
                                                                if(isset($prevRevenueByYear[$year])) {
                                                                        $row[] = $prevRevenueByYear[$year];
                                                                } else {
                                                                        $row[] = '';
                                                                }
                                                        }
                                                } else {
                                                        foreach($noYears as $year)
                                                        {
                                                                $row[] = '';
                                                        }
                                                }
                                        }
                                        $row[] = ($data['Comments'] == null) ? '' : $data['Comments'];
                                        $row[] = $createdDate;
                                        $row[] = $modifiedDate;
                                        $arrDataExcel[] = $row;
                                } else {
                                        $arrDataExcel[] = array($data['Region'], $data['Country'], $data['City'],
                                            $data['ClientName'], $data['ParentCompany'], $data['ClientCategory'], $data['LeadAgency'],
                                            $data['PitchStage'], $data['Service'], $clientSince, $lostDate, $pitchDate,
                                            $data['MarketScope'], html_entity_decode($data['ActiveMarkets']), $data['Comments']);
                                }
                                $i++;
                        }
                        if(!empty($arrDataExcel)) {
                                if ($this->Auth->user('role') != 'Viewer') {
                                        $objPHPExcel->getActiveSheet()->getStyle('A2:'.$colName.$i)->applyFromArray(array('font' => array('size'  => 11, 'name'  => 'Calibri'), 'alignment' => array('wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                                        $objPHPExcel->getActiveSheet()->getStyle('P2:P'.$i)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_NUMBER_00);
                                        $objPHPExcel->getActiveSheet()->getStyle('Q2:Q'.$i)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_NUMBER_00);
                                        $objPHPExcel->getActiveSheet()->getStyle('R2:R'.$i)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_NUMBER_00);
                                        $objPHPExcel->getActiveSheet()->fromArray($arrDataExcel, null, 'A2');
                                        $objPHPExcel->getActiveSheet()->setAutoFilter('A1:'.$colName.$i);
                                } else {
                                        if($exportFormat != 'csv') {
                                                $objPHPExcel->getActiveSheet()->getStyle('A2:O'.$i)->applyFromArray(array('font' => array('size'  => 11, 'name'  => 'Calibri'), 'alignment' => array('wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                                        }
                                        $objPHPExcel->getActiveSheet()->fromArray($arrDataExcel, null, 'A2');
                                        if($exportFormat != 'csv') {
                                                $objPHPExcel->getActiveSheet()->setAutoFilter('A1:O'.$i);
                                        }
                                }
                        }

                        // Rename sheet
                        $objPHPExcel->getActiveSheet()->setTitle('Client List');
                        // Save Excel 2007/CSV file
                        if($exportFormat == 'csv') {
                                $fileName = 'Client_Data_' . date('m-d-Y') . '.csv';
                                $objWriter = new PHPExcel_Writer_CSV($objPHPExcel);
                        } else {
                                $fileName = 'Client_Data_' . date('m-d-Y') . '.xlsx';
                                $objWriter = new PHPExcel_Writer_Excel2007($objPHPExcel);
                        }
                        $objWriter->save('files/' . $fileName);
                        if($exportOption=="export_download"){
                                $result = array('filename' => $fileName);
                                $result['success'] = true;
                        }else{
                                $user=array();
                                $user = $this->User->find('first', array('fields' => array('User.email_id'), 'conditions' => array('User.id' => $this->Auth->user('id'))));
                                $email=new CakeEmail('gmail');
                                $email->viewVars(array('title_for_layout' => 'Client data export'));
                                $email->template('clientdata_export', 'default')
                                   ->emailFormat('html')
                                   ->attachments('files/'.$fileName)
                                   ->to(array($user['User']['email_id']))
                                   ->from(array('connectiprospect@gmail.com' => 'Connect iProspect'))
                                   ->subject('Client data export');
                                if($email->send()){
                                        $success="Email has been sent successfully on " . $user['User']['email_id'];
                                        $result = array('message' => $success);
                                        $result['success'] = true;
                                } else{
                                        $error="Unable to send email to " . $user['User']['email_id'] . ". Please try later.";
                                        $result = array('message' => $error);
                                        $result['success'] = false;
                               }
                        }
                        return json_encode($result);
                }
        }
        
        public function export_currentclient_data() {
                set_time_limit(0);
                ini_set('memory_limit', '-1');
                if ($this->request->isPost()) {
                        if($this->RequestHandler->isAjax()){
                                $this->autoRender=false;
                        }
                        date_default_timezone_set($this->request->data['timezone']);
                        $arrData = $this->request->data['datarows'];
                        $exportCurrency = $this->request->data['currency'];
                        $exportFormat = $this->request->data['format'];
                        $exportRevenue = isset($this->request->data['revenue']) ? $this->request->data['revenue'] : 'NO';
                        $exportOption = isset($this->request->data['exportOpt']) ? $this->request->data['exportOpt'] : 'export_download';
                        $currencies = $this->Currency->find('list', array('fields' => array('Currency.convert_rate', 'Currency.currency'), 'order' => 'Currency.currency Asc'));
                        $convertRatio = array_search($exportCurrency, $currencies);
                        App::import('Vendor', 'PHPExcel', array('file' => 'PhpExcel/PHPExcel.php'));
                        if (!class_exists('PHPExcel')) {
                                throw new CakeException('Vendor class PHPExcel not found!');
                        }
                        if($exportFormat == 'csv') {
                                App::import('Vendor', 'PHPExcel_Writer_CSV', array('file' => 'PhpExcel/PHPExcel/Writer/CSV.php'));
                                if (!class_exists('PHPExcel_Writer_CSV')) {
                                        throw new CakeException('Vendor class PHPExcel not found!');
                                }
                        } else {
                                App::import('Vendor', 'PHPExcel_Writer_Excel2007', array('file' => 'PhpExcel/PHPExcel/Writer/Excel2007.php'));
                                if (!class_exists('PHPExcel_Writer_Excel2007')) {
                                        throw new CakeException('Vendor class PHPExcel not found!');
                                }
                        }
                        $objPHPExcel = new PHPExcel();
                        // Set properties
                        $objPHPExcel->getProperties()->setCreator("Siddharth Kulkarni");
                        $objPHPExcel->getProperties()->setLastModifiedBy("Siddharth Kulkarni");
                        $objPHPExcel->getProperties()->setTitle("Client Data by date " . date('m/d/Y'));
                        $objPHPExcel->getProperties()->setSubject("Client Data by date " . date('m/d/Y'));
                        $noYears= $this->ClientActualRevenueByYear->find('list', array('fields' => array('id', 'ClientActualRevenueByYear.fin_year'),'order' => 'ClientActualRevenueByYear.fin_year desc', 'group' => 'ClientActualRevenueByYear.fin_year'));
                        // Add some data
                        $objPHPExcel->setActiveSheetIndex(0);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("A")->setWidth(15);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("B")->setWidth(20);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("C")->setWidth(20);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("D")->setWidth(40);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("E")->setWidth(40);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("F")->setWidth(35);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("G")->setWidth(12);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("H")->setWidth(20);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("I")->setWidth(30);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("J")->setWidth(10);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("K")->setWidth(10);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("L")->setWidth(10);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("M")->setWidth(15);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("N")->setWidth(35);
                        if ($this->Auth->user('role') != 'Viewer') {
                                $objPHPExcel->getActiveSheet()->getColumnDimension("O")->setWidth(20);
                                $objPHPExcel->getActiveSheet()->getColumnDimension("P")->setWidth(20);
                                $objPHPExcel->getActiveSheet()->getColumnDimension("Q")->setWidth(20);
                                $objPHPExcel->getActiveSheet()->getColumnDimension("R")->setWidth(20);
                                $col=18;
                                if($exportRevenue=="YES"){
                                        foreach($noYears as $year){
                                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                                $objPHPExcel->getActiveSheet()->getColumnDimension($colName)->setWidth(14);
                                                $col++;
                                        }
                                }
                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                $objPHPExcel->getActiveSheet()->getColumnDimension($colName)->setWidth(14);
                                $col++;
                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                $objPHPExcel->getActiveSheet()->getColumnDimension($colName)->setWidth(14);
                                $col++;
                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                $objPHPExcel->getActiveSheet()->getColumnDimension($colName)->setWidth(14);
                        } else {
                                $objPHPExcel->getActiveSheet()->getColumnDimension("O")->setWidth(40);
                        }
                        if ($this->Auth->user('role') != 'Viewer') {
                                if($exportFormat != 'csv') {
                                        $objPHPExcel->getActiveSheet()->getStyle("A1:".$colName.'1')->applyFromArray(array("font" => array( "bold" => true, 'size'  => 12, 'name'  => 'Calibri'), 'alignment' => array('horizontal' => PHPExcel_Style_Alignment::HORIZONTAL_CENTER_CONTINUOUS, 'wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                                }
                        } else {
                                $objPHPExcel->getActiveSheet()->getStyle("A1:O1")->applyFromArray(array("font" => array( "bold" => true, 'size'  => 12, 'name'  => 'Calibri'), 'alignment' => array('horizontal' => PHPExcel_Style_Alignment::HORIZONTAL_CENTER_CONTINUOUS, 'wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                        }
                        $objPHPExcel->getActiveSheet()->getStyle('A1:E1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('CCC0DA');
                        $objPHPExcel->getActiveSheet()->getStyle('F1:L1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('C5D9F1');
                        if ($this->Auth->user('role') != 'Viewer') {
                                if($exportFormat != 'csv') {
                                        $objPHPExcel->getActiveSheet()->getStyle('M1:'.$colName.'1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('FCD5B4');
                                }
                        } else {
                                $objPHPExcel->getActiveSheet()->getStyle('M1:O1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('FCD5B4');
                        }
                        $objPHPExcel->getActiveSheet()->SetCellValue('A1', 'Region');
                        $objPHPExcel->getActiveSheet()->SetCellValue('B1', 'Country');
                        $objPHPExcel->getActiveSheet()->SetCellValue('C1', 'City');
                        $objPHPExcel->getActiveSheet()->SetCellValue('D1', 'Client');
                        $objPHPExcel->getActiveSheet()->SetCellValue('E1', 'Parent Company');
                        $objPHPExcel->getActiveSheet()->SetCellValue('F1', 'Client Category');
                        $objPHPExcel->getActiveSheet()->SetCellValue('G1', 'Lead Agency');
                        $objPHPExcel->getActiveSheet()->SetCellValue('H1', 'Status');
                        $objPHPExcel->getActiveSheet()->SetCellValue('I1', 'Service');
                        $objPHPExcel->getActiveSheet()->SetCellValue('J1', 'Client Since (M-Y)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('K1', 'Lost Since(M-Y)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('L1', 'Pitched (M-Y)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('M1', 'Scope');
                        $objPHPExcel->getActiveSheet()->SetCellValue('N1', 'Active Markets');
                        if ($this->Auth->user('role') == 'Viewer') {
                                $objPHPExcel->getActiveSheet()->SetCellValue('O1', 'Comments');
                        } else {
                                $objPHPExcel->getActiveSheet()->SetCellValue('O1', 'Currency');
                                $objPHPExcel->getActiveSheet()->SetCellValue('P1', 'iP '.date('Y').' Estimated Revenue');
                                $objPHPExcel->getActiveSheet()->SetCellValue('Q1', 'Fiscal Yr. ' .date('Y').' Revenue');
                                $objPHPExcel->getActiveSheet()->SetCellValue('R1', 'iP '.(date('Y')-1).' Actual Revenue');
                                $col = 18;
                                if($exportRevenue == "YES") {
                                        foreach($noYears as $year)
                                        {
                                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                                $objPHPExcel->getActiveSheet()->SetCellValue($colName.'1', 'iP'.$year.' Actual Revenue');
                                                $col++;
                                        }
                                }
                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                $objPHPExcel->getActiveSheet()->SetCellValue($colName.'1', 'Comments');
                                $col++;
                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                $objPHPExcel->getActiveSheet()->SetCellValue($colName.'1', 'Created on');
                                $col++;
                                $colName = PHPExcel_Cell::stringFromColumnIndex($col);
                                $objPHPExcel->getActiveSheet()->SetCellValue($colName.'1', 'Last modified on');
                        }
                        if($exportRevenue == "YES") {
                                $prevRevenue = $this->ClientActualRevenueByYear->find('list', array('fields' => array('ClientActualRevenueByYear.fin_year', 'ClientActualRevenueByYear.actual_revenue','ClientActualRevenueByYear.client_service_id'), 'order' => 'ClientActualRevenueByYear.fin_year desc'));
                        }
                        $i = 1;
                        $arrDataExcel = array();
                        foreach($arrData as $data) {
                                if($data['ClientSince'] != '') {
                                        $clientSince = trim($data['ClientSince']);
                                } else {
                                        $clientSince = '';
                                }
                                if($data['Lost'] != '') {
                                        $lostDate = trim($data['Lost']);
                                } else {
                                        $lostDate = '';
                                }
                                if($data['PitchStart'] != '') {
                                        $pitchDate = trim($data['PitchStart']);
                                } else {
                                        $pitchDate = '';
                                }
                                if($exportCurrency == "Actual currencies") {
                                        $currency = $data['Currency'];
                                } else {
                                        $currency = $exportCurrency;
                                }
                                if($data['Created'] != '') {
                                        $createdDate = date('m/d/Y', strtotime($data['Created']));
                                } else {
                                        $createdDate = '01/01/2015';
                                }
                                if($data['Modified'] != '') {
                                        $modifiedDate = date('m/d/Y', strtotime($data['Modified']));
                                } else {
                                        $modifiedDate = '';
                                }
                                $estimatedRevenue = 0;
                                $actualRevenue = 0;
                                $fiscalRevenue = 0;
                                if ($this->Auth->user('role') != 'Viewer') {
                                        if($exportCurrency == "Actual currencies") {
                                                $estimatedRevenue = $data['EstimatedRevenue'];
                                                $actualRevenue = $data['ActualRevenue'];
                                                $fiscalRevenue = $data['FiscalRevenue'];
                                        } else {
                                                if(is_numeric($data['EstimatedRevenue'])) {
                                                        if($data['Currency'] == $exportCurrency) {
                                                                $estimatedRevenue = $data['EstimatedRevenue'];
                                                        } else {
                                                                $dollarConvertRatio = array_search($data['Currency'], $currencies);
                                                                if($exportCurrency == "USD") {
                                                                     $estimatedRevenue = ($data['EstimatedRevenue'] * $dollarConvertRatio);
                                                                } else {
                                                                     $dollarEstRevenue = ($data['EstimatedRevenue'] * $dollarConvertRatio);
                                                                     $estimatedRevenue = ($dollarEstRevenue / $convertRatio);
                                                                }
                                                        }
                                                }
                                                if(is_numeric($data['ActualRevenue'])) {
                                                        if($data['Currency'] == $exportCurrency) {
                                                                $actualRevenue = $data['ActualRevenue'];
                                                        } else {
                                                                $dollarConvertRatio = array_search($data['Currency'], $currencies);
                                                                if($exportCurrency == "USD") {
                                                                     $actualRevenue = ($data['ActualRevenue'] * $dollarConvertRatio);
                                                                } else {
                                                                     $dollarEstRevenue = ($data['ActualRevenue'] * $dollarConvertRatio);
                                                                     $actualRevenue = ($dollarEstRevenue / $convertRatio);
                                                                }
                                                        }
                                                }
                                                if(is_numeric($data['FiscalRevenue'])) {
                                                        if($data['Currency'] == $exportCurrency) {
                                                                $actualRevenue = $data['FiscalRevenue'];
                                                        } else {
                                                                $dollarConvertRatio = array_search($data['Currency'], $currencies);
                                                                if($exportCurrency == "USD") {
                                                                     $actualRevenue = ($data['FiscalRevenue'] * $dollarConvertRatio);
                                                                } else {
                                                                     $dollarEstRevenue = ($data['FiscalRevenue'] * $dollarConvertRatio);
                                                                     $actualRevenue = ($dollarEstRevenue / $convertRatio);
                                        }
                                                        }
                                                }
                                        }
                                        $row = array($data['Region'], $data['Country'], $data['City'],
                                            $data['ClientName'], $data['ParentCompany'], $data['ClientCategory'], $data['LeadAgency'],
                                            $data['PitchStage'], $data['Service'],$clientSince, $lostDate, $pitchDate, $data['MarketScope'],
                                            html_entity_decode($data['ActiveMarkets']), $currency, (($estimatedRevenue == 0) ? '' : $estimatedRevenue),(($fiscalRevenue == 0) ? '' : $fiscalRevenue),(($actualRevenue == 0) ? '' : $actualRevenue));
                                        if($exportRevenue == "YES") {
                                                $recordId = $data['RecordId'];
                                                if(isset($prevRevenue[$recordId])){
                                                        $prevRevenueByYear = $prevRevenue[$recordId];
                                                        foreach($noYears as $year)
                                                        {
                                                                if(isset($prevRevenueByYear[$year])) {
                                                                        $row[] = $prevRevenueByYear[$year];
                                                                } else {
                                                                        $row[] = '';
                                                                }
                                                        }
                                                } else {
                                                        foreach($noYears as $year)
                                                        {
                                                                $row[] = '';
                                                        }
                                                }
                                        }
                                        $row[] = ($data['Comments'] == null) ? '' : $data['Comments'];
                                        $row[] = $createdDate;
                                        $row[] = $modifiedDate;
                                        $arrDataExcel[] = $row;
                                } else {
                                        $arrDataExcel[] = array($data['Region'], $data['Country'], $data['City'],
                                            $data['ClientName'], $data['ParentCompany'], $data['ClientCategory'], $data['LeadAgency'],
                                            $data['PitchStage'], $data['Service'], $clientSince, $lostDate, $pitchDate,
                                            $data['MarketScope'], html_entity_decode($data['ActiveMarkets']), $data['Comments']);
                                }
                                $i++;
                        }
                        if(!empty($arrDataExcel)) {
                                if ($this->Auth->user('role') != 'Viewer') {
                                        $objPHPExcel->getActiveSheet()->getStyle('A2:'.$colName.$i)->applyFromArray(array('font' => array('size'  => 11, 'name'  => 'Calibri'), 'alignment' => array('wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                                        $objPHPExcel->getActiveSheet()->getStyle('P2:P'.$i)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_NUMBER_00);
                                        $objPHPExcel->getActiveSheet()->getStyle('Q2:Q'.$i)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_NUMBER_00);
                                        $objPHPExcel->getActiveSheet()->getStyle('R2:R'.$i)->getNumberFormat()->setFormatCode(PHPExcel_Style_NumberFormat::FORMAT_NUMBER_00);
                                        $objPHPExcel->getActiveSheet()->fromArray($arrDataExcel, null, 'A2');
                                        $objPHPExcel->getActiveSheet()->setAutoFilter('A1:'.$colName.$i);
                                } else {
                                        if($exportFormat != 'csv') {
                                                $objPHPExcel->getActiveSheet()->getStyle('A2:O'.$i)->applyFromArray(array('font' => array('size'  => 11, 'name'  => 'Calibri'), 'alignment' => array('wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                                        }
                                        $objPHPExcel->getActiveSheet()->fromArray($arrDataExcel, null, 'A2');
                                        if($exportFormat != 'csv') {
                                                $objPHPExcel->getActiveSheet()->setAutoFilter('A1:O'.$i);
                                        }
                                }
                        }
                        // Rename sheet
                        $objPHPExcel->getActiveSheet()->setTitle('Client List');
                        // Save Excel 2007/CSV file
                        if($exportFormat == 'csv') {
                                $fileName = 'Current_Client_Data_' . date('m-d-Y') . '.csv';
                                $objWriter = new PHPExcel_Writer_CSV($objPHPExcel);
                        } else {
                                $fileName = 'Current_Client_Data_' . date('m-d-Y') . '.xlsx';
                                $objWriter = new PHPExcel_Writer_Excel2007($objPHPExcel);
                        }
                        $objWriter->save('files/' . $fileName);
                        if($exportOption=="export_download"){
                                $result = array('filename' => $fileName);
                                $result['success'] = true;
                        }else{
                                $user=array();
                                $user = $this->User->find('first', array('fields' => array('User.email_id'), 'conditions' => array('User.id' => $this->Auth->user('id'))));
                                $email=new CakeEmail('gmail');
                                $email->viewVars(array('title_for_layout' => 'Client data export'));
                                $email->template('clientdata_export', 'default')
                                   ->emailFormat('html')
                                   ->attachments('files/'.$fileName)
                                   ->to(array($user['User']['email_id']))
                                   ->from(array('connectiprospect@gmail.com' => 'Connect iProspect'))
                                   ->subject('Client data export');
                                if($email->send()){
                                        $success="Email has been sent successfully on " . $user['User']['email_id'];
                                        $result = array('message' => $success);
                                        $result['success'] = true;
                                } else{
                                        $error="Unable to send email to " . $user['User']['email_id'] . ". Please try later.";
                                        $result = array('message' => $error);
                                        $result['success'] = false;
                               }
                        }
                        return json_encode($result);
                }
        }
        
        public function office_data() {

                $arrKeyDepts = array('Executive' => 'executive', 'FinanceHead' => 'finance_head', 'ProductHead' => 'product_head', 'StrategyHead' => 'strategy_head', 'ClientHead' => 'client_head', 'BusinessHead' => 'business_head', 'MarketingHead' => 'marketing_head');
                $arrServices = array(11 => 'Search', 12 => 'SEO',6 => 'Display',1 => 'Affiliates',  2 => 'Content',  4 => 'Data');
                $countries = $this->Country->find('list', array('fields' => array('Country.country', 'Country.country'), 'order' => 'Country.country Asc'));
                $this->set('countries', json_encode($countries, JSON_HEX_APOS));
                $arrRegions = array();
                $regions = $this->Region->find('all', array('order' => 'Region.region Asc'));
                foreach ($regions as $region) {
                        $arrRegions[$region['Region']['region']] = $region['Region']['region'];
                }
                $this->set('regions', json_encode($arrRegions));
                $arrLanguages = $this->Language->find('list', array('fields' => array('Language.language', 'Language.language'), 'order' => 'Language.language Asc'));
                $this->set('departments', $arrKeyDepts);
                $this->set('services', $arrServices);
                $this->set('json_services', json_encode($arrServices));
                $this->set('languages', json_encode($arrLanguages));
                $this->set('userRole', $this->Auth->user('role'));
                $userMarkets = array();
                if($this->Auth->user('role') == 'Regional') {
                        $arrUserMarkets = $this->UserMarket->find('all', array('fields' => array('UserMarket.market_id'),'conditions' => array('UserMarket.user_id' => $this->Auth->user('id'), 'UserMarket.active' => 1)));
                        $arrUserRegions = array();
                        foreach($arrUserMarkets as $arrUserMarket) {
                               $arrUserRegions[] = $arrUserMarket['UserMarket']['market_id'];
                        }
                        $userMarkets = $this->Region->find('list', array('conditions' => array('Region.id in (' . implode(',', $arrUserRegions) . ')')));
                } elseif($this->Auth->user('role') == 'Country' || $this->Auth->user('role') == 'Country - Viewer') {
                        $arrUserMarkets = $this->UserMarket->find('all', array('fields' => array('UserMarket.market_id'),'conditions' => array('UserMarket.user_id' => $this->Auth->user('id'), 'UserMarket.active' => 1)));
                        $arrCountries = array();
                        foreach($arrUserMarkets as $arrUserMarket) {
                               $arrCountries[] = $arrUserMarket['UserMarket']['market_id'];
                        }
                        $userMarkets = $this->Country->find('list', array('conditions' => array('Country.id in (' . implode(',', $arrCountries) . ')')));
                }
                $arrPreference = $this->UserGridPreference->find('first', array('fields' =>array('UserGridPreference.preference'),'conditions' => array('UserGridPreference.user_id' => $this->Auth->user('id'),'UserGridPreference.formname' =>'office_data')));
                if(!empty($arrPreference)) {
                        $this->set('widthPreferences_office_data', $arrPreference['UserGridPreference']['preference']);
                } else {
                        $this->set('widthPreferences_office_data', '{}');
                }
                $this->set('userMarkets', json_encode($userMarkets));
        }

        public function get_office_data() {
                $this->autoRender=false;
                $officeData = array();
                $arrKeyDepts = array('Executive' => 'executive','BusinessHead' => 'business_head');
                $arrServices = array(11 => 'Search', 12 => 'SEO',6 => 'Display',1 => 'Affiliates',  2 => 'Content',  4 => 'Data');
                $i = 0;
                $conditions = array();
                if(isset($_GET['mode']) && $_GET['mode'] == 'edit') {
                        if ($this->Auth->user('role') == 'Regional') {
                                $regions = $this->UserMarket->find('all', array('conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                                $arrRegions = array();
                                foreach ($regions as $region) {
                                        $arrRegions[] = $region['UserMarket']['market_id'];
                                }
                                $conditions[] = 'Office.region_id IN (' . implode(',', $arrRegions) . ')';
                        }
                        if ($this->Auth->user('role') == 'Country') {
                                $countries = $this->UserMarket->find('all', array('conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                                $arrCountries = array();
                                foreach ($countries as $country) {
                                        $arrCountries[] = $country['UserMarket']['market_id'];
                                }
                                $conditions[] = 'Office.country_id IN (' . implode(',', $arrCountries) . ')';
                        }
                }
                $this->Office->Behaviors->attach('Containable');
                $offices = $this->Office->find('all', array('conditions' => $conditions, 'order' => 'Region.region Asc, Country.country, City.city'));

                foreach($offices as $office) {
                        $officeData[$i]['RecordId'] = $office['Office']['id'];
                        $officeData[$i]['Region'] = $office['Region']['region'];
                        $officeData[$i]['Country'] = $office['Country']['country'];
                        $officeData[$i]['City'] = $office['City']['city'];
                        $officeData[$i]['YearEstablished'] = $office['Office']['year_established'];
                        $officeData[$i]['TotalEmployee'] = $office['Office']['employee_count'];
                        $keyContacts = array();
                        foreach($office['OfficeKeyContact'] as $officeKeyContact) {
                                $keyContacts[$officeKeyContact['contact_type']][] = $officeKeyContact['contact_name'] . (!empty($officeKeyContact['contact_title']) ? "<br/>" . $officeKeyContact['contact_title'] : "<br/>" . 'title') . (!empty($officeKeyContact['contact_email']) ? "<br/><a href='mailto:" . $officeKeyContact['contact_email'] . "' target='_blank'>" . $officeKeyContact['contact_email'] . '</a>' : "<br/>" . 'email');
                        }
                        foreach($arrKeyDepts as $key => $keyDept) {
                                if(isset($keyContacts[$keyDept])) {
                                        $officeData[$i][$key] = implode("<br/>-------------------------<br/>", $keyContacts[$keyDept]);
                                } else {
                                        $officeData[$i][$key] = '';
                                }
                        }
                        $serviceContacts = array();
                        foreach($office['OfficeServiceContact'] as $officeServiceContact) {
                                $serviceContacts[$officeServiceContact['service_id']][] = $officeServiceContact['contact_name'] . (!empty($officeServiceContact['contact_title']) ? "<br/>" . $officeServiceContact['contact_title'] : "<br/>" . 'title') . (!empty($officeServiceContact['contact_email']) ? "<br/><a href='mailto:" . $officeServiceContact['contact_email'] . "' target='_blank'>" . $officeServiceContact['contact_email'] . '</a>' : "<br/>" . 'email');
                        }
                        foreach($arrServices as $serviceId => $service) {
                                if(isset($serviceContacts[$serviceId])) {
                                        $officeData[$i][$service] = implode("<br/>-------------------------<br/>", $serviceContacts[$serviceId]);
                                } else {
                                        $officeData[$i][$service] = '';
                                }
                        }
                        $i++;
                }
                echo json_encode($officeData);
        }

        public function save_office_record() {
                $arrKeyDepts = array('Executive' => 'executive','BusinessHead' => 'business_head');
                $arrServices = array(11 => 'Search', 12 => 'SEO',6 => 'Display',1 => 'Affiliates',  2 => 'Content',  4 => 'Data');
                if ($this->request->isPost()) {
                        if($this->RequestHandler->isAjax()){
                                $this->autoRender=false;
                        }
                        $arrData = $this->request->data;
                        $region = $this->Region->findByRegion(trim($arrData['Region']));
                        $country = $this->Country->findByCountry(trim($arrData['Country']));
                        if(!empty($arrData['RecordId'])) {
                                $officeId = $arrData['RecordId'];
                                $this->Office->id = $officeId;
                                $this->Office->save(
                                        array(
                                                'Office' => array(
                                                        'region_id' => $region['Region']['id'],
                                                        'year_established' => $arrData['YearEstablished'],
                                                        'employee_count' => $arrData['EmployeeCount']
                                                )
                                        )
                                );
                                $marketExists = $this->Market->find('first', array('conditions' => array('region_id' => $region['Region']['id'], 'country_id' => $country['Country']['id'])));
                                $this->Market->id = $marketExists['Market']['id'];
                                $this->Market->save(
                                        array('Market' => array(
                                                        'region_id' => $region['Region']['id'],
                                                )
                                        )
                                );

                                $this->OfficeAttribute->query('DELETE FROM `office_attributes` WHERE `office_id` = ' . $officeId);
                                $this->OfficeKeyContact->query('DELETE FROM `office_key_contacts` WHERE `office_id` = ' . $officeId);
                                $this->OfficeServiceContact->query('DELETE FROM `office_service_contacts` WHERE `office_id` = ' . $officeId);
                                $this->OfficeEmployeeCountByDepartment->query('DELETE FROM `office_employee_count_by_departments` WHERE `office_id` = ' . $officeId);
                                $this->OfficeLanguage->query('DELETE FROM `office_languages` WHERE `office_id` = ' . $officeId);
                        } else {
                                $marketExists = $this->Market->find('count', array('conditions' => array('region_id' => $region['Region']['id'], 'country_id' => $country['Country']['id'])));
                                if($marketExists == 0) {
                                        $this->Market->create();
                                        $this->Market->save(
                                                array('Market' => array(
                                                                'region_id' => $region['Region']['id'],
                                                                'country_id' => $country['Country']['id'],
                                                                'market' => $arrData['Country']
                                                        )
                                                )
                                        );
                                }

                                $city = $arrData['City'];
                                $this->City->create();
                                $this->City->save(
                                        array('City' => array(
                                                        'city' => $city,
                                                        'country_id' => $country['Country']['id']
                                                )
                                        )
                                );
                                $cityId = $this->City->getLastInsertId();

                                $this->Office->create();
                                $this->Office->save(
                                        array(
                                                'Office' => array(
                                                        'region_id' => $region['Region']['id'],
                                                        'country_id' => $country['Country']['id'],
                                                        'city_id' => $cityId,
                                                        'year_established' => $arrData['YearEstablished'],
                                                        'employee_count' => $arrData['EmployeeCount']
                                                )
                                        )
                                );
                                $officeId = $this->Office->getLastInsertId();
                        }

                        foreach($arrData['KeyContacts'] as $deptContacts) {
                                $keyDept = $arrKeyDepts[$deptContacts['dept_name']];
                                foreach($deptContacts['dept_contacts'] as $deptContact) {
                                        if(!empty($deptContact)) {
                                                $dataDeptContact = explode('/', $deptContact);
                                                $contactName = $dataDeptContact[0];
                                                if(isset($dataDeptContact[1]) && $dataDeptContact[1] != 'title') {
                                                        $contactTitle = $dataDeptContact[1];
                                                } else {
                                                        $contactTitle = '';
                                                }
                                                if(isset($dataDeptContact[2]) && $dataDeptContact[2] != 'email') {
                                                        $contactEmail = $dataDeptContact[2];
                                                } else {
                                                        $contactEmail = '';
                                                }
                                                $this->OfficeKeyContact->create();
                                                $this->OfficeKeyContact->save(
                                                        array(
                                                                'OfficeKeyContact' => array(
                                                                        'office_id' => $officeId,
                                                                        'contact_type' => $keyDept,
                                                                        'contact_name' => $contactName,
                                                                        'contact_title' => $contactTitle,
                                                                        'contact_email' => $contactEmail
                                                                )
                                                        )
                                                );
                                        }
                                }
                        }
                        foreach($arrData['ServicesContacts'] as $serviceContacts) {
                                $serviceId = array_search($serviceContacts['service_name'], $arrServices);
                                foreach($serviceContacts['service_contacts'] as $serviceContact) {
                                        if(!empty($serviceContact)) {
                                                $dataServiceContact = explode('/', $serviceContact);
                                                $contactName = $dataServiceContact[0];
                                                if(isset($dataServiceContact[1]) && $dataServiceContact[1] != 'title') {
                                                        $contactTitle = $dataServiceContact[1];
                                                } else {
                                                        $contactTitle = '';
                                                }
                                                if(isset($dataServiceContact[2]) && $dataServiceContact[2] != 'email') {
                                                        $contactEmail = $dataServiceContact[2];
                                                } else {
                                                        $contactEmail = '';
                                                }
                                                $this->OfficeServiceContact->create();
                                                $this->OfficeServiceContact->save(
                                                        array(
                                                                'OfficeServiceContact' => array(
                                                                        'office_id' => $officeId,
                                                                        'service_id' => $serviceId,
                                                                        'contact_name' => $contactName,
                                                                        'contact_title' => $contactTitle,
                                                                        'contact_email' => $contactEmail
                                                                )
                                                        )
                                                );
                                        }
                                }
                        }
                }
                $result = array();
                $result['success'] = true;
                return json_encode($result);
        }

        public function delete_office_record() {
                if ($this->request->isPost()) {
                        if($this->RequestHandler->isAjax()){
                                $this->autoRender=false;
                        }

                        $arrData = $this->request->data;

                        if ($this->Office->delete($arrData['RecordId'])) {
                                $this->OfficeAttribute->query('DELETE FROM `office_attributes` WHERE `office_id` = ' . $arrData['RecordId']);
                                $this->OfficeKeyContact->query('DELETE FROM `office_key_contacts` WHERE `office_id` = ' . $arrData['RecordId']);
                                $this->OfficeServiceContact->query('DELETE FROM `office_service_contacts` WHERE `office_id` = ' . $arrData['RecordId']);
                                $this->OfficeEmployeeCountByDepartment->query('DELETE FROM `office_employee_count_by_departments` WHERE `office_id` = ' . $arrData['RecordId']);
                                $this->OfficeLanguage->query('DELETE FROM `office_languages` WHERE `office_id` = ' . $arrData['RecordId']);

                                $result = array();
                                $result['success'] = true;
                                return json_encode($result);
                        }
                }
        }

        public function office_report() {

                $arrLanguages = $this->Language->find('list', array('fields' => array('Language.language', 'Language.language'), 'order' => 'Language.language Asc'));
                $this->set('languages', json_encode($arrLanguages));
                $arrPreference = $this->UserGridPreference->find('first', array('fields' =>array('UserGridPreference.preference'),'conditions' => array('UserGridPreference.user_id' => $this->Auth->user('id'),'UserGridPreference.formname' =>'office_report')));
                if(!empty($arrPreference)) {
                        $this->set('widthPreferences_office_report', $arrPreference['UserGridPreference']['preference']);
                } else {
                        $this->set('widthPreferences_office_report', '{}');
                }
                $this->set('userRole', $this->Auth->user('role'));
                $this->set('loggedUser', $this->Auth->user());
                $this->set('userAcl', $this->Acl);
        }

        public function export_office_data() {
                set_time_limit(0);
                ini_set('memory_limit', '-1');

                if ($this->request->isPost()) {
                        if($this->RequestHandler->isAjax()){
                                $this->autoRender=false;
                        }

                        $arrData = $this->request->data;

                        App::import('Vendor', 'PHPExcel', array('file' => 'PhpExcel/PHPExcel.php'));
                        if (!class_exists('PHPExcel')) {
                                throw new CakeException('Vendor class PHPExcel not found!');
                        }
                        App::import('Vendor', 'PHPExcel_Writer_Excel2007', array('file' => 'PhpExcel/PHPExcel/Writer/Excel2007.php'));
                        if (!class_exists('PHPExcel_Writer_Excel2007')) {
                                throw new CakeException('Vendor class PHPExcel not found!');
                        }

                        $objPHPExcel = new PHPExcel();

                        // Set properties
                        $objPHPExcel->getProperties()->setCreator($this->Auth->user('display_name'));
                        $objPHPExcel->getProperties()->setLastModifiedBy($this->Auth->user('display_name'));
                        $objPHPExcel->getProperties()->setTitle("Office Data by date " . date('m/d/Y'));
                        $objPHPExcel->getProperties()->setSubject("Office Data by date " . date('m/d/Y'));

                        // Add some data
                        $objPHPExcel->setActiveSheetIndex(0);
                        $objPHPExcel->getActiveSheet()->mergeCells('A1:E1');
                        $objPHPExcel->getActiveSheet()->mergeCells('F1:G1');
                        $objPHPExcel->getActiveSheet()->getStyle("A1:M2")->applyFromArray(array("font" => array( "bold" => true, 'size'  => 12, 'name'  => 'Calibri'), 'alignment' => array('horizontal' => PHPExcel_Style_Alignment::HORIZONTAL_CENTER_CONTINUOUS, 'wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                        $objPHPExcel->getActiveSheet()->getStyle('A1:E1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('CCC0DA');
                        $objPHPExcel->getActiveSheet()->getStyle('F1:G1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('C5D9F1');
                        $objPHPExcel->getActiveSheet()->getStyle('H1:M1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('CCC0DA');
                        $objPHPExcel->getActiveSheet()->getStyle('A2:E2')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('CCC0DA');
                        $objPHPExcel->getActiveSheet()->getStyle('F2:G2')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('C5D9F1');
                        $objPHPExcel->getActiveSheet()->getStyle('H2:M2')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('CCC0DA');
                        $objPHPExcel->getActiveSheet()->getColumnDimension("A")->setWidth(11);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("B")->setWidth(11);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("C")->setWidth(18);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("D")->setWidth(14);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("E")->setWidth(14);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("F")->setWidth(34);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("G")->setWidth(25);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("H")->setWidth(28);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("I")->setWidth(28);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("J")->setWidth(28);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("K")->setWidth(28);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("L")->setWidth(28);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("M")->setWidth(28);
                        $objPHPExcel->getActiveSheet()->SetCellValue('A1', 'General Information');
                        $objPHPExcel->getActiveSheet()->SetCellValue('F1', 'Key management contacts');
                        $objPHPExcel->getActiveSheet()->SetCellValue('H1', 'Head of Affiliates');
                        $objPHPExcel->getActiveSheet()->SetCellValue('I1', 'Head of Content');
                        $objPHPExcel->getActiveSheet()->SetCellValue('J1', 'Head of Data and Insights');
                        $objPHPExcel->getActiveSheet()->SetCellValue('K1', 'Head of Display');
                        $objPHPExcel->getActiveSheet()->SetCellValue('L1', 'Head of Search-PPC');
                        $objPHPExcel->getActiveSheet()->SetCellValue('M1', 'Head of SEO');
                        $objPHPExcel->getActiveSheet()->SetCellValue('A2', 'Region');
                        $objPHPExcel->getActiveSheet()->SetCellValue('B2', 'Market');
                        $objPHPExcel->getActiveSheet()->SetCellValue('C2', 'Location name (City)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('D2', 'Year established');
                        $objPHPExcel->getActiveSheet()->SetCellValue('E2', 'Total # employees');
                        $objPHPExcel->getActiveSheet()->SetCellValue('F2', 'Head of Office(Name/title/email address)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('G2', 'Head of New Business (Name/title/email address)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('H2', 'Key contact (Name/title/email address)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('I2', 'Key contact (Name/title/email address)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('J2', 'Key contact (Name/title/email address)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('K2', 'Key contact (Name/title/email address)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('L2', 'Key contact (Name/title/email address)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('M2', 'Key contact (Name/title/email address)');
 
                        $i = 2;
                        $arrDataExcel = array();
                        foreach($arrData as $data) {
                                $arrDataExcel[] = array($data['Region'], $data['Country'], $data['City'], $data['YearEstablished'],
                                    $data['TotalEmployee'],
                                    strip_tags(str_replace('<br/>', "\n", $data['Executive'])),
                                    strip_tags(str_replace('<br/>', "\n", $data['BusinessHead'])),
                                    strip_tags(str_replace('<br/>', "\n", $data['Affiliates'])),
                                    strip_tags(str_replace('<br/>', "\n", $data['Content'])),
                                    strip_tags(str_replace('<br/>', "\n", $data['Data'])),
                                    strip_tags(str_replace('<br/>', "\n", $data['Display'])),
                                    strip_tags(str_replace('<br/>', "\n", $data['Search'])),
                                    strip_tags(str_replace('<br/>', "\n", $data['SEO']))

                                 );
                                $i++;
                        }
                        if(!empty($arrDataExcel)) {
                                $objPHPExcel->getActiveSheet()->getStyle('A3:M'.$i)->applyFromArray(array('font' => array('size'  => 11, 'name'  => 'Calibri'), 'alignment' => array('wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                                $objPHPExcel->getActiveSheet()->fromArray($arrDataExcel, null, 'A3');
                                $objPHPExcel->getActiveSheet()->setAutoFilter('A2:M'.$i);
                        }

                        // Rename sheet
                        $objPHPExcel->getActiveSheet()->setTitle('Offices List');

                        // Save Excel 2007 file
                        $objWriter = new PHPExcel_Writer_Excel2007($objPHPExcel);
                        $objWriter->save('files/Office_Data_' . date('m-d-Y') . '.xlsx');
                }
                $result = array();
                $result['success'] = true;
                return json_encode($result);
        }

        public function get_actual_revenue() {
                if($this->RequestHandler->isAjax()) {
                        $this->autoRender=false;
                }
                $arrData = $this->request->data;
                $recordId = $arrData['RecordId'];
                $arrRevenue = $this->ClientActualRevenueByYear->find('list', array('fields' => array('ClientActualRevenueByYear.fin_year','ClientActualRevenueByYear.actual_revenue'),'conditions' => array('ClientActualRevenueByYear.client_service_id' => $recordId),'order' => 'ClientActualRevenueByYear.fin_year desc'));
                $result = array();
                $result['success'] = true;
                $result['data'] = $arrRevenue;
                return json_encode($result);
        }

        public function user_grid_preferences() {
                if($this->RequestHandler->isAjax()) {
                        $this->autoRender=false;
                }
                $user_id=$this->Auth->user('id');
                $gridStatus= $this->request->data;
                $recordExists = $this->UserGridPreference->find('first', array('fields' =>array('UserGridPreference.id', 'UserGridPreference.preference'),'conditions' => array('UserGridPreference.user_id' => $this->Auth->user('id'),'UserGridPreference.formname' =>$gridStatus['formname'])));
                if(!empty($recordExists)) {
                        $this->UserGridPreference->id = $recordExists['UserGridPreference']['id'];
                        $this->UserGridPreference->save(
                                  array(
                                        'UserGridPreference' => array(
                                                'preference'=>  json_encode($gridStatus['state'])
                                               )
                                       )
                                );
                } else {
                        $this->UserGridPreference->create();
                        $this->UserGridPreference->save(
                                  array(
                                        'UserGridPreference' => array(
                                                'user_id'=>$user_id,
                                                'preference'=>  json_encode($gridStatus['state']),
                                                'formname'=>$gridStatus['formname'],
                                                'created' =>date('Y-m-d H:i:s')
                                               )
                                       )
                                );
                }
        }

        public function delete_grid_preferences() {
                if($this->RequestHandler->isAjax()) {
                          $this->autoRender=false;
                  }
                $data = $this->request->data;
                $user_id=$this->Auth->user('id');
                $this->UserGridPreference->query('DELETE FROM `user_grid_preferences` WHERE `user_id`='.$user_id.' AND `formname` = \''.$data['formname'].'\'');
        }

        public function client_delete_log() {

                $this->set('currencies', json_encode($this->Currency->find('list', array('fields' => array('Currency.convert_rate', 'Currency.currency'), 'order' => 'Currency.currency Asc'))));
                $this->set('current_year', date('Y'));
                $arrMarkets = array();
                $arrRegions = array();
                $arrCities = array();
                $regions = $this->Region->find('all', array('order' => 'Region.region Asc'));
                foreach ($regions as $region) {
                        $arrRegions[$region['Region']['region']] = $region['Region']['region'];
                        $markets = $this->Market->find('list', array('fields' => array('Market.country_id', 'Market.market'), 'conditions' => array('Market.region_id' => $region['Region']['id']), 'order' => 'Market.market Asc'));
                        if(!empty($markets)) {
                                foreach ($markets as $countryId => $market)
                                {
                                        $arrMarkets[$region['Region']['region']][$market] = $market;
                                        $cities = $this->City->find('list', array('fields' => array('City.city', 'City.city'), 'conditions' => array('City.country_id' => $countryId), 'order' => 'City.city Asc'));
                                        if(!empty($cities)) {
                                                $arrCities[$market] = $cities;
                                        }
                                }
                        }
                }
                $this->set('regions', json_encode($arrRegions));
                $this->set('markets', json_encode($arrMarkets));
                $this->set('cities', json_encode($arrCities));
        }

        public function get_deleted_records() {
                $this->autoRender=false;

                $clientData = array();
                $i = 0;
                $this->ClientDeleteLog->Behaviors->attach('Containable');
                $clients = $this->ClientDeleteLog->query("CALL allDeletedClients();");
                //echo '<pre>'; print_r($clients); exit(0);

                foreach ($clients as $client) {
                        $clientData[$i]['id'] = $client['ClientDeleteLog']['id'];
                        $clientData[$i]['RecordId'] = $client['ClientDeleteLog']['record_id'];
                        $clientData[$i]['Region'] = $client[0]['region'];
                        if ($client['ClientDeleteLog']['managing_entity'] == 'Global') {
                                $clientData[$i]['Country'] = 'Global';
                                $clientData[$i]['City'] = 'Global';
                        } elseif ($client['ClientDeleteLog']['managing_entity'] == 'Regional') {
                                $clientData[$i]['Country'] = 'Regional - ' . $client[0]['region'];
                                $clientData[$i]['City'] = 'Regional - ' . $client[0]['region'];
                        } else {
                                $clientData[$i]['Country'] = $client[0]['country'];
                                $clientData[$i]['City'] = $client[0]['city'];
                        }
                        $clientData[$i]['LeadAgency'] = $client[0]['agency'];
                        $clientData[$i]['ClientName'] = $client['ClientDeleteLog']['client_name'];
                        $clientData[$i]['SearchClientName'] = strtr( $client['ClientDeleteLog']['client_name'], $this->unwanted_array );
                        $clientData[$i]['ParentCompany'] = $client['ClientDeleteLog']['parent_company'];
                        $clientData[$i]['SearchParentCompany'] = strtr( $client['ClientDeleteLog']['parent_company'], $this->unwanted_array );
                        $clientData[$i]['ClientCategory'] = $client[0]['category'];
                        if ($client['ClientDeleteLog']['pitch_date'] != '0000-00-00') {
                                $pitchDate = explode('-', $client['ClientDeleteLog']['pitch_date']);
                                $clientData[$i]['PitchStart'] = $pitchDate[1] . '/' . $pitchDate[0];
                        } else {
                                $clientData[$i]['PitchStart'] = '';
                        }
                        $clientData[$i]['PitchStage'] = $client['ClientDeleteLog']['pitch_stage'];
                        if ($client['ClientDeleteLog']['lost_date'] != '0000-00-00') {
                                $lostDate = explode('-', $client['ClientDeleteLog']['lost_date']);
                                $clientData[$i]['Lost'] = $lostDate[1] . '/' . $lostDate[0];
                        } else {
                                $clientData[$i]['Lost'] = '';
                        }
                        $clientData[$i]['ClientMonth'] = ($client['ClientDeleteLog']['client_since_month'] != 0 && $client['ClientDeleteLog']['client_since_month'] != null) ? $this->months[$client['ClientDeleteLog']['client_since_month']] : '';
                        $clientData[$i]['ClientYear'] = $client['ClientDeleteLog']['client_since_year'];
                        if ($client['ClientDeleteLog']['client_since_month'] != 0 && $client['ClientDeleteLog']['client_since_year'] != 0) {
                                $clientData[$i]['ClientSince'] = $client['ClientDeleteLog']['client_since_month']. '/' .$client['ClientDeleteLog']['client_since_year'];
                        } elseif ($client['ClientDeleteLog']['client_since_month'] == 0 && $client['ClientDeleteLog']['client_since_year'] != 0) {
                                $clientData[$i]['ClientSince'] = '01/' .$client['ClientDeleteLog']['client_since_year'];
                        } else {
                                $clientData[$i]['ClientSince'] = '';
                        }
                        $clientData[$i]['Service'] = $client[0]['service_name'];
                        $clientData[$i]['MarketScope'] = $client['ClientDeleteLog']['market_scope'];
                        $clientData[$i]['ActiveMarkets'] = $client['ClientDeleteLog']['active_markets'];

                        $estimatedRevenue = $client['ClientDeleteLog']['estimated_revenue'];
                        $fiscalRevenue = $client['ClientDeleteLog']['fiscal_revenue']; 
                        $clientData[$i]['EstimatedRevenue'] = (($estimatedRevenue == 0) ? '' : $estimatedRevenue);
                        $clientData[$i]['FiscalRevenue'] = (($fiscalRevenue == 0) ? '' : $fiscalRevenue);
                        $clientData[$i]['Currency'] = $client[0]['currency'];
                        $clientData[$i]['Comments'] = $client['ClientDeleteLog']['comments'];
                        $clientData[$i]['Year'] = $client['ClientDeleteLog']['year'];
                        $clientData[$i]['Created'] = $client['ClientDeleteLog']['created'];
                        $clientData[$i]['Deleted'] = $client['ClientDeleteLog']['deleted'];
                        if($client['ClientDeleteLog']['deleted_by'] == 1) {
                                $clientData[$i]['DeletedBy'] = 'System';
                                $clientData[$i]['SearchDeletedBy'] = 'System';
                        } else {
                                $clientData[$i]['DeletedBy'] = $client[0]['deleted_by_name'];
                                $clientData[$i]['SearchDeletedBy'] = strtr( $client[0]['deleted_by_name'], $this->unwanted_array );
                        }

                        $i++;
                }
                echo json_encode($clientData);
        }

        public function export_client_delete_log() {
                set_time_limit(0);
                ini_set('memory_limit', '-1');

                if ($this->request->isPost()) {
                        if($this->RequestHandler->isAjax()){
                                $this->autoRender=false;
                        }
                        date_default_timezone_set($this->request->data['timezone']);

                        $arrData = $this->request->data['datarows'];

                        App::import('Vendor', 'PHPExcel', array('file' => 'PhpExcel/PHPExcel.php'));
                        if (!class_exists('PHPExcel')) {
                                throw new CakeException('Vendor class PHPExcel not found!');
                        }
                        App::import('Vendor', 'PHPExcel_Writer_Excel2007', array('file' => 'PhpExcel/PHPExcel/Writer/Excel2007.php'));
                        if (!class_exists('PHPExcel_Writer_Excel2007')) {
                                throw new CakeException('Vendor class PHPExcel not found!');
                        }
                        $objPHPExcel = new PHPExcel();
                        // Set properties
                        $objPHPExcel->getProperties()->setCreator($this->Auth->user('display_name'));
                        $objPHPExcel->getProperties()->setLastModifiedBy($this->Auth->user('display_name'));
                        $objPHPExcel->getProperties()->setTitle("Client Data Deletion log by date " . date('m/d/Y'));
                        $objPHPExcel->getProperties()->setSubject("Client Data Deletion log " . date('m/d/Y'));

                        // Add some data
                        $objPHPExcel->setActiveSheetIndex(0);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("A")->setWidth(30);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("B")->setWidth(15);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("C")->setWidth(20);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("D")->setWidth(20);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("E")->setWidth(40);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("F")->setWidth(40);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("G")->setWidth(35);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("H")->setWidth(15);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("I")->setWidth(20);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("J")->setWidth(30);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("K")->setWidth(10);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("L")->setWidth(10);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("M")->setWidth(10);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("N")->setWidth(15);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("O")->setWidth(35);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("P")->setWidth(20);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("Q")->setWidth(20);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("R")->setWidth(40);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("S")->setWidth(15);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("T")->setWidth(15);
                        $objPHPExcel->getActiveSheet()->getStyle("A1:S1")->applyFromArray(array("font" => array( "bold" => true, 'size'  => 12, 'name'  => 'Calibri'), 'alignment' => array('horizontal' => PHPExcel_Style_Alignment::HORIZONTAL_CENTER_CONTINUOUS, 'wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                        $objPHPExcel->getActiveSheet()->getStyle('A1:F1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('CCC0DA');
                        $objPHPExcel->getActiveSheet()->getStyle('G1:M1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('C5D9F1');
                        $objPHPExcel->getActiveSheet()->getStyle('N1:T1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('FCD5B4');

                        $objPHPExcel->getActiveSheet()->SetCellValue('A1', 'Deleted By');
                        $objPHPExcel->getActiveSheet()->SetCellValue('B1', 'Region');
                        $objPHPExcel->getActiveSheet()->SetCellValue('C1', 'Country');
                        $objPHPExcel->getActiveSheet()->SetCellValue('D1', 'City');
                        $objPHPExcel->getActiveSheet()->SetCellValue('E1', 'Client');
                        $objPHPExcel->getActiveSheet()->SetCellValue('F1', 'Parent Company');
                        $objPHPExcel->getActiveSheet()->SetCellValue('G1', 'Client Category');
                        $objPHPExcel->getActiveSheet()->SetCellValue('H1', 'Lead Agency');
                        $objPHPExcel->getActiveSheet()->SetCellValue('I1', 'Status');
                        $objPHPExcel->getActiveSheet()->SetCellValue('J1', 'Service');
                        $objPHPExcel->getActiveSheet()->SetCellValue('K1', 'Client Since (M-Y)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('L1', 'Lost Since(M-Y)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('M1', 'Pitched (M-Y)');
                        $objPHPExcel->getActiveSheet()->SetCellValue('N1', 'Scope');
                        $objPHPExcel->getActiveSheet()->SetCellValue('O1', 'Active Markets');
                        $objPHPExcel->getActiveSheet()->SetCellValue('P1', 'Currency');
                        $objPHPExcel->getActiveSheet()->SetCellValue('Q1', 'Estimated Revenue');
                        $objPHPExcel->getActiveSheet()->SetCellValue('R1', 'Fiscal Revenue');
                        $objPHPExcel->getActiveSheet()->SetCellValue('S1', 'Comments');
                        $objPHPExcel->getActiveSheet()->SetCellValue('T1', 'Deleted On');

                        $i = 1;
                        $arrDataExcel = array();
                        foreach($arrData as $data) {
                                if($data['ClientSince'] != '') {
                                        $clientSince = date('m/Y', strtotime($data['ClientSince']));
                                } else {
                                        $clientSince = '';
                                }
                                if($data['Lost'] != '') {
                                        $lostDate = date('m/Y', strtotime($data['Lost']));
                                } else {
                                        $lostDate = '';
                                }
                                if($data['PitchStart'] != '') {
                                        $pitchDate = date('m/Y', strtotime($data['PitchStart']));
                                } else {
                                        $pitchDate = '';
                                }
                                $currency = $data['Currency'];
                                if($data['Deleted'] != '') {
                                        $deletedDate = date('m/d/Y', strtotime($data['Deleted']));
                                } else {
                                        $deletedDate = '01/01/2015';
                                }
                                $estimatedRevenue = $data['EstimatedRevenue'];
                                $fiscalRevenue = $data['FiscalRevenue'];

                                $row = array($data['DeletedBy'], $data['Region'], $data['Country'], $data['City'],
                                    $data['ClientName'], $data['ParentCompany'], $data['ClientCategory'], $data['LeadAgency'],
                                    $data['PitchStage'], $data['Service'],$clientSince, $lostDate, $pitchDate, $data['MarketScope'],
                                    html_entity_decode($data['ActiveMarkets']), $currency, (($estimatedRevenue == 0) ? '' : $estimatedRevenue),
                                    (($fiscalRevenue == 0) ? '' : $fiscalRevenue),(($data['Comments'] == null) ? '' : $data['Comments']), $deletedDate);
                                    

                                $arrDataExcel[] = $row;
                                $i++;
                        }
                        if(!empty($arrDataExcel)) {
                                $objPHPExcel->getActiveSheet()->getStyle('A2:T'.$i)->applyFromArray(array('font' => array('size'  => 11, 'name'  => 'Calibri'), 'alignment' => array('wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                                $objPHPExcel->getActiveSheet()->fromArray($arrDataExcel, null, 'A2');
                                $objPHPExcel->getActiveSheet()->setAutoFilter('A1:T'.$i);
                        }

                        // Rename sheet
                        $objPHPExcel->getActiveSheet()->setTitle('Client Deletion Log');
                        // Save Excel 2007 file
                        $fileName = 'Client_Deleted_Log_' . date('m-d-Y') . '.xlsx';
                        $objWriter = new PHPExcel_Writer_Excel2007($objPHPExcel);
                        $objWriter->save('files/' . $fileName);
                        $result = array('filename' => $fileName);
                        $result['success'] = true;
                        return json_encode($result);
                }
        }
}
