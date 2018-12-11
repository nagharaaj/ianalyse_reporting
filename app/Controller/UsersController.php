<?php
App::import('Vendor', 'Ldap', array('file' => 'Ldap' . DS . 'Ldap.class.php'));

class UsersController extends AppController {
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
            'LoginRole',
            'User',
            'UserLoginRole',
            'UserMarket',
            'UserMailNotificationClient',
            'UserAdminAccess',
            'AdministrationLink'
        );

        public $name = 'Users';
        public $ldapConfig = null;

        public function beforeFilter() {

                $this->Auth->allow('login', 'logout');

                $this->Auth->loginAction = array(
                  'controller' => 'users',
                  'action' => 'login'
                );
                $this->Auth->logoutRedirect = array(
                  'controller' => 'users',
                  'action' => 'login'
                );
                $this->Auth->loginRedirect = array(
                  'controller' => 'reports',
                  'action' => 'client_report'
                );
                $this->Auth->authError = array(
                  'controller' => 'dashboard',
                  'action' => 'index'
                );

                $this->ldapConfig = Configure::read('IP.ldap_configuration');
        }

        public function beforeRender() {
                if($this->Auth->user()) {
                        $this->set('admNavLinks', parent::generateNav($this->arrNav, $this->Auth->user()));
                }
        }

        /*
         * function to validate user on login page.
         */
        public function login() {
                $domain     = $this->ldapConfig['domain'];
                $baseDN     = $this->ldapConfig['base_dn'];
                $ldapServer = $this->ldapConfig['ldap_server'];
                $ldapPort   = $this->ldapConfig['ldap_port'];

                $this->set('title_for_layout', 'Log In');

                if ($this->request->is('post')) {
                        $username = $this->request->data['User']['username'];
                        $password = $this->request->data['User']['password'];

                        $ldap = new CLdapLogin($ldapServer, $ldapPort, $domain, $username, $password, $baseDN);
			var_dump($ldap);die; 
                        if (true == $ldap->login()) {
                                $loggedUser = $this->User->find('first', array('conditions' => array('User.username' => $username, 'User.is_active' => 1)));
                                if($loggedUser) {
                                        $userLoginRole = $this->UserLoginRole->find('first', array('conditions' => array('UserLoginRole.user_id' => $loggedUser['User']['id'])));
                                        $userId = $loggedUser['User']['id'];
                                        $roleId = $userLoginRole['UserLoginRole']['role_id'];
                                        $displayName = $loggedUser['User']['display_name'];
                                        $this->request->data['User'] = array_merge(
                                            $this->request->data['User'],
                                            array('id' => $userId, 'role_id' => $roleId, 'role' => $userLoginRole['LoginRole']['name'], 'display_name' => $displayName)
                                        );
                                        unset($this->request->data['User']['password']);
                                        $this->Auth->login($this->request->data['User']);
                                        $this->Session->write('loggedUser.displayName', $displayName);
                                        $this->Session->write('loggedUser.role', $userLoginRole['LoginRole']['name']);
                                        return $this->redirect($this->Auth->redirect());
                                }
                        }
                        $this->set('complete', false);
                        $this->data = array();
                }
        }

        /*
         * function to log user out of the logged session
         */
        public function logout() {
                $this->Session->delete('loggedUser');
                $this->Session->destroy();
                return $this->redirect($this->Auth->logout());
        }

        /*
         * method for the user permissions module
         * shows all the users information
         */
        public function user_permissions() {

                $this->set('countries', json_encode($this->Country->find('list', array('fields' => array('Country.country', 'Country.country'), 'order' => 'Country.country Asc')), JSON_HEX_APOS));
                if($this->Auth->user('role') == 'Regional') {
                // if user is not global, fetch regions to which user have access
                        $userRegions = $this->UserMarket->find('list', array('fields' => array('UserMarket.market_id'), 'conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                }
                if($this->Auth->user('role') != 'Global') {
                // if user is not global, fetch only regions and markets to which user have access
                        $this->set('loginRoles', json_encode($this->LoginRole->find('list', array('conditions' => array('LoginRole.name NOT IN ("Global", "Viewer")'), 'order' => 'LoginRole.id Asc'))));
                        $this->set('regions', json_encode($this->Region->find('list', array('conditions' => array('Region.id in (' . implode(',', $userRegions) . ')'), 'order' => 'Region.region Asc'))));
                        $markets = $this->Market->find('all', array('conditions' => array('Market.region_id in (' . implode(',', $userRegions) . ')'), 'order' => 'Country.country Asc'));
                } else {
                        $this->set('loginRoles', json_encode($this->LoginRole->find('list', array('order' => 'LoginRole.id Asc'))));
                        $this->set('regions', json_encode($this->Region->find('list', array('order' => 'Region.region Asc'))));
                        $markets = $this->Market->find('all', array('order' => 'Country.country Asc'));
                }
                foreach ($markets as $market) {
                        $arrMarkets[$market['Market']['market']] = $market['Market']['market'];
                }
                $this->set('markets', json_encode($arrMarkets));
                $this->set('adminLinks', $this->AdministrationLink->find('list', array('order' => 'AdministrationLink.id Asc')));
                $this->set('userRole', $this->Auth->user('role'));
        }

        /*
         * function to fetch client names for the select box
         * of client specific mails on the add user popup
         */
        public function get_client_list() {
                $this->autoRender=false;

                $clients = $this->ClientRevenueByService->find('all', array('fields' => array('DISTINCT parent_company', 'client_name'), 'order' => 'client_name', 'group' => 'client_name'));
                $clientList = array();
                foreach($clients as $client) {
                        $clientList[] = array(
                            'display_name' => $client['ClientRevenueByService']['client_name'] . (!empty($client['ClientRevenueByService']['parent_company']) ? ' - ' . $client['ClientRevenueByService']['parent_company'] : ''),
                            'client_name' => $client['ClientRevenueByService']['client_name']
                        );
                }
                return json_encode($clientList);
        }

        /*
         * function to search a user name in active directory
         * on the create new user popup.
         */
        public function search_user() {

                $this->autoRender=false;

                $username 	= $this->ldapConfig['ldap_user'];
                $baseDN         = $this->ldapConfig['base_dn'];
                $ldapServer     = $this->ldapConfig['ldap_server'];
                $ldapPort       = $this->ldapConfig['ldap_port'];
                $domain         = $this->ldapConfig['domain'];
                $password 	= $this->ldapConfig['ldap_passwd'];

                $ldap = new CLdapLogin($ldapServer, $ldapPort, $domain, $username, $password, $baseDN);

                if($this->request->data['name_startsWith']) {
                        $nameStartsWith = $this->request->data['name_startsWith'];
                }
                if (false == $ldap->login()) {
                        echo '<div class="alert alert-danger">Failed to login with UserName :: <u>' . $ldap->getUserName(true) . '</u></div>';
                } else {
                        // This code is used to display the user name and group associated to that user.
                        $ldap->getAllUserInfo($nameStartsWith);
                }
        }

        /*
         * function the save new user information.
         */
        public function save_user() {
                $this->autoRender=false;

                $arrData = $this->request->data;

                $isActive = $arrData['activeflag'];
                $isDeleted = false;
                $userId = null;

                if(isset($arrData['username'])) {
                        // check if user already exists
                        $userExists = $this->User->find('first', array('conditions' => array('User.username' => $arrData['username'])));
                        if(isset($userExists['User']['id'])) {
                                // is user already exists and not marked as deleted
                                if($userExists['User']['is_deleted'] == 0) {
                                        $result = array();
                                        $result['success'] = false;
                                        $result['errors'] = 'User already exists...';
                                        return json_encode($result);
                                } else {
                                // if user is marked as deleted
                                        $userId = $userExists['User']['id'];
                                }
                        }
                }

                if($userId) {
                // if user exists and was marked as deleted, activate existing user record
                        $this->User->id = $userId;
                        $this->User->save(
                                array(
                                        'User' => array(
                                                'display_name' => $arrData['displayname'],
                                                'title' => $arrData['title'],
                                                'location' => $arrData['location'],
                                                'email_id' => $arrData['email'],
                                                'is_active' => $isActive,
                                                'daily_sync_mail' => $arrData['dailysyncmails'],
                                                'weekly_summary_mail' => $arrData['weeklysummarymails'],
                                                'client_specific_mail' => $arrData['clientpitchmails'],
                                                'is_deleted' => $isDeleted
                                        )
                                )
                        );
                } else {
                // if user does not exist, create new record
                        $this->User->create();
                        $this->User->save(
                                array(
                                        'User' => array(
                                                'display_name' => $arrData['displayname'],
                                                'username' => $arrData['username'],
                                                'title' => $arrData['title'],
                                                'location' => $arrData['location'],
                                                'email_id' => $arrData['email'],
                                                'is_active' => $isActive,
                                                'daily_sync_mail' => $arrData['dailysyncmails'],
                                                'weekly_summary_mail' => $arrData['weeklysummarymails'],
                                                'client_specific_mail' => $arrData['clientpitchmails'],
                                                'is_deleted' => $isDeleted
                                        )
                                )
                        );
                        $userId = $this->User->getLastInsertId();
                }

                if(isset($arrData['permission'])) {
                        $loginRole = $this->LoginRole->findByName($arrData['permission']);
                        $loginRoleId = $loginRole['LoginRole']['id'];
                        $this->UserLoginRole->create();
                        $this->UserLoginRole->save(
                                array(
                                        'UserLoginRole' => array(
                                            'user_id' => $userId,
                                            'role_id' => $loginRoleId,
                                            'active' => $isActive
                                        )
                                )
                        );

                        if($arrData['permission'] == 'Regional' && isset($arrData['nameofentity'])) {
                                $regions = $this->Region->find('all', array('conditions' => array('Region.region in (\'' . str_replace(",", "','", $arrData['nameofentity']) . '\')')));
                                foreach($regions as $region) {
                                        $this->UserMarket->create();
                                        $this->UserMarket->save(
                                                array(
                                                        'UserMarket' => array(
                                                            'user_id' => $userId,
                                                            'market_id' => $region['Region']['id'],
                                                            'active' => $isActive
                                                        )
                                                )
                                        );
                                }
                        }

                        if(($arrData['permission'] == 'Country' || $arrData['permission'] == 'Country - Viewer') && isset($arrData['nameofentity'])) {
                                $countries = $this->Market->find('all', array('conditions' => array('Market.market in (\'' . str_replace(",", "','", $arrData['nameofentity']) . '\')')));
                                foreach($countries as $country) {
                                        $this->UserMarket->create();
                                        $this->UserMarket->save(
                                                array(
                                                        'UserMarket' => array(
                                                            'user_id' => $userId,
                                                            'market_id' => $country['Market']['country_id'],
                                                            'active' => $isActive
                                                        )
                                                )
                                        );
                                }
                        }

                        if($arrData['permission'] == 'Global' && $arrData['clientpitchmails'] === true && $arrData['targetclients'] != '') {
                                $targetClients = explode(',', $arrData['targetclients']);
                                foreach($targetClients as $targetClient) {
                                        $this->UserMailNotificationClient->create();
                                        $this->UserMailNotificationClient->save(
                                                array(
                                                        'UserMailNotificationClient' => array(
                                                            'user_id' => $userId,
                                                            'client_name' => $targetClient
                                                        )
                                                )
                                        );
                                }
                        }

                        if($arrData['permission'] == 'Global' && isset($arrData['adminlinks'])) {
                                foreach($arrData['adminlinks'] as $adminLink) {
                                        $this->UserAdminAccess->create();
                                        $this->UserAdminAccess->save(
                                                array(
                                                        'UserAdminAccess' => array(
                                                            'user_id' => $userId,
                                                            'admin_link_id' => $adminLink
                                                        )
                                                )
                                        );
                                }
                        }
                }
                $result = array();
                $result['success'] = true;
                return json_encode($result);
        }

        /*
         * function to fetch users information into the
         * grid on user permissions page
         */
        public function get_users() {
                $this->autoRender=false;

                $userData = array();
                $i = 0;
                $conditions = array();
                $joins = array();
                isset($_GET['checked']) ? $_GET['checked'] : $_GET['checked']= 'false';
                if($_GET['checked'] == 'false'){
                        $conditions['User.is_active'] = 1;
                }
                // show only users which are not marked as deleted
                $conditions['User.is_deleted'] = 0;
                // if user role is regional then fetch users created in the assigned region only
                if($this->Auth->user('role') != 'Global') {
                        $userRegions = $this->UserMarket->find('list', array('fields' => array('market_id'), 'conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $userCountries = $this->Market->find('list', array('fields' => array('Market.country_id'), 'conditions' => array('Market.region_id IN (' . implode(',', $userRegions) . ')')));
                        $joins[] = array(
                            'table' => 'user_login_roles',
                            'alias' => 'UserLoginRole',
                            'type' => 'INNER',
                            'conditions' => array(
                                'UserLoginRole.user_id = User.id'
                            )
                        );
                        $joins[] = array(
                            'table' => 'login_roles',
                            'alias' => 'LoginRole',
                            'type' => 'INNER',
                            'conditions' => array(
                                'UserLoginRole.role_id = LoginRole.id'
                            )
                        );
                        $joins[] = array(
                            'table' => 'user_markets',
                            'alias' => 'UserMarket',
                            'type' => 'INNER',
                            'conditions' => array(
                                'UserMarket.user_id = User.id'
                            )
                        );
                        $conditions[] = array(
                            'OR' => array(
                                array(
                                    "LoginRole.name = 'Regional'",
                                    'UserMarket.market_id IN (' . implode(',', $userRegions) . ')'
                                ),
                                array(
                                    "LoginRole.name IN ('Country','Country - Viewer')",
                                    'UserMarket.market_id IN (' . implode(',', $userCountries) . ')'
                                )
                            )
                        );
                }
                $users = $this->User->find('all',array('order' => 'User.display_name Asc', 'joins' => $joins, 'conditions'=> $conditions));
                foreach($users as $user) {
                        $userData[$i]['targetclients'] = '';

                        $userData[$i]['userid'] = $user['User']['id'];
                        $userData[$i]['displayname'] = $user['User']['display_name'];
                        $userData[$i]['title'] = $user['User']['title'];
                        $userData[$i]['location'] = $user['User']['location'];
                        $userData[$i]['email'] = $user['User']['email_id'];

                        $userLoginRole = $this->UserLoginRole->find('first', array('conditions' => array('UserLoginRole.user_id' => $user['User']['id'])));
                        $userData[$i]['permission'] = $userLoginRole['LoginRole']['name'];

                        if($userLoginRole['LoginRole']['name'] == 'Regional') {
                                $arrRegions = array();
                                $userMarkets = $this->UserMarket->find('all', array('conditions' => array('UserMarket.user_id' => $user['User']['id'])));
                                foreach($userMarkets as $userMarket) {
                                        $region = $this->Region->find('first', array('conditions' => array('Region.id' => $userMarket['UserMarket']['market_id'])));
                                        $arrRegions[] = $region['Region']['region'];
                                }
                                $userData[$i]['nameofentity'] = implode(",", $arrRegions);
                        } elseif($userLoginRole['LoginRole']['name'] == 'Country' || $userLoginRole['LoginRole']['name'] == 'Country - Viewer') {
                                $arrCountries = array();
                                $userMarkets = $this->UserMarket->find('all', array('conditions' => array('UserMarket.user_id' => $user['User']['id'])));
                                foreach($userMarkets as $userMarket) {
                                        $country = $this->Market->find('first', array('conditions' => array('Market.country_id' => $userMarket['UserMarket']['market_id'])));
                                        $arrCountries[] = $country['Market']['market'];
                                }
                                $userData[$i]['nameofentity'] = implode(",", $arrCountries);
                        } elseif($userLoginRole['LoginRole']['name'] == 'Global') {
                                $userData[$i]['nameofentity'] = 'Global';

                                $targetClients = $this->UserMailNotificationClient->find('list', array('conditions' => array('user_id' => $user['User']['id'])));
                                $arrTargetClients = array();
                                foreach($targetClients as $targetClient) {
                                        $arrTargetClients[] = $targetClient;
                                }
                                $userData[$i]['targetclients'] = implode(',', $arrTargetClients);

                                $adminLinks = $this->UserAdminAccess->find('list', array('fields' => array('id', 'admin_link_id'), 'conditions' => array('user_id' => $user['User']['id'])));
                                $arrAdminLinks = array();
                                foreach($adminLinks as $adminLink) {
                                        $arrAdminLinks[] = $adminLink;
                                }
                                $userData[$i]['adminlinks'] = $arrAdminLinks;
                        } elseif($userLoginRole['LoginRole']['name'] == 'Viewer') {
                                $userData[$i]['nameofentity'] = '/';
                        }

                        $userData[$i]['active'] = $user['User']['is_active'];
                        $userData[$i]['dailysyncmail'] = $user['User']['daily_sync_mail'];
                        $userData[$i]['weeklysummarymail'] = $user['User']['weekly_summary_mail'];
                        $userData[$i]['clientpitchmail'] = $user['User']['client_specific_mail'];

                        $i++;
                }
                echo json_encode($userData);
        }

        /*
         * function to update existing user information
         */
        public function update_user() {
                $this->autoRender=false;

                $arrData = $this->request->data;

                $isActive = $arrData['activeflag'];
                if($isActive == null) {
                        $isActive = false;
                }

                if(isset($arrData['email'])) {
                        $userExists = $this->User->find('first', array('conditions' => array('User.email_id' => $arrData['email'])));
                        if(isset($userExists['User']['id']) && !empty($arrData['displayname'])) {
                                $this->User->id = $userExists['User']['id'];
                                $this->User->save(
                                        array(
                                                'User' => array(
                                                        'display_name' => $arrData['displayname'],
                                                        'title' => $arrData['title'],
                                                        'location' => $arrData['location'],
                                                        'is_active' => $isActive,
                                                        'daily_sync_mail' => $arrData['dailysyncmails'],
                                                        'weekly_summary_mail' => $arrData['weeklysummarymails'],
                                                        'client_specific_mail' => $arrData['clientpitchmails']
                                                )
                                        )
                                );
                        } else {
                                $result = array();
                                $result['success'] = false;
                                return json_encode($result);
                        }
                        $userId = $userExists['User']['id'];

                        if(!empty($arrData['permission'])) {
                                $this->UserLoginRole->deleteAll(array('user_id' => $userId));
                                $this->UserMarket->deleteAll(array('user_id' => $userId));
                                $this->UserMailNotificationClient->deleteAll(array('user_id' => $userId));
                                $this->UserAdminAccess->deleteAll(array('user_id' => $userId));

                                $loginRole = $this->LoginRole->findByName($arrData['permission']);
                                $loginRoleId = $loginRole['LoginRole']['id'];
                                $this->UserLoginRole->create();
                                $this->UserLoginRole->save(
                                        array(
                                                'UserLoginRole' => array(
                                                    'user_id' => $userId,
                                                    'role_id' => $loginRoleId,
                                                    'active' => $isActive
                                                )
                                        )
                                );

                                if($arrData['permission'] == 'Regional') {
                                        if(!empty($arrData['nameofentity'])) {
                                                $regions = $this->Region->find('all', array('conditions' => array('Region.region in (\'' . str_replace(",", "','", $arrData['nameofentity']) . '\')')));
                                                foreach($regions as $region) {
                                                        $this->UserMarket->create();
                                                        $this->UserMarket->save(
                                                                array(
                                                                        'UserMarket' => array(
                                                                            'user_id' => $userId,
                                                                            'market_id' => $region['Region']['id'],
                                                                            'active' => $isActive
                                                                        )
                                                                )
                                                        );
                                                }
                                        } else {
                                                $result = array();
                                                $result['success'] = false;
                                                return json_encode($result);
                                        }
                                }

                                if($arrData['permission'] == 'Country' || $arrData['permission'] == 'Country - Viewer') {
                                        if(!empty($arrData['nameofentity'])) {
                                                $countries = $this->Market->find('all', array('conditions' => array('Market.market in (\'' . str_replace(",", "','", $arrData['nameofentity']) . '\')')));
                                                foreach($countries as $country) {
                                                        $this->UserMarket->create();
                                                        $this->UserMarket->save(
                                                                array(
                                                                        'UserMarket' => array(
                                                                            'user_id' => $userId,
                                                                            'market_id' => $country['Market']['country_id'],
                                                                            'active' => $isActive
                                                                        )
                                                                )
                                                        );
                                                }
                                        } else {
                                                $result = array();
                                                $result['success'] = false;
                                                return json_encode($result);
                                        }
                                }

                                if($arrData['permission'] == 'Global' && $arrData['clientpitchmails'] === true && $arrData['targetclients'] != '') {
                                        $targetClients = explode(',', $arrData['targetclients']);
                                        foreach($targetClients as $targetClient) {
                                                $this->UserMailNotificationClient->create();
                                                $this->UserMailNotificationClient->save(
                                                        array(
                                                                'UserMailNotificationClient' => array(
                                                                    'user_id' => $userId,
                                                                    'client_name' => $targetClient
                                                                )
                                                        )
                                                );
                                        }
                                }

                                if($arrData['permission'] == 'Global' && isset($arrData['adminlinks'])) {
                                foreach($arrData['adminlinks'] as $adminLink) {
                                        $this->UserAdminAccess->create();
                                        $this->UserAdminAccess->save(
                                                array(
                                                        'UserAdminAccess' => array(
                                                            'user_id' => $userId,
                                                            'admin_link_id' => $adminLink
                                                        )
                                                )
                                        );
                                }
                        }
                        } else {
                                $result = array();
                                $result['success'] = false;
                                return json_encode($result);
                        }
                }
                $result = array();
                $result['success'] = true;
                return json_encode($result);
        }

        /*
         * function to export all users list data into excel
         */
        public function export_users_data() {
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
                        $objPHPExcel->getProperties()->setTitle("Users Data by date " . date('m/d/Y'));
                        $objPHPExcel->getProperties()->setSubject("Users Data by date " . date('m/d/Y'));

                        // Add some data
                        $objPHPExcel->setActiveSheetIndex(0);
                        $objPHPExcel->getActiveSheet()->getStyle("A1:G1")->applyFromArray(array("font" => array( "bold" => true, 'size'  => 12, 'name'  => 'Calibri'), 'alignment' => array('horizontal' => PHPExcel_Style_Alignment::HORIZONTAL_CENTER_CONTINUOUS, 'wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                        $objPHPExcel->getActiveSheet()->getStyle('A1:G1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getStartColor()->setRGB('CCC0DA');
                        $objPHPExcel->getActiveSheet()->getColumnDimension("A")->setWidth(34);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("B")->setWidth(34);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("C")->setWidth(25);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("D")->setWidth(43);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("E")->setWidth(16);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("F")->setWidth(25);
                        $objPHPExcel->getActiveSheet()->getColumnDimension("G")->setWidth(12);
                        $objPHPExcel->getActiveSheet()->SetCellValue('A1', 'Name');
                        $objPHPExcel->getActiveSheet()->SetCellValue('B1', 'Title');
                        $objPHPExcel->getActiveSheet()->SetCellValue('C1', 'Location');
                        $objPHPExcel->getActiveSheet()->SetCellValue('D1', 'Email');
                        $objPHPExcel->getActiveSheet()->SetCellValue('E1', 'Permissions');
                        $objPHPExcel->getActiveSheet()->SetCellValue('F1', 'Entity');
                        $objPHPExcel->getActiveSheet()->SetCellValue('G1', 'Active');

                        $i = 1;
                        $arrDataExcel = array();
                        foreach($arrData as $data) {
                                $arrDataExcel[] = array($data['displayname'], $data['title'], $data['location'], $data['email'],
                                    $data['permission'], $data['nameofentity'], ($data['active']) ? 'Yes' : 'No'
                                );
                                $i++;
                        }
                        if(!empty($arrDataExcel)) {
                                $objPHPExcel->getActiveSheet()->getStyle('A2:G'.$i)->applyFromArray(array('font' => array('size'  => 11, 'name'  => 'Calibri'), 'alignment' => array('wrap' => true), 'borders' => array('allborders' => array('style' => PHPExcel_Style_Border::BORDER_THIN))));
                                $objPHPExcel->getActiveSheet()->fromArray($arrDataExcel, null, 'A2');
                                $objPHPExcel->getActiveSheet()->setAutoFilter('A1:G'.$i);
                        }
                        // Rename sheet
                        $objPHPExcel->getActiveSheet()->setTitle('Users List');

                        // Save Excel 2007 file
                        $objWriter = new PHPExcel_Writer_Excel2007($objPHPExcel);
                        $objWriter->save('files/Users_Data_' . date('m-d-Y') . '.xlsx');
                }
                $result = array();
                $result['success'] = true;
                return json_encode($result);
        }

        /*
         *  function to mark existing user as deleted
         */
        public function delete_user() {
                $this->autoRender=false;

                $arrData = $this->request->data;

                $isActive = false;
                $isDeleted = true;

                if(isset($arrData['UserEmail'])) {
                        $userExists = $this->User->find('first', array('conditions' => array('User.email_id' => $arrData['UserEmail'])));
                        if(isset($userExists['User']['id'])) {
                                // mark user as deleted
                                $this->User->id = $userExists['User']['id'];
                                $this->User->save(
                                        array(
                                                'User' => array(
                                                        'is_active' => $isActive,
                                                        'is_deleted' => $isDeleted
                                                )
                                        )
                                );
                                // delete records from user associated tables
                                $this->UserLoginRole->deleteAll(array('user_id' => $userExists['User']['id']));
                                $this->UserMarket->deleteAll(array('user_id' => $userExists['User']['id']));
                                $this->UserMailNotificationClient->deleteAll(array('user_id' => $userExists['User']['id']));
                                $this->UserAdminAccess->deleteAll(array('user_id' => $userExists['User']['id']));
                        } else {
                                $result = array();
                                $result['error'] = 'User does not exist. Please try again.';
                                $result['success'] = false;
                                return json_encode($result);
                        }
                }
                $result = array();
                $result['success'] = true;
                return json_encode($result);
        }
}
