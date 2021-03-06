<?php

class DashboardController extends AppController {
	public $helpers = array('Html', 'Form');

        public $components = array('RequestHandler');

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
                $this->Auth->authError = array(
                  'controller' => 'users',
                  'action' => 'login'
                );
        }

        public $uses = array(
            'Market',
            'Region',
            'ClientRevenueByService',
            'User',
            'UserLoginRole',
            'UserMarket',
            'OverviewAnnouncement',
            'OverviewSection',
            'OverviewSectionBrand',
            'OverviewNotification'
        );

        public function beforeRender() {
                if($this->Auth->user()) {
                        $this->set('admNavLinks', parent::generateNav($this->arrNav, $this->Auth->user()));
                }
        }

        /*
         * Global Strategy action
         */
        public function index() {
                $this->set('loggedUser', $this->Auth->user());
                $this->set('loggedUserRole', $this->Auth->user('role'));

                $this->set('announcement_details', $this->OverviewAnnouncement->find('first'));
                $this->OverviewSection->Behaviors->attach('Containable');
                $this->set('section_details', $this->OverviewSection->find('all'));
                $markets = $this->Market->find('list', array('fields' => array('Market.country_id', 'Market.market'), 'order' => 'Market.market Asc'));
                $this->set('markets', json_encode($markets));
        }

        public function global_growth() {
                $this->set('loggedUser', $this->Auth->user());
                if($this->Auth->user('role') == 'Regional') {
                        $userRegions = $this->UserMarket->find('list', array('fields' => array('UserMarket.id', 'UserMarket.market_id'), 'conditions' => array('UserMarket.user_id' => $this->Auth->user('id'))));
                        $regions = $this->Region->find('list', array('conditions' => array('Region.id in (' . implode(',', $userRegions) . ')'), 'order' => 'Region.region Asc'));
                        $this->set('userRegions', $regions);
                }
        }

        public function local_growth() {

        }

        /*
         * action to save announcement details on Global Strategy
         */
        public function save_announcements() {
                $this->autoRender=false;

                $arrData = $this->request->data;

                if(isset($arrData['announcement'])) {
                        $this->OverviewAnnouncement->query('DELETE FROM `overview_announcements` WHERE 1');
                        $this->OverviewAnnouncement->create();
                        $this->OverviewAnnouncement->save(
                                array(
                                        'OverviewAnnouncement' => array(
                                                'announcement_details' => $arrData['announcement']
                                        )
                                )
                        );
                } else {
                        $result = array();
                        $result['success'] = false;
                        $result['errors'] = 'Missing announcement data...';
                        return json_encode($result);
                }
                $result = array();
                $result['success'] = true;
                return json_encode($result);
        }

        /*
         * function to save section and brands details on Global Strategy
         */
        public function save_section_data() {
                $this->autoRender=false;

                $arrData = $this->request->data;

                if(isset($arrData)) {
                        $brandCnt = count($arrData['brandData']);
                        if(isset($arrData['sectionId']) && $arrData['sectionId'] != null) {
                                $this->OverviewSection->id = $arrData['sectionId'];
                                $this->OverviewSection->save(
                                        array(
                                                'OverviewSection' => array(
                                                        'section_title' => strtoupper($arrData['sectionTitle']),
                                                        'section_no' => $arrData['sectionNo'],
                                                        'brand_cnt' => $brandCnt
                                                )
                                        )
                                );
                                $sectionId = $arrData['sectionId'];
                        } else {
                                $this->OverviewSection->create();
                                $this->OverviewSection->save(
                                        array(
                                                'OverviewSection' => array(
                                                        'section_title' => strtoupper($arrData['sectionTitle']),
                                                        'section_no' => $arrData['sectionNo'],
                                                        'brand_cnt' => $brandCnt
                                                )
                                        )
                                );
                                $sectionId = $this->OverviewSection->getLastInsertId();
                        }

                        $brands = $arrData['brandData'];
                        $arrBrands = array();
                        foreach($brands as $brand) {
                                if($brand['clientName'] != "CLIENT NAME") {
                                        if(isset($brand['brandId']) && $brand['brandId'] != null) {
                                                $existingMarkets = $this->OverviewSectionBrand->find('first', array('fields' => array('brand_markets', 'brand_services'), 'conditions' => array('OverviewSectionBrand.id' => $brand['brandId'])));

                                                $this->OverviewSectionBrand->id = $brand['brandId'];
                                                $this->OverviewSectionBrand->save(
                                                        array(
                                                                'OverviewSectionBrand' => array(
                                                                        'section_id' => $sectionId,
                                                                        'brand_name' => strtoupper($brand['clientName']),
                                                                        'brand_services' => strtoupper($brand['services']),
                                                                        'brand_markets' => strtoupper($brand['markets']),
                                                                        'brand_synopsis' => $brand['synopsis'],
                                                                        'brand_no' => $brand['brandNo']
                                                                )
                                                        )
                                                );
                                                $arrBrands[$brand['brandNo']] = $brand['brandId'];
                                        } else {
                                                $this->OverviewSectionBrand->create();
                                                $this->OverviewSectionBrand->save(
                                                        array(
                                                                'OverviewSectionBrand' => array(
                                                                        'section_id' => $sectionId,
                                                                        'brand_name' => strtoupper($brand['clientName']),
                                                                        'brand_services' => strtoupper($brand['services']),
                                                                        'brand_markets' => strtoupper($brand['markets']),
                                                                        'brand_synopsis' => $brand['synopsis'],
                                                                        'brand_no' => $brand['brandNo']
                                                                )
                                                        )
                                                );
                                                $arrBrands[$brand['brandNo']] = $this->OverviewSectionBrand->getLastInsertId();
                                        }
                                        if(isset($brand['markets']) && $brand['markets'] != 'MARKETS') {
                                                $notifyMarkets = explode(', ', $brand['markets']);
                                                foreach($notifyMarkets as $notifyMarket) {
                                                        $notificationExists = $this->OverviewNotification->find('first',
                                                                array('conditions' => array(
                                                                    'market' => $notifyMarket,
                                                                    'section' => $arrData['sectionTitle'],
                                                                    'brand' => $brand['clientName'],
                                                                    'services' => (!empty($existingMarkets)) ? $existingMarkets['OverviewSectionBrand']['brand_services']  : $brand['services']
                                                                ))
                                                        );
                                                        if(empty($notificationExists)) {
                                                                $this->OverviewNotification->create();
                                                                $this->OverviewNotification->save(
                                                                        array(
                                                                            'OverviewNotification' => array(
                                                                                'market' => $notifyMarket,
                                                                                'section' => $arrData['sectionTitle'],
                                                                                'brand' => $brand['clientName'],
                                                                                'services' => $brand['services'],
                                                                                'user_id' => $this->Auth->user('id'),
                                                                                'created' => date('Y-m-d H:i:s')
                                                                            )
                                                                        )
                                                                );
                                                        } else {
                                                                $this->OverviewNotification->id = $notificationExists['OverviewNotification']['id'];
                                                                $this->OverviewNotification->save(
                                                                        array(
                                                                            'OverviewNotification' => array(
                                                                                'market' => $notifyMarket,
                                                                                'section' => $arrData['sectionTitle'],
                                                                                'brand' => $brand['clientName'],
                                                                                'services' => $brand['services'],
                                                                                'user_id' => $this->Auth->user('id'),
                                                                                'created' => date('Y-m-d H:i:s')
                                                                            )
                                                                        )
                                                                );
                                                        }
                                                }
                                        }
                                }
                        }
                }
                $result = array();
                $result['success'] = true;
                $result['sectionId'] = $sectionId;
                $result['brandIds'] = $arrBrands;
                return json_encode($result);
        }

        /*
         * function to save logo images of brands on Global Strategy
         */
        public function brand_logo_upload() {
                $this->autoRender=false;

                $sectionId = $_GET['sectionId'];
                $brandId = $_GET['brandId'];

                $data = array();
                if(isset($_FILES[0]["type"]))
                {
                        $validextensions = array("jpeg", "jpg", "png");
                        $temporary = explode(".", $_FILES[0]["name"]);
                        $file_extension = end($temporary);
                        if ((($_FILES[0]["type"] == "image/png") || ($_FILES[0]["type"] == "image/jpg") || ($_FILES[0]["type"] == "image/jpeg")
                        ) && ($_FILES[0]["size"] < 1048576)//Approx. 1MB files can be uploaded.
                        && in_array($file_extension, $validextensions)) {
                                if ($_FILES[0]["error"] > 0) {
                                        $data["error"] = $_FILES[0]["error"];
                                } else {
                                        if (file_exists("files/overview_page/" . $_FILES[0]["name"])) {
                                                unlink("files/overview_page/" . $_FILES[0]["name"]);
                                                //echo $_FILES[0]["name"] . " <span id='invalid'><b>already exists.</b></span> ";
                                        }
                                        $sourcePath = $_FILES[0]['tmp_name']; // Storing source path of the file in a variable
                                        $targetPath = 'files/overview_page/' . 'Logo_' . $sectionId . '_' . $brandId . '.' . $file_extension; // Target path where file is to be stored
                                        move_uploaded_file($sourcePath,$targetPath) ; // Moving Uploaded file
                                        $this->OverviewSectionBrand->id = $brandId;
                                        $this->OverviewSectionBrand->save(
                                                array('OverviewSectionBrand' => array(
                                                        'brand_logo' => '/' . $targetPath
                                                ))
                                        );
                                        $data["success"] = 'image uploaded successfully!!!';
                                        $data["filepath"] = '/' . $targetPath;
                                }
                        } else {
                                $data["error"] = "***Invalid file Size (Max 1MB) or Type (jpeg, jpg, png)***";
                        }
                }
                return json_encode($data);
        }

        /*
         * function to remove a brand under section on Global Strategy
         */
        public function remove_brand() {
                $this->autoRender=false;
                $data = array();

                $arrData = $this->request->data;
                if($arrData) {
                        $this->OverviewSectionBrand->delete($arrData['brandId']);

                        $brandCnt = 1;
                        $arrBrands = array();
                        $brands = $this->OverviewSectionBrand->find("all", array('conditions' => array('OverviewSectionBrand.section_id' => $arrData['sectionId'])));
                        foreach($brands as $brand) {
                                $this->OverviewSectionBrand->id = $brand['OverviewSectionBrand']['id'];
                                $this->OverviewSectionBrand->save(
                                        array(
                                                'OverviewSectionBrand' => array(
                                                        'brand_no' => $brandCnt
                                                )
                                        )
                                );
                                $arrBrands[$brand['OverviewSectionBrand']['id']] = $brandCnt;
                                $brandCnt++;
                        }

                        $this->OverviewSection->id = $arrData['sectionId'];
                        $this->OverviewSection->save(
                                array(
                                        'OverviewSection' => array(
                                                'brand_cnt' => ($brandCnt-1)
                                        )
                                )
                        );

                        $data["success"] = true;
                        $data['brandCnts'] = $arrBrands;
                }
                return json_encode($data);
        }

        /*
         * function to remove entire section on Global Strategy
         */
        public function remove_section() {
                $this->autoRender=false;
                $data = array();

                $arrData = $this->request->data;
                if($arrData) {
                        $this->OverviewSectionBrand->deleteAll(array('section_id' => $arrData['sectionId']));

                        $this->OverviewSection->delete($arrData['sectionId']);

                        $data["success"] = true;
                }
                return json_encode($data);
        }
}
