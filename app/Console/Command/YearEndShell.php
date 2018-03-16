<?php
App::uses('CakeEmail', 'Network/Email');

class YearEndShell extends AppShell {
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
            'PitchStage',
            'ClientRevenueByService',
            'ClientDeleteLog',
            'ClientActualRevenueByYear',
            'User'
        );

        public function main() {
                $this->autoRender = false;
                set_time_limit(0);
                ini_set('memory_limit', '-1');

                App::import('Component','Auth');
                $this->Auth = new AuthComponent(new ComponentCollection());
                $adminUser = $this->User->find('first', array('conditions' => array('title' => 'System Admin')));
                if(!empty($adminUser)) {
                    $this->Auth->login($adminUser['User']);
                }

                $currDt = date('Y-m-d');
                $lastYrStartDt = (date('Y')-1) . '-01-01';
                $lastYrEndDt = (date('Y')-1) . '-12-31';
                $currYr = date('Y');
                $prevYr = (date('Y')-1);
                $pastYr = (date('Y')-2);

                //script to update pitches with Won/Lost to Current-Client/Lost-Archive
                $pitchesWonLost = $this->ClientRevenueByService->find('all',
                        array('conditions' => array(
                                'OR' => array('ClientRevenueByService.pitch_date BETWEEN ? AND ?' => array($lastYrStartDt, $lastYrEndDt),
                                    'OR' => array('ClientRevenueByService.created BETWEEN ? AND ?' => array($lastYrStartDt, $lastYrEndDt),
                                        'ClientRevenueByService.created' => null)),
                                'AND' => array('ClientRevenueByService.pitch_stage' => array('Won - new business', 'Won - retained', 'Lost - current client', 'Lost - new business'))
                            ),
                            'order' => 'ClientRevenueByService.id'
                        )
                );
                //echo '<pre>'; print_r($pitchesWonLost);
                foreach($pitchesWonLost as $result) {
                        if(preg_match('/Lost/', $result['ClientRevenueByService']['pitch_stage'])) {
                                if($result['ClientRevenueByService']['lost_date'] <= $lastYrEndDt || $result['ClientRevenueByService']['lost_date'] == '0000-00-00') {
                                        $this->ClientRevenueByService->id = $result['ClientRevenueByService']['id'];
                                        $this->ClientRevenueByService->save(
                                                array('ClientRevenueByService' => array(
                                                    'pitch_stage' => 'Lost - archive'
                                                ))
                                        );
                                }
                        } else {
                                if($result['ClientRevenueByService']['client_since_year'] != $currYr) {
                                        $this->ClientRevenueByService->id = $result['ClientRevenueByService']['id'];
                                        $this->ClientRevenueByService->save(
                                                array('ClientRevenueByService' => array(
                                                    'pitch_stage' => 'Current client'
                                                ))
                                        );
                                }
                        }
                }

                //script to delete pitches with Cancelled/Declined status
                $pitchesCancelDecline = $this->ClientRevenueByService->find('all',
                        array('conditions' => array(
                                'OR' => array('ClientRevenueByService.pitch_date BETWEEN ? AND ?' => array($lastYrStartDt, $lastYrEndDt),
                                    'OR' => array('ClientRevenueByService.created BETWEEN ? AND ?' => array($lastYrStartDt, $lastYrEndDt),
                                        'ClientRevenueByService.created' => null)),
                                'AND' => array('ClientRevenueByService.pitch_stage' => array('Cancelled', 'Declined'))
                            ),
                            'order' => 'ClientRevenueByService.id'
                        )
                );
                //echo '<pre>'; print_r($pitchesCancelDecline);
                foreach($pitchesCancelDecline as $result) {
                        if ($this->ClientRevenueByService->delete($result['ClientRevenueByService']['id'])) {
                                $this->ClientDeleteLog->create();
                                $this->ClientDeleteLog->save(
                                        array(
                                                'ClientDeleteLog' => array(
                                                        'record_id' => $result['ClientRevenueByService']['id'],
                                                        'pitch_date' => $result['ClientRevenueByService']['pitch_date'],
                                                        'pitch_stage' => $result['ClientRevenueByService']['pitch_stage'],
                                                        'lost_date' => $result['ClientRevenueByService']['lost_date'],
                                                        'parent_id' => $result['ClientRevenueByService']['parent_id'],
                                                        'client_name' => $result['ClientRevenueByService']['client_name'],
                                                        'parent_company' => $result['ClientRevenueByService']['parent_company'],
                                                        'comments' => $result['ClientRevenueByService']['comments'] . "\ndeleted during year-end processing.",
                                                        'category_id' => $result['ClientRevenueByService']['category_id'],
                                                        'client_since_month' => $result['ClientRevenueByService']['client_since_month'],
                                                        'client_since_year' => $result['ClientRevenueByService']['client_since_year'],
                                                        'agency_id' => $result['ClientRevenueByService']['agency_id'],
                                                        'region_id' => $result['ClientRevenueByService']['region_id'],
                                                        'managing_entity' => $result['ClientRevenueByService']['managing_entity'],
                                                        'country_id' => $result['ClientRevenueByService']['country_id'],
                                                        'city_id' => $result['ClientRevenueByService']['city_id'],
                                                        'active_markets' => $result['ClientRevenueByService']['active_markets'],
                                                        'service_id' => $result['ClientRevenueByService']['service_id'],
                                                        'division_id' => $result['ClientRevenueByService']['division_id'],
                                                        'currency_id' => $result['ClientRevenueByService']['currency_id'],
                                                        'estimated_revenue' => $result['ClientRevenueByService']['estimated_revenue'],
                                                        'actual_revenue' => $result['ClientRevenueByService']['actual_revenue'],
                                                        'year' => $result['ClientRevenueByService']['year'],
                                                        'created' => ($result['ClientRevenueByService']['created'] != '') ? $result['ClientRevenueByService']['created'] : 'NULL',
                                                        'modified' => ($result['ClientRevenueByService']['modified'] != '') ? $result['ClientRevenueByService']['modified'] : 'NULL',
                                                        'deleted_by' => $this->Auth->user('id'),
                                                        'deleted' => date('Y-m-d H:i:s')
                                                )
                                        )
                                );
                        }
                }

                //script to update actual revenue and estimated revenue for pitches with status as Current-client
                $pitchesCurrentClient = $this->ClientRevenueByService->find('all',
                        array('conditions' => array(
                                'OR' => array('ClientRevenueByService.pitch_date BETWEEN ? AND ?' => array($lastYrStartDt, $lastYrEndDt),
                                    'OR' => array('ClientRevenueByService.created BETWEEN ? AND ?' => array($lastYrStartDt, $lastYrEndDt),
                                        'ClientRevenueByService.created' => null)),
                                'AND' => array('ClientRevenueByService.pitch_stage' => array('Current client', 'Lost - archive'))
                            ),
                            'order' => 'ClientRevenueByService.id'
                        )
                );
                //echo '<pre>'; print_r($pitchesCurrentClient);
                foreach($pitchesCurrentClient as $result) {
                        if($result['ClientRevenueByService']['actual_revenue'] != 0 && $result['ClientRevenueByService']['actual_revenue'] != null) {
                                $this->ClientActualRevenueByYear->create();
                                $this->ClientActualRevenueByYear->save(
                                        array('ClientActualRevenueByYear' => array(
                                            'client_service_id' => $result['ClientRevenueByService']['id'],
                                            'fin_year' => $pastYr,
                                            'actual_revenue' => $result['ClientRevenueByService']['actual_revenue']
                                        ))
                                );
                        }

                        $this->ClientRevenueByService->id = $result['ClientRevenueByService']['id'];
                        $this->ClientRevenueByService->save(
                                array('ClientRevenueByService' => array(
                                    'estimated_revenue' => 0,
                                    'actual_revenue' => $result['ClientRevenueByService']['estimated_revenue']
                                ))
                        );
                }
        }
}
