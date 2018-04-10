<?php
/**
 * Application level Controller
 *
 * This file is application-wide controller file. You can put all
 * application-wide controller-related methods here.
 *
 * PHP 5
 *
 * CakePHP(tm) : Rapid Development Framework (http://cakephp.org)
 * Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 * @link          http://cakephp.org CakePHP(tm) Project
 * @package       app.Controller
 * @since         CakePHP(tm) v 0.2.9
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

App::uses('Controller', 'Controller');

/**
 * Application Controller
 *
 * Add your application-wide methods in the class below, your controllers
 * will inherit them.
 *
 * @package       app.Controller
 * @link http://book.cakephp.org/2.0/en/controllers.html#the-app-controller
 */
class AppController extends Controller {

    public $components = array(
        'Acl',
        'Auth' => array(
            'authorize' => array(
                'Actions' => array('actionPath' => 'controllers')
            )
        ),
        'Session'
    );

    public $arrNav = array(
       // 'GLOBAL STRATEGY' => '/dashboard/index',
        //'DASHBOARD' => '/dashboard/global_growth',
        'CURRENT CLIENT DATA' => '/reports/current_client_report',
        'NEW BUSINESS DATA' => '/reports/client_report',
        'OFFICE DATA' => '/reports/office_report',
        'PERMISSIONS' => '/users/user_permissions',
        'HELP' => '/help/index'
    );

    function beforeFilter() {
        $this->Auth->allow();
    }
    
    public function generateNav($arrNav, $user) {
        $arrAuthNav = array();

        foreach($arrNav as $linkName => $linkUrl) {
            $arrLink = explode('/', $linkUrl);
            if($this->Acl->check($user, 'controllers'.$linkUrl)) {
                $arrAuthNav[$linkName] = $linkUrl;
            }
        }
        $userAdmLinks = $this->getUserAdminAccess($user['id']);

        return array('admNavLinks' => $arrAuthNav, 'userAdmLinks' => $userAdmLinks);
    }

    public function parseRequestVars() {
        $requestVars = array();

        if (isset($this->params['pass']) && !empty($this->params['pass'])) {
            for ($i = 0; $i < count($this->params['pass']); $i = $i+2 ) {
                $requestVars[$this->params['pass'][$i]] = $this->params['pass'][$i+1];
            }
        }

        return $requestVars;
    }

    public $uses = array(
        'User',
        'LoginRole',
        'UserLoginRole',
        'UserAdminAccess'
    );

    public function getUserRoles($userId) {
        $userLoginRoles = $this->UserLoginRole->find('all', array('conditions' => array('user_id' => $userId)));
        $userRoles = array();
        foreach($userLoginRoles as $userLoginRole) {
            $userRoles[$userLoginRole['LoginRole']['id']] = $userLoginRole['LoginRole']['name'];
        }
        return $userRoles;
    }
    
    public function getUserAdminAccess($userId) {
        $this->UserAdminAccess->Behaviors->attach('Containable');
        $userAdminAccesses = $this->UserAdminAccess->find('all', array('conditions' => array('user_id' => $userId)));
        $arrUserAdminAccess = array();
        foreach($userAdminAccesses as $userAdminAccess) {
            $arrUserAdminAccess[$userAdminAccess['AdministrationLink']['link_name']] = $userAdminAccess['AdministrationLink']['link_url'];
        }
        return $arrUserAdminAccess;
    }
}
