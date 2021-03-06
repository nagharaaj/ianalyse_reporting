<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<?php echo $this->Html->charset(); ?>
	<title>
		<?php echo $title_for_layout; ?>
	</title>
	<?php
		echo $this->Html->meta('icon');

		//echo $this->Html->css('cake.generic');
                echo $this->Html->css('style');
                echo $this->Html->css('jqwidgets/styles/jqx.base');

                echo $this->Html->script('jquery-1.11.1.min.js');
                echo $this->Html->script('google-analytics');
                echo $this->Html->script('jstz.min.js');
                echo $this->Html->script('jqwidgets/jqxcore.js');
                echo $this->Html->script('jqwidgets/jqxmenu.js');
                echo $this->Html->script('jqwidgets/jqxdata.js');
                echo $this->Html->script('jqwidgets/jqxdata.export.js');
                echo $this->Html->script('jqwidgets/jqxdatatable.js');
                echo $this->Html->script('jqwidgets/jqxbuttons.js');
                echo $this->Html->script('jqwidgets/jqxscrollbar.js');
                echo $this->Html->script('jqwidgets/jqxmenu.js');
                echo $this->Html->script('jqwidgets/jqxcombobox.js');
                echo $this->Html->script('jqwidgets/jqxdropdownlist.js');
                echo $this->Html->script('jqwidgets/jqxcheckbox.js');
                echo $this->Html->script('jqwidgets/jqxlistbox.js');
                echo $this->Html->script('jqwidgets/jqxgrid.js');
                echo $this->Html->script('jqwidgets/jqxwindow.js');
                echo $this->Html->script('jqwidgets/jqxinput.js');
                echo $this->Html->script('jqwidgets/jqxnumberinput.js');
                echo $this->Html->script('jqwidgets/jqxcalendar.js');
                echo $this->Html->script('jqwidgets/jqxdatetimeinput.js');
                echo $this->Html->script('jqwidgets/jqxvalidator.js');
                echo $this->Html->script('jqwidgets/jqxpanel.js');
                echo $this->Html->script('jqwidgets/jqxeditor.js');
                echo $this->Html->script('jqwidgets/jqxgrid.edit.js');
                echo $this->Html->script('jqwidgets/jqxgrid.selection.js');
                echo $this->Html->script('jqwidgets/jqxgrid.filter.js');
                echo $this->Html->script('jqwidgets/jqxgrid.sort.js');
                echo $this->Html->script('jqwidgets/jqxgrid.pager.js');
                echo $this->Html->script('jqwidgets/jqxgrid.storage.js');
                echo $this->Html->script('jqwidgets/jqxgrid.columnsresize.js');
                echo $this->Html->script('jqwidgets/jqxgrid.export.js');
                echo $this->Html->script('common.js');
                echo $this->Html->script('jquery.mousewheel.min.js');
	?>
                <meta http-equiv="X-UA-Compatible" content="IE=edge" />
</head>
<body>
	<div id="container">
		<div id="header">
                        <div id="header-copy">
                                <h1>
                                        <?php echo $this->Html->link("Title", "/"); ?>
                                </h1>
                        <?php
                                if($this->Session->check('loggedUser.displayName')) {
                        ?>
                                <div id="lnk-logout">
                                        <span>Welcome, <?php echo $this->Session->read('loggedUser.displayName'); ?>&nbsp;(<a href="/users/logout">Logout</a>)</span>
                                <?php if($this->Session->check('loggedUser.role') == 'Global') {?>
                                        <div class="drop" style="display: none;">
                                            <ul>
                                <?php
                                if(isset($admNavLinks['userAdmLinks']) && !empty($admNavLinks['userAdmLinks'])) {
                                        foreach($admNavLinks['userAdmLinks'] as $linkName => $linkUrl) {
                                ?>
                                                    <li><a href="<?php echo $linkUrl;?>"><?php echo $linkName;?></a><hr/></li>
                                <?php
                                        }
                                }
                                ?>
                                            </ul>
                                        </div>
                                <?php }?>
                                </div>
                        <?php
                                }
                        ?>
                        </div>
		</div>
                <div id="nav-menu" align="center">
                        <?php
                                if(isset($admNavLinks['admNavLinks']))
                                {
                                        foreach($admNavLinks['admNavLinks'] as $navHead => $arrLinks)
                                        {
                                                if($navHead == 'CLIENT & NEW BUSINESS DATA') {
                                                        $className = 'grey';
                                                } else if ($navHead == 'OFFICE DATA') {
                                                        $className = 'orange';
                                                } else if ($navHead == 'PERMISSIONS') {
                                                        $className = 'blue';
                                                } else if ($navHead == 'HELP') {
                                                        $className = 'red';
                                                } else if ($navHead == 'GLOBAL STRATEGY') {
                                                        $className = 'light-grey';
                                                } else if ($navHead == 'DASHBOARD') {
                                                        $className = 'light-torquoise';
                                                } else {
                                                        $className = 'green';
                                                }
                                ?>
                        <div id="<?php echo str_replace("/", "-", $arrLinks); ?>" class="<?php echo $className; ?>">
                                <?php
                                                echo $this->Html->link
                                                (
                                                        $navHead,
                                                        $arrLinks
                                                );
                                ?>
                        </div>
                                <?php
                                        }
                                }
                        ?>
                </div>
<script type="text/javascript">
        $(document).ready(function() {
                $('#nav-menu div#-<?php echo $this->params['controller'].'-'.$this->params['action']; ?>').addClass('selected');
                
                $('#lnk-logout').hover(function(){
                        $('.drop').show();
                },function(){
                        $('.drop').hide();
                });
        });
        
        var loggedUser = "<?php echo $this->Session->read('loggedUser.displayName');?>"
        var timer;
        var wait=20;
        document.onkeypress=resetTimer;
        document.onmousemove=resetTimer;
        function resetTimer()
        {
            if(loggedUser) {
                    clearTimeout(timer);
                    timer=setTimeout("logout()", 60000*wait);
            }
        }

        function logout()
        {
            window.location.href='/users/logout';
        }

        $.fn.serializeObject = function() {
           var o = {};
           var a = this.serializeArray();
           $.each(a, function() {
               if (o[this.name]) {
                   if (!o[this.name].push) {
                       o[this.name] = [o[this.name]];
                   }
                   o[this.name].push(this.value || '');
               } else {
                   o[this.name] = this.value || '';
               }
           });
           return o;
        };
</script>
                <br/>
                <div id="content">

			<?php echo $this->Session->flash(); ?>

			<?php echo $content_for_layout; ?>

		</div>
		<div id="footer"></div>
	</div>
	<?php echo $this->element('sql_dump'); ?>
</body>
</html>
