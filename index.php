<?php 

require_once('classes/mWaf.php');

$mwaf = new mWaf();
$mwaf->startProtection();

echo("test");