<?php
// WSTG-INJT-12: command injection, PHP flavour.
$host = $_REQUEST['host'] ?? '127.0.0.1';
echo "<html><body><h1>Ping utility</h1><pre>";
echo shell_exec("ping -c 1 -W 1 " . $host);
echo "</pre></body></html>";