<?php
// WSTG-INJT-11.1: local AND remote file inclusion.
// allow_url_include=On (zz-lab.ini) and no path validation at all.
$page = $_REQUEST['page'] ?? 'home.php';
echo "<html><body><h1>Page viewer</h1><div id='content'>";
include($page);
echo "</div></body></html>";