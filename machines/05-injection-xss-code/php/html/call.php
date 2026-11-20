<?php
// WSTG-INJT-11: second code-injection sink - the callable itself is user input.
$fn  = $_REQUEST['fn']  ?? 'strtoupper';
$arg = $_REQUEST['arg'] ?? '';
echo "<html><body><h1>Callback runner</h1><pre>";
echo htmlspecialchars((string)call_user_func($fn, $arg));
echo "</pre></body></html>";