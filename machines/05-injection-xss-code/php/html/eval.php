<?php
// WSTG-INJT-11: PHP code injection. User input is handed straight to eval().
// (PHP 8 removed preg_replace /e, create_function() and string assert(), so
// eval() and call_user_func() in call.php are the live code-execution sinks.)
$expr = $_REQUEST['expr'] ?? '';
echo "<html><body><h1>Expression evaluator</h1><pre>";
if ($expr !== '') {
    $ret = eval($expr);
    if ($ret !== null && $ret !== false) {
        echo htmlspecialchars((string)$ret);
    }
}
echo "</pre></body></html>";