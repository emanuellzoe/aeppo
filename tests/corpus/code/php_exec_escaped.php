<?php
exec('echo hi ' . escapeshellarg($name), $output);
passthru($command);
