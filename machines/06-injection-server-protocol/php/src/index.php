<?php
// WSTG-INJT-23: PHP unserialize() with a POP chain. Intentionally vulnerable.

class Report {
    public $title;
    function __wakeup() { echo "REPORT: " . $this->title; }
}

class Reader {
    public $path;
    function __toString() { return file_get_contents($this->path); }
}

class Executor {
    public $cmd;
    function __destruct() { echo shell_exec($this->cmd); }
}

class Logger {
    public $file;
    public $data;
    function __destruct() { if ($this->file) { file_put_contents($this->file, $this->data); } }
}

echo "<pre>";
$data = $_GET['data'] ?? '';
if ($data !== '') {
    $obj = unserialize(base64_decode($data));   // VULNERABLE: no allowed_classes restriction
    if (is_object($obj)) { echo "\n[loaded " . get_class($obj) . "]"; }
} else {
    echo "usage: /?data=base64(serialize(...))\n";
    echo "classes: Report(title) -> Reader(path) __toString ; Executor(cmd) __destruct ; Logger(file,data)";
}
echo "</pre>";