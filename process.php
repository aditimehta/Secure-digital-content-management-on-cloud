<?php
if(isset($_POST['field1']) && isset($_POST['field2'])) {
	echo $_POST['field1'];
    $data = $_POST['field1'] . ',' . $_POST['field2'] . "\n";
    $ret = file_put_contents('mylocation.txt', $data, FILE_APPEND | LOCK_EX);
    if($ret === false) {
        die('There was an error writing this file');
    }
    else {
        echo " Your location coordinates is received";
    }
}
else {
   die('no post data to process');
}