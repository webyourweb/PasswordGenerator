# PasswordGenerator

* PHP version - php7.4  
* PHPUnit version - 7.5  
  
Create your password, to simple use:
```php
require 'autoload.php';

use core\PasswordGenerator;

$passGen = new PasswordGenerator();  
$passGen->generate();  
echo $passGen->getPassword();  
```