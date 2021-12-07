# PasswordGenerator

## Requirements   
* PHP version - php7.4  
* PHPUnit version - 7.5  
  
## Usage  

```php
require_once __DIR__ . '/autoload.php';

use core\PasswordGenerator;

$passGen = new PasswordGenerator();  
$passGen->generate();  
echo $passGen->getPassword();  
```