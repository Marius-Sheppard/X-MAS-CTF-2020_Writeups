# PHP MASTER  
:star: I don't know if this is the only solution or the simplest one but I tried to explain it the best I could so that beginners like me would easily understand. 

### As we check the X-MAS CTF Web Exploitation section we find the following challenge:  
![Given Challenge](https://github.com/Marius-Sheppard/X-MAS-CTF-2020_Writeups/blob/main/PHP%20Master/xmasctftask.png)  
### When navigating to the specified url we find the following code:
```php
 <?php
include('flag.php'); // The statement includes and evaluates the specified file

$p1 = $_GET['param1']; // This is the first parameter that the program can take
$p2 = $_GET['param2']; // This is the second parameter that it can take

if(!isset($p1) || !isset($p2)) // This checks if ANY of the two parameters are missing
{highlight_file(__FILE__); // Here it shows this file with the source code 
die(); // Here it exists and terminates the program with a normal exit code of 0
}

if(strpos($p1, 'e') === false && strpos($p2, 'e') === false  && strlen($p1) === strlen($p2) && $p1 !== $p2 && $p1[0] != '0' && $p1 == $p2) 
//If this statement is true, it will exit showing us the flag. I will break it down below.
{die($flag);}
?>

```  
  
 If we want to get the flag all the conditions below must be true:
```php
strpos($p1, 'e') === false // strpos returns the position of the character in the string if found, so the character 'e' must not be present in the first parameter
strpos($p2, 'e') === false  // The character 'e' must not be present in the second parameter
strlen($p1) === strlen($p2) // The length of our parameters must be the same
$p1 !== $p2 // The first parameter is not identical with the second one (true if $p1 is not equal to $p2, or they are not of the same type !!)
$p1[0] != '0' // The first character of the first parameter must not be 0
$p1 == $p2 // Our parameters must be equal
```

To pass parameters to the given URL we append it like this:
```
challs.xmas.htsp.ro:3000/?param1=value&param2=value
```
To respect the conditions, some possible values can be: 
```
param1=1E2&param2=100  (1E2= 10^2 = 100; they have the same length:3 characters, and are equal but not identical)
param1=+1&param2=01    (+1 == 1)
param1=.10&param2=0.1  (0.10 == 0.1)
```

Sending a request to the server with any of those value pairs will fetch us the flag: **X-MAS{s0_php_m4ny_skillz-69acb43810ed4c42}**
