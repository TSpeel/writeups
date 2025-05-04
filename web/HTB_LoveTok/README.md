# HackTheBox LoveTok
When booting up the challenge, we find the following homepage:
![LoveTok](/web/HTB_LoveTok/images/lovetok.PNG)
This page features a countdown to a random date, and a button to roll a new random date. Clicking the button sets a new date with a GET request with the parameter `format=r`. This is our first hint that we can somehow influence a `date()` command. In this challenge we are also provided the source code. There is not much interesting code, except the `TimeModel` class which uses `eval()` to execute `date()` based on the provided `format` parameter:
```
<?php
class TimeModel
{
    public function __construct($format)
    {
        $this->format = addslashes($format);

        [ $d, $h, $m, $s ] = [ rand(1, 6), rand(1, 23), rand(1, 59), rand(1, 69) ];
        $this->prediction = "+${d} day +${h} hour +${m} minute +${s} second";
    }

    public function getTime()
    {
        eval('$time = date("' . $this->format . '", strtotime("' . $this->prediction . '"));');
        return isset($time) ? $time : 'Something went terribly wrong';
    }
}
```
This kind of code with `eval()` screams command injection. I started off by trying some common command injection techniques, but this did not immediately work. Taking a second look at the code explains why; `addslashes()` is used to escape the input string. We can take a look at the [addslashes() docs](https://www.php.net/manual/en/function.addslashes.php), which reveals this is an escaping function. However, it also reveals that it is not safe for preventing i.e. SQL injection. 

At this point, it is clear that the goal of the challenge is to bypass the `addslashes()` and achieve command injection. Googling for "php addslashes exploit" results in some pages on SQL injection, and a page about [addslashes() in eval safety](https://security.stackexchange.com/questions/263114/php-is-addslashes-in-eval-really-that-unsafe). This post also links to an article titled "[Using complex variables to bypass the addlashes function to achieve RCE](https://www.programmersought.com/article/30723400042/)". These posts explain that the characters $, {, }, ( and ) are not escaped, which allows injecting of inline commands. This means you can still use commands inside of the string context with a payload such as:
```
${phpinfo()}
```
However, the problem still persists when we want to execute commands such as (the `+` is a space as this is passed as GET parameter in the URL):
```
${system("ls+../")}
```
The above payload will not work, as the double quotes are still escaped by `addslashes()`. Some commands such as `id` can still be executed by leaving out the quotes, but commands containing spaces do not work without the double quotes. Luckily, the first post we found about [addslashes() in eval safety](https://security.stackexchange.com/questions/263114/php-is-addslashes-in-eval-really-that-unsafe) also highlights a way to bypass this issue. As payload we can use `${eval($_GET[1])}`, which will fetch the command from the GET parameter `1`. This can be used to execute commands as follows:
```
/?format=${eval($_GET[1])}&1=system("id");
```
This now successfully prints the result of `id` on the page!
![LoveTokExp](/web/HTB_LoveTok/images/lovetokexploited.PNG)
The payload can be cleaned up further, as the nesting of `eval()` and `system()` is not needed: 
```
/?format=${system($_GET[1])}&1=id
```
This can now be used to fetch the flag from the randomly generated flag name as follows:
```
/?format=${system($_GET[1])}&1=cat+/flag*
```

