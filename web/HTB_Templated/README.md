# Templated
The name of the challenge hints that this is a server side template injection (SSTI) challenge.

## Reconnaisance
The site's home page looks to be a static web page stating the website is still under construction. It reveals that the site is built using Flask and Jinja2. Let's make a mental note of Jinja2, as this is the template engine we will most likely be exploiting.

![Homepage](/web/HTB_Templated/images/homepage.PNG)

As we are looking for SSTI, we will need some kind of user input that is injected into a template, but the homepage does not show anything that processes user input. I thus assumed there were other pages that did accept user input. Another possibility would be that the site accepts some kind of GET parameters, but this is less common. I started a scan with dirbuster, which immediately revealed something strange. All inputs generated with dirbuster resulted in HTTP 200 status code responses. When I looked at a random one, it shows that they were actually error 404 pages, but returned as valid web pages which is a bit strange. Below is an example:

![404](/web/HTB_Templated/images/404.PNG)

Admittedly, it took me a while to realise that the page we are trying to access is printed in the error page. Let's investigate if this is is done using Jinja2. Jinja2 uses `{{...}}` template notation. Below is the response for `http://<ip>:<port>/{{7*7}}`:

![7times7](/web/HTB_Templated/images/7times7.PNG)

Great! We've confirmed Jinja2 SSTI works. Now I went looking for a payload to turn this into RCE. I found the following payload on this ![article](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756) (this executes `ls`):

```
{{self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read()}}
```
This prints the following files:

![ls](/web/HTB_Templated/images/ls.PNG)

This reveals a file `flag.txt`. We can read it out with the following request (remember this has to be URL encoded and appended to `http://<ip>:port/`):

```
{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read()}}
```
