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
The challenge contains the following pwnme function:
```

```




I used the
[pwn template](
https://radboudinstituteof.pwning.nl/posts/how2pwn/) from the Radboud CTF team.
