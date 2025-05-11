# VUCTF2025 Time
This challenge contains a binary file and the IP of a remote service running the binary. First, let's disassemble the binary to figure out the challenge. The binary's main function can be seen below:
```
004013ce    int32_t main(int32_t argc, char** argv, char** envp)

004013dc        void* fsbase
004013dc        int64_t rax = *(fsbase + 0x28)
004013f1        char* rax_2 = malloc(bytes: 0x20)
004013fc        load_flag(rax_2)
00401406        char* rax_3 = malloc(bytes: 9)
00401414        generate_hex(rax_2, rax_3)
00401420        puts(str: "Your guess: ")
0040142c        fflush(fp: __TMC_END__)
00401445        char buf[0x9]
00401445        fgets(&buf, n: 9, fp: stdin)
00401459        buf[strcspn(&buf, U"\n")] = 0
00401459        
0040146a        if (strlen(&buf) != 8)
004014af            __printf_chk(flag: 2, 
004014af                format: "You can't even set the right lenght!")
004014b9            exit(status: 1)
004014b9            noreturn
004014b9        
0040146c        int32_t rbp = 7
00401471        int32_t i = 0
00401471        
00401479        while (i s<= 8)
0040148a            if (buf[sx.q(rbp)] != rax_3[sx.q(i)])
004014c5                puts(str: "Wrong! You can't beat me. Goodbye!")
004014cf                exit(status: 1)
004014cf                noreturn
004014cf            
00401491            usleep(useconds: 0x3d090)
00401496            i += 1
00401499            rbp -= 1
00401499        
004014e8        __printf_chk(flag: 2, format: "Congrats! You guessed (or shall we say timed?) Roomba\'s password right", 
004014e8            rax_2)
004014f0        free(mem: rax_2)
004014f8        free(mem: rax_3)
00401502        *(fsbase + 0x28)
00401502        
0040150b        if (rax == *(fsbase + 0x28))
0040151c            return 0
0040151c        
0040151d        __stack_chk_fail()
0040151d        noreturn
```
It is a bit tricky to read, but the binary generates an 8 character hex string password based on the flag. If the password is provided correctly, it prints the file.
Now the question of course is, how can we figure out the password?

The binary evaluates the password one character at a time, starting at the final character. If the character is correct, it sleeps for 0.25 seconds before continuing. We can use this to brute-force the password one character at a time.
To do this, I wrote the following Python script using pwntools, based on the Radboud's Institute of Pwning [template](https://radboudinstituteof.pwning.nl/posts/how2pwn/):
```
chars = b'0123456789abcdef'

char_array = b""
for i in range(0,8):
    print("\nTesting position ", 8-i)
    max_delay = 0
    found_char = b""
    for char in chars:
        io = start()
        print("Testing char ", chr(char))
        payload = b"x" * (7-i)  + chr(char).encode() + char_array
        print("Payload: ", payload)
        io.sendlineafter(b"Your guess: \n", payload)


        start_time = time.time()
        response = io.recvall(timeout=2)
        elapsed = time.time() - start_time
        print(f"Response time: {elapsed:.2f} seconds\n")
        if elapsed > max_delay:
            max_delay = elapsed
            found_char = chr(char).encode()
        io.close()
    print("Character identified: ",found_char)
    char_array = (found_char) + char_array

print("Found password: ", char_array)

print("Getting flag:")
io = start()
io.sendlineafter(b"Your guess: \n", char_array)
print(io.recvall().decode())
```
The full script can be found here

