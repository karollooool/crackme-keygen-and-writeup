# Callfuscated

**HackTheBox Insane Challenge Writeup by KarolLoL**

https://app.hackthebox.com/challenges/Callfuscated

---

## First Look

When you load the binary in IDA you immediately notice something is off. There are no real call instructions anywhere. Instead, every single function call has been replaced with a push of an address followed by a ret. So instead of `call some_func` you get `push 0x401234; ret`. This is callfuscation, a technique that turns the call graph into a mess and makes static analysis really painful because IDA and Ghidra both struggle to follow the control flow properly.

The binary also uses a custom VM that interprets bytecode and runs a password check. You enter a 32 character password and the VM grinds through it and either says correct or wrong.

## Understanding the Structure

After spending time just getting IDA to cooperate and manually tracing the push/ret chains, the structure started to make sense. The VM reads a bytecode array from the stack, dispatches opcodes, and uses four core functions throughout the computation. I started calling them f3, f5, f7 and f8 based on their addresses.

The VM also seeds rand() with 1337 at startup. The self modifying part means that rand() output gets written into the bytecode at runtime, so you cannot just statically read all the constants off the bat.

Each group of 4 characters from the input gets accumulated into a 32 bit value and then transformed using two stored constants (I called them K1 and K2). The final result of all 8 groups gets compared to zero. If it is zero, you win.

## Identifying the Four Functions

This was the main challenge. The four functions are heavily obfuscated using pointless multiplications by arbitrary constants, xor noise, and dead calculations that get discarded. Just reading the decompiled output does not tell you what they actually compute.

I tried to manually translate the assembly into Python line by line for all four functions. That turned into a complete disaster. The transliterations produced wrong results for every test case I threw at them. The chain extraction approach I tried from the IDA database also produced the wrong answers. Both gave the same broken output, so the issue was in how I extracted the functions, not just the Python translation.

The approach that actually worked was GDB. I ran the binary inside a Docker container with Ubuntu 22.04 and wrote a GDB Python script that broke at the entry and exit of each function, logged the arguments and return values, and let the binary run with a known test input.

The test input I used was `ABCDEFGHIJKLMNOPQRSTUVWXYZ012345`. I knew what the last group of characters was ("2345" = 0x32333435 as a big endian 32 bit integer), so I could check what the functions did to known values.

From the GDB trace:

f5 got called with (0x3233, 256) and returned 0x323300. That is just 0x3233 times 256. So f5 is multiply.

f8 got called with (0x32333435, 0x6c6a524e) and returned 0x5e59667b. XOR of those two inputs gives exactly 0x5e59667b. So f8 is XOR.

f3 got called with (0x5e59667b, 0x33333333) and returned 0x2b263348. Subtract the second from the first and you get 0x2b263348. So f3 is subtract.

For f7 the trace showed the accumulator after processing the four characters "2345" was exactly 0x32333435, which is what you get if you just pack 0x32, 0x33, 0x34, 0x35 as a big endian 32 bit integer. Working backwards through the computation:

```
f7(0, 0x32) = 0x32
f7(0x32 * 256, 0x33) = 0x3233
f7(0x3233 * 256, 0x34) = 0x323334
f7(0x323334 * 256, 0x35) = 0x32333435
```

This only works if f7 is addition. So f7 is add.

So after all that obfuscation the four mystery functions are just add, subtract, multiply, and XOR. The whole point of the obfuscation was to hide four trivial operations.

## The Formula

Once I had the four operations the VM formula became clear. For each group of 4 characters:

1. Accumulate the characters into a big endian 32 bit integer using repeated multiply by 256 and add
2. XOR that value with K1[g]
3. Subtract K2[g]
4. Add the result to a running total R

At the end, if R equals zero the password is correct.

For R to be zero the cleanest solution is for each group contribution to be zero individually. That means for each group:

```
pack_bigendian(chars[g]) XOR K1[g] == K2[g]
```

Which means:

```
pack_bigendian(chars[g]) == K1[g] XOR K2[g]
```

So the correct 4 character group for each position is just K1[g] XOR K2[g] interpreted as bytes.

## Getting the Flag

I had the K1 and K2 constants from IDA (confirmed they were not modified by rand() at runtime, since the GDB trace showed K1[7] = 0x6c6a524e matching the static value).

```python
K1 = [0x0915033a, 0x427d7872, 0x30310a00, 0x2a052e32,
      0xcff5ecdf, 0x1914031e, 0xf6f7c6ad, 0x6c6a524e]

K2 = [0x41414141, 0x11111111, 0x55555555, 0x5a5a5a5a,
      0xaaaaaaaa, 0x77777777, 0x99999999, 0x33333333]

flag = b''
for g in range(8):
    v = K1[g] ^ K2[g]
    flag += bytes([(v >> 24) & 0xff, (v >> 16) & 0xff,
                   (v >> 8)  & 0xff,  v        & 0xff])

print(flag.decode())
```

Running that gives `HTB{Sliced_Up_the_Function_4_Ya}`.

Plugging it into the binary in Docker:

```
echo -n 'HTB{Sliced_Up_the_Function_4_Ya}' | ./crackme
Welcome to callfuscated crackme.
To register enter your password: Correct. Validate the challenge using the flag: HTB{Sliced_Up_the_Function_4_Ya}
```

## What Made This Hard

The callfuscation itself is annoying but manageable once you understand the pattern. The real time sink was the obfuscated arithmetic functions. The decompiler output for each of them is pages of multiplications by large constants, xors of intermediate values, and additions that partially cancel each other out. Manually reading that and figuring out it just computes a-b took a long time.

The Python transliteration approach I started with was a dead end. The assembly to Python conversion had bugs that were very hard to find because the obfuscated form obscures what the "correct" output should even look like. Switching to GDB and just measuring the actual function behavior with known inputs was the move that unlocked everything.

The flag itself is a reference to the challenge. "Sliced Up the Function" describes callfuscation pretty well. Every function got sliced up with push/ret pairs.
