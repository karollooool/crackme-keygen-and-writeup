# CrackNotMe's MCM 6.0 - Project Mayhem — Writeup

**Author:** KarolLoL  
**Key:** `S4CaqeCret20MCM6`
---

## Overview

The binary is a custom-packed Windows x64 executable. The `start` function is a 2MB control-flow-flattened dispatcher that handles anti-debugging, payload decryption, and reflective PE loading. The actual crackme logic lives inside an encrypted PE embedded in the `.rdata` section.

## Stage 1 — Outer Binary

Entry point at `0x140007C70`. First thing it does is read the first byte from each of the 8 fake sections (`.vmp0`, `.vmp1`, `.themida`, `.enigma1`, `UPX0`, `.aspack`, `.obs0`, `.vbox`) and sums them. These section names are trolling decoys — no commercial protector is used.

It then initializes a key value `0x64FA4D94` and runs several checks:

- **Anti-debug (code scanning):** `sub_1401EFBA0` scans process memory for x86 byte patterns with wildcard masks, looking for debugger breakpoints or patches
- **Timing check:** Calls `GetTickCount`, sleeps 50ms, calls `GetTickCount` again. If delta < 30ms or > 5000ms, the key gets XOR'd with `0xBAADFACE` / `0xFACEBADD`
- **Computer name check:** Calls `GetComputerNameA`, if it fails, XOR with `0xDEADFACE`

If any check triggers, the key gets corrupted and decryption produces garbage.

## Stage 2 — Payload Decryption

The packed payload sits at `0x1402C7000` (431,616 bytes). The decryption runs in three stages:

### 2.1 — Byte Transform

```
for i in range(SIZE):
    buf[i] = (buf[i] - (i ^ 0xAB)) & 0xFF
    buf[i] ^= (0x94 + i * 0x37) & 0xFF
```

Per-byte subtraction and XOR using index-derived values. `0x94` is the low byte of the key.

### 2.2 — Fisher-Yates Shuffle

Seeded with the key `0x64FA4D94` using MSVC's `rand()` implementation:

```
seed = seed * 214013 + 2531011
return (seed >> 16) & 0x7FFF
```

Generates a permutation array (indices from N-1 down to 1), then applies the shuffle forward (1 to N-1).

### 2.3 — 4-Byte XOR

The key is split into LE bytes (`94 4D FA 64`) and XOR'd cyclically across the entire payload:

```
buf[i] ^= key_bytes[i % 4]
```

Result: a valid PE (MZ header, clean sections, C++ runtime strings).

## Stage 3 — HMAC Integrity Check

After decryption, HMAC-SHA256 is computed over the decrypted payload using a 32-byte hardcoded key. The result is compared against a 32-byte expected hash using constant-time XOR accumulation. If it doesn't match, the binary calls `ExitProcess(2)`.

## Stage 4 — Reflective PE Loading

`sub_1401F02B0` maps the decrypted PE into memory:
- Checks MZ/PE signature
- Allocates memory via `VirtualAlloc`
- Copies sections
- Processes relocations
- Resolves imports
- Calls the entry point

## Stage 5 — Child PE

The decrypted PE is a full C++ application with:
- `ReadConsoleW` / `WriteConsoleW` for I/O
- Anti-debug taunts (`"MCM v5.0 | :) debugger detected :)"`, `"Your breakpoints are cute"`, `"Nice try, reverser"`)
- A fake success flag: `"[+] SUCCESS BUT NOT! Flag: MCM6{%08X}"`
- PEB-walking to find `NTDLL.DLL` by FNV-1a hash
- `.smc` section (self-modifying code)

### Password Validation

At `0x14002BDF0` in the child PE, the user's input is compared against four hardcoded strings using `std::string::compare`:

1. `S4CaqeCret20MCM6` ← **this is the valid password**
2. `LalkaZalupka` — decoy
3. `0xCC010558193FUNC1337` — decoy
4. `MCM56_8571795378165931561` — decoy

Only `S4CaqeCret20MCM6` actually passes all subsequent checks. The others trigger different code paths that eventually fail.

There's also `PwEedPasswordOtsosiPenis` referenced in a separate anti-tampering function.

## Keygen

See `keygen.py` — reads the packed binary, decrypts the 3-stage payload, extracts the password from the child PE.

**The crackme:** https://crackmes.one/crackme/69a95101fbfe0ef21de94652
