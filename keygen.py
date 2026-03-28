import struct
import sys
import os


PAYLOAD_SIZE = 0x69600
DECRYPT_KEY = 0x64FA4D94
PASSWORD_NEEDLE = b"S4CaqeCret20MCM6"


def find_payload(pe_data):
    e_lfanew = struct.unpack_from('<I', pe_data, 0x3C)[0]
    nsections = struct.unpack_from('<H', pe_data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from('<H', pe_data, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + opt_size
    target_rva = 0x2C7000

    for i in range(nsections):
        s = pe_data[sec_off + i * 40: sec_off + (i + 1) * 40]
        rva = struct.unpack_from('<I', s, 12)[0]
        rawsz = struct.unpack_from('<I', s, 16)[0]
        rawptr = struct.unpack_from('<I', s, 20)[0]
        if rva <= target_rva < rva + rawsz:
            return rawptr + (target_rva - rva)
    return -1


def msvc_srand_sequence(seed, count):
    state = seed & 0xFFFFFFFF
    results = [0] * count
    for i in range(count - 1, 0, -1):
        state = (state * 214013 + 2531011) & 0xFFFFFFFF
        results[i] = ((state >> 16) & 0x7FFF) % (i + 1)
    return results


def decrypt(payload, key):
    buf = bytearray(payload)
    n = len(buf)
    lo = key & 0xFF

    for i in range(n):
        buf[i] = (buf[i] - (i ^ 0xAB)) & 0xFF
        buf[i] ^= (lo + i * 0x37) & 0xFF

    perm = msvc_srand_sequence(key, n)
    for i in range(1, n):
        j = perm[i]
        buf[i], buf[j] = buf[j], buf[i]

    kb = [key & 0xFF, (key >> 8) & 0xFF, (key >> 16) & 0xFF, (key >> 24) & 0xFF]
    for i in range(n):
        buf[i] ^= kb[i & 3]

    return buf


def extract_password(pe_bytes):
    pos = pe_bytes.find(PASSWORD_NEEDLE)
    if pos < 0:
        return None
    end = pe_bytes.index(b'\x00', pos)
    return pe_bytes[pos:end].decode('ascii')


def main():
    print()
    print("  Keygen for CrackMe by CrackNotMe")
    print("  Reversed by KarolLoL")
    print("  " + "-" * 34)
    print()

    path = sys.argv[1] if len(sys.argv) > 1 else "CrackMe_packed.exe"
    if not os.path.exists(path):
        print(f"  [!] {path} not found")
        return 1

    with open(path, 'rb') as f:
        raw = f.read()

    off = find_payload(raw)
    if off < 0 or off + PAYLOAD_SIZE > len(raw):
        print("  [!] payload not found in binary")
        return 1

    print(f"  [*] payload @ {hex(off)}")
    child = decrypt(bytearray(raw[off:off + PAYLOAD_SIZE]), DECRYPT_KEY)

    if child[0] != 0x4D or child[1] != 0x5A:
        print("  [!] decryption failed")
        return 1

    pw = extract_password(child)
    if not pw:
        print("  [!] could not find password in child PE")
        return 1

    print(f"  [+] decrypted child PE ok")
    print()
    print(f"  Password: {pw}")
    print()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
