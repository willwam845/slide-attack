sbox = [13, 5, 8, 3, 1, 9, 12, 11, 6, 14, 15, 10, 2, 7, 4, 0]
inv_sbox = [sbox.index(i) for i in range(16)]

rounds = 100
KEYS = [70, 8]

def sub(block, sbox):
    return (sbox[block >> 4] << 4) + sbox[block & 0xf]

def encrypt_dr(block):
    for i in range(2):
        block ^= KEYS[i % len(KEYS)]
        block = sub(block, sbox)
    return block

def encrypt(block):
    for i in range(rounds):
        block ^= KEYS[i % len(KEYS)]
        block = sub(block, sbox)
    return block

import random
pts = [0, 81]
cts = [encrypt(x) for x in pts]
print(pts)
print(cts)

def check_keys(k0, k1):
    keys = [k0, k1]
    for i in range(min(10, len(pts))):
        p = pts[i]
        for r in range(rounds):
            p ^= keys[r & 1]
            p = sub(p, sbox)
        if p != cts[i]:
            return False
    print("sice?", k0, k1)

def recover_keys(pt1, pt2):
    keys = []
    for k0 in range(256):
        p = pt1 ^ k0
        p = sub(p, sbox)
        pp = sub(pt2, inv_sbox)
        k1 = p ^ pp
        keys.append((k0, k1))
    return keys

def check_slide(pt1, ct1, pt2, ct2):
    blah = False
    recovered_keys = recover_keys(pt1, pt2)
    for k0, k1 in recovered_keys:
        c = sub(ct1 ^ k0, sbox)
        c = sub(c ^ k1, sbox)
        if c == ct2:
            check_keys(k0, k1)
            
for i in range(len(pts)):
    pt1 = pts[i]
    ct1 = cts[i]
    for j in range(len(cts)):
        pt2 = pts[j]
        ct2 = cts[j]
        if i != j:
            check_slide(pt1, ct1, pt2, ct2)

print(encrypt_dr(0))