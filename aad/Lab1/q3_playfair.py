def keymat(k):
    k = k.upper().replace('J', 'I')
    seen = set(); seq = []
    for ch in (k + "ABCDEFGHIKLMNOPQRSTUVWXYZ"):
        if ch.isalpha() and ch not in seen:
            seen.add(ch); seq.append(ch)
    return [seq[i:i+5] for i in range(0, 25, 5)]

def pairs(s, prep=True):
    s = ''.join(ch for ch in s.upper() if ch.isalpha())
    if prep:
        s = s.replace('J', 'I')
        p = []; i = 0
        while i < len(s):
            a = s[i]; b = s[i+1] if i+1 < len(s) else 'X'
            if a == b:
                p.append(a + 'X'); i += 1
            else:
                p.append(a + b); i += 2
        return p
    return [s[i:i+2] for i in range(0, len(s), 2)]

def playfair(text, key, enc=True):
    m = keymat(key)
    pos = {m[r][c]: (r, c) for r in range(5) for c in range(5)}
    out = []
    for a, b in pairs(text, prep=enc):
        r1, c1 = pos[a]; r2, c2 = pos[b]
        if r1 == r2:
            out.append(m[r1][(c1 + (1 if enc else -1)) % 5] +
                       m[r2][(c2 + (1 if enc else -1)) % 5])
        elif c1 == c2:
            out.append(m[(r1 + (1 if enc else -1)) % 5][c1] +
                       m[(r2 + (1 if enc else -1)) % 5][c2])
        else:
            out.append(m[r1][c2] + m[r2][c1])
    return ''.join(out)

enc = lambda pt, k: playfair(pt, k, True)
dec = lambda ct, k: playfair(ct, k, False)

if __name__ == '__main__':
    pt = input("Plaintext: ")
    k  = input("Key: ")
    ct = enc(pt, k); print("Ciphertext:", ct)
    print("Decrypted:", dec(ct, k))