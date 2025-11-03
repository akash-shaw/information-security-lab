from string import ascii_uppercase as A

def idx(c): return A.index(c)
def infer_shift(ct, pt):
    return (idx(ct[0]) - idx(pt[0].upper())) % 26

def decrypt(ct, shift):
    return ''.join(A[(idx(c) - shift) % 26] if c.isalpha() else c for c in ct)

known_ct = "CIW"
known_pt = "yes"
cipher = "XVIEWYWI"

shift = infer_shift(known_ct, known_pt)
print(decrypt(cipher, shift))