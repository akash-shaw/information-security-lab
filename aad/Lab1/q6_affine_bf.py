def main():
    # Affine cipher: E(x) = (ax + b) mod 26
    # Given: "ab" -> "GL"
    # a=0, b=1 -> G=6, L=11

    ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

    for a in range(1, 26):
        if gcd(a, 26) != 1:
            continue
        a_inv = mod_inverse(a, 26)
        if a_inv is None:
            continue

        for b in range(26):
            # check constraint: "ab" -> "GL" (a*0+b=6, a*1+b=11 mod 26)
            if (b % 26 == 6) and ((a + b) % 26 == 11):
                decrypted = []
                for ch in ciphertext:
                    if ch.isalpha():
                        y = ord(ch.upper()) - ord('A')
                        x = (a_inv * (y - b)) % 26
                        decrypted.append(chr(x + ord('A')))
                    else:
                        decrypted.append(ch)

                print(f"Key found: a={a}, b={b}")
                print(f"Ciphertext: {ciphertext}")
                print(f"Decrypted: {''.join(decrypted)}")
                return

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

if __name__ == '__main__':
    main()
