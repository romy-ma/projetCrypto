def KSA(key):
    key = [ord(c) for c in key]
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S):
    i = j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        yield S[(S[i] + S[j]) % 256]

def rc4_encrypt(key, plaintext):
    S = KSA(key)
    keystream = PRGA(S)
    return bytes([c ^ next(keystream) for c in plaintext])

# Utilisation
key = input("Clé RC4 : ")
message = input("Message à chiffrer : ")
cipher = rc4_encrypt(key, message.encode())

print("Message chiffré (hex) :", cipher.hex())
# Déchiffrement (même fonction)
decrypted = rc4_encrypt(key, cipher).decode()
print("Message déchiffré :", decrypted)
