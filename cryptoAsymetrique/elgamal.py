from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto import Random
from Crypto.Util.Padding import pad, unpad


from Crypto.Util.number import GCD
from Crypto.Random.random import getrandbits, randint

from Crypto.PublicKey import ElGamal
from Crypto.Random import random

from Crypto.Util import number

def elgamal_keygen(bits=256):
    p = number.getPrime(bits, randfunc=Random.get_random_bytes)
    g = randint(2, p-1)
    x = randint(2, p-2)  # clé privée
    y = pow(g, x, p)     # clé publique
    return (p, g, y), x

def elgamal_encrypt(pub_key, plaintext):
    p, g, y = pub_key
    k = randint(1, p-2)
    a = pow(g, k, p)
    b = [(ord(char) * pow(y, k, p)) % p for char in plaintext]
    return a, b

def elgamal_decrypt(priv_key, p, a, b):
    s = pow(a, priv_key, p)
    s_inv = pow(s, -1, p)
    decrypted = ''.join([chr((char * s_inv) % p) for char in b])
    return decrypted

# Input utilisateur
msg = input("Entrez un message à chiffrer (ElGamal) : ")
public_key, private_key = elgamal_keygen()
a, b = elgamal_encrypt(public_key, msg)
print("Message chiffré :", (a, b))

decrypted = elgamal_decrypt(private_key, public_key[0], a, b)
print("Message déchiffré :", decrypted)
