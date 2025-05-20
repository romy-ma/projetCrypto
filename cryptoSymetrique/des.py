from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key = get_random_bytes(8)  # Clé DES (8 octets)
cipher = DES.new(key, DES.MODE_ECB)

message = input("Message à chiffrer (DES) : ")
ciphertext = cipher.encrypt(pad(message.encode(), 8))
print("Message chiffré (hex) :", ciphertext.hex())

# Déchiffrement
decipher = DES.new(key, DES.MODE_ECB)
decrypted = unpad(decipher.decrypt(ciphertext), 8).decode()
print("Message déchiffré :", decrypted)
