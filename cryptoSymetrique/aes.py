from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)  # Clé AES-128
cipher = AES.new(key, AES.MODE_ECB)

message = input("Message à chiffrer (AES) : ")
ciphertext = cipher.encrypt(pad(message.encode(), 16))
print("Message chiffré (hex) :", ciphertext.hex())

# Déchiffrement
decipher = AES.new(key, AES.MODE_ECB)
decrypted = unpad(decipher.decrypt(ciphertext), 16).decode()
print("Message déchiffré :", decrypted)
