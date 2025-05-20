from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Génération des clés RSA
key = RSA.generate(2048)
public_key = key.publickey()
cipher = PKCS1_OAEP.new(public_key)
decipher = PKCS1_OAEP.new(key)

# Input utilisateur
message = input("Entrez un message à chiffrer (RSA) : ")
message_bytes = message.encode()

# Chiffrement
encrypted = cipher.encrypt(message_bytes)
print("Message chiffré (base64):", base64.b64encode(encrypted).decode())

# Déchiffrement
decrypted = decipher.decrypt(encrypted)
print("Message déchiffré :", decrypted.decode())
