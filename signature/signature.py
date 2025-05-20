from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Étape 1 : Lire un message depuis l'utilisateur
message_str = input("👉 Entrez le message à signer : ")
message = message_str.encode()

# Étape 2 : Générer les clés RSA
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

# Étape 3 : Calculer le haché SHA-256 du message
hash_msg = SHA256.new(message)

# Étape 4 : Signer le message avec la clé privée
signature = pkcs1_15.new(private_key).sign(hash_msg)
print("\n✍️ Signature générée (hexadécimal) :")
print(signature.hex())

# Étape 5 : Vérifier la signature avec la clé publique
print("\n🕵️ Vérification de la signature...")
try:
    pkcs1_15.new(public_key).verify(hash_msg, signature)
    print("✅ Signature VALIDE.")
except (ValueError, TypeError):
    print("❌ Signature INVALIDE.")
