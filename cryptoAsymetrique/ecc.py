from ecdsa import SigningKey, SECP256k1

# Génération de clé privée/clé publique ECC
private_key = SigningKey.generate(curve=SECP256k1)
public_key = private_key.verifying_key

# Input utilisateur
message = input("Entrez un message à signer (ECC) : ")
message_bytes = message.encode()

# Signature
signature = private_key.sign(message_bytes)
print("Signature :", signature.hex())

# Vérification
try:
    valid = public_key.verify(signature, message_bytes)
    print("Signature valide :", valid)
except:
    print("Signature invalide.")
