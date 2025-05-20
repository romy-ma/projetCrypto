import hashlib

# Demander un message à l'utilisateur
message = input("👉 Entrez le message à hacher : ").encode()

# Afficher les choix disponibles
print("\nChoisissez l'algorithme de hachage :")
print("1 - MD5")
print("2 - SHA-1")
print("3 - SHA-256")

# Lire le choix de l'utilisateur
choix = input("Votre choix (1/2/3) : ")

# Appliquer le bon algorithme
if choix == "1":
    hash_result = hashlib.md5(message).hexdigest()
    algo = "MD5"
elif choix == "2":
    hash_result = hashlib.sha1(message).hexdigest()
    algo = "SHA-1"
elif choix == "3":
    hash_result = hashlib.sha256(message).hexdigest()
    algo = "SHA-256"
else:
    print("❌ Choix invalide.")
    exit()

# Afficher le résultat
print(f"\n🔐 Hachage avec {algo} :")
print(hash_result)
