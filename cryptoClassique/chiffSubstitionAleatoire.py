import random
import string

def substitution_aleatoire(texte):
    alphabet = string.ascii_lowercase
    substitution = list(alphabet)
    random.shuffle(substitution)
    table = str.maketrans(alphabet, ''.join(substitution))
    texte_chiffre = texte.lower().translate(table)
    return texte_chiffre, substitution

# === Utilisation ===
texte = input("Entrez un texte à chiffrer (Substitution aléatoire) : ")
texte_chiffre, cle_utilisee = substitution_aleatoire(texte)

print("Texte chiffré :", texte_chiffre)
print("Clé utilisée :", ''.join(cle_utilisee))
