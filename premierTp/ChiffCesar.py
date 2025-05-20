def cesar_chiffre(texte, decalage):
    resultat = ""
    for char in texte:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            resultat += chr((ord(char) - base + decalage) % 26 + base)
        else:
            resultat += char
    return resultat

# === Utilisation ===
texte = input("Entrez un texte à chiffrer (César) : ")
decalage = int(input("Entrez le décalage : "))
resultat = cesar_chiffre(texte, decalage)
print("Texte chiffré :", resultat)
