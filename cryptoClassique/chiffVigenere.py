def vigenere_chiffre(texte, cle):
    texte = texte.lower()
    cle = cle.lower()
    resultat = ""
    j = 0
    for i in range(len(texte)):
        if texte[i].isalpha():
            decalage = ord(cle[j % len(cle)]) - ord('a')
            code = (ord(texte[i]) - ord('a') + decalage) % 26 + ord('a')
            resultat += chr(code)
            j += 1
        else:
            resultat += texte[i]
    return resultat

# === Utilisation ===
texte = input("Entrez un texte à chiffrer (Vigenère) : ")
cle = input("Entrez la clé (ex : 'cle') : ")
texte_chiffre = vigenere_chiffre(texte, cle)

print("Texte chiffré :", texte_chiffre)
