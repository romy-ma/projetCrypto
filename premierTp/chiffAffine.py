def pgcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def chiffrement_affine(texte, a, b):
    if pgcd(a, 26) != 1:
        raise ValueError("a doit être premier avec 26")
    resultat = ""
    for char in texte:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            x = ord(char) - base
            code = (a * x + b) % 26 + base
            resultat += chr(code)
        else:
            resultat += char
    return resultat

# === Utilisation ===
texte = input("Entrez un texte à chiffrer (Affine) : ")
a = int(input("Entrez la valeur de a (premier avec 26) : "))
b = int(input("Entrez la valeur de b : "))
try:
    resultat = chiffrement_affine(texte, a, b)
    print("Texte chiffré :", resultat)
except ValueError as e:
    print("Erreur :", e)
