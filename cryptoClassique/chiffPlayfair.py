def prepare_texte(texte):
    texte = texte.upper().replace("J", "I")
    texte = ''.join(filter(str.isalpha, texte))
    i = 0
    res = ""
    while i < len(texte):
        a = texte[i]
        b = ''
        if i + 1 < len(texte):
            b = texte[i + 1]
        if a == b:
            res += a + 'X'
            i += 1
        else:
            if b:
                res += a + b
                i += 2
            else:
                res += a + 'X'
                i += 1
    return res

def generate_grille(cle):
    cle = cle.upper().replace("J", "I")
    seen = set()
    grille = ""
    for c in cle + string.ascii_uppercase:
        if c.isalpha() and c not in seen and c != 'J':
            grille += c
            seen.add(c)
    return [list(grille[i:i+5]) for i in range(0, 25, 5)]

def find_position(grille, lettre):
    for i in range(5):
        for j in range(5):
            if grille[i][j] == lettre:
                return i, j
    return None

def chiffrement_playfair(texte, cle):
    texte = prepare_texte(texte)
    grille = generate_grille(cle)
    resultat = ""
    for i in range(0, len(texte), 2):
        a, b = texte[i], texte[i+1]
        ra, ca = find_position(grille, a)
        rb, cb = find_position(grille, b)
        if ra == rb:
            resultat += grille[ra][(ca + 1) % 5]
            resultat += grille[rb][(cb + 1) % 5]
        elif ca == cb:
            resultat += grille[(ra + 1) % 5][ca]
            resultat += grille[(rb + 1) % 5][cb]
        else:
            resultat += grille[ra][cb]
            resultat += grille[rb][ca]
    return resultat

# === Utilisation ===
import string

texte = input("Entrez un texte à chiffrer (Playfair) : ")
cle = input("Entrez la clé : ")
resultat = chiffrement_playfair(texte, cle)
print("Texte chiffré :", resultat)
