from collections import Counter

def indice_coincidence(texte):
    texte = ''.join(filter(str.isalpha, texte.lower()))
    N = len(texte)
    if N <= 1:
        return 0.0
    frequence = Counter(texte)
    num = sum(f * (f - 1) for f in frequence.values())
    denom = N * (N - 1)
    return round(num / denom, 4)

# === Utilisation ===
texte = input("Entrez un texte pour calculer l'indice de coïncidence : ")
ic = indice_coincidence(texte)
print("Indice de coïncidence :", ic)
