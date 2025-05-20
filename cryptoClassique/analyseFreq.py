from collections import Counter

def analyse_frequentielle(texte):
    texte = ''.join(filter(str.isalpha, texte.lower()))
    frequence = Counter(texte)
    total = sum(frequence.values())
    resultat = {lettre: round((compte / total) * 100, 2) for lettre, compte in frequence.items()}
    return resultat

# === Utilisation ===
texte = input("Entrez un texte à analyser (fréquence des lettres) : ")
frequences = analyse_frequentielle(texte)

print("Fréquence des lettres (%):")
for lettre, freq in sorted(frequences.items()):
    print(f"{lettre} : {freq}%")
