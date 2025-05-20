def test_kasiski(texte, longueur=3):
    texte = texte.lower()
    repetitions = {}
    for i in range(len(texte) - longueur + 1):
        seq = texte[i:i + longueur]
        if seq in repetitions:
            repetitions[seq].append(i)
        else:
            repetitions[seq] = [i]
    # On garde seulement les séquences qui apparaissent plus d'une fois
    return {seq: positions for seq, positions in repetitions.items() if len(positions) > 1}

# === Utilisation ===
texte = input("Entrez un texte à analyser (Test de Kasiski) : ")
taille_sequence = int(input("Longueur de séquence à rechercher (par défaut 3) : ") or 3)

resultats = test_kasiski(texte, taille_sequence)

if resultats:
    print("Séquences répétées trouvées :")
    for seq, positions in resultats.items():
        print(f"{seq} : positions {positions}")
else:
    print("Aucune séquence répétée trouvée.")
