# 🔐 Cryptographie Classique en Python

Ce projet contient plusieurs implémentations de techniques de **cryptographie classique** et de **cryptanalyse** en Python. Chaque fichier est indépendant et contient un exemple d'utilisation avec saisie utilisateur.

---

## 📦 Contenu

### 1. `chiffCesar.py` — Chiffrement de César
- Décale chaque lettre d’un certain nombre de positions.
- Paramètre : `décalage` (entier)
- Exemple : `A` avec décalage 3 → `D`

---

### 2. `chiffSubstitionAleatoire.py` — Substitution Aléatoire
- Substitue chaque lettre par une autre selon une clé générée aléatoirement.
- Affiche la **clé utilisée**.
- Exemple : `bonjour` → `dktqczs` (selon clé aléatoire)

---

### 3. `chiffVigenere.py` — Chiffrement de Vigenère
- Utilise une **clé alphabétique** répétée pour décaler les lettres.
- Plus sécurisé que César.
- Exemple : Texte = `bonjour`, Clé = `cle` → `dsmnbcr`

---

### 4. `analyseFreq.py` — Analyse Fréquentielle
- Affiche la fréquence (%) d’apparition des lettres dans le texte.
- Outil utile pour casser un chiffrement monoalphabétique.

---

### 5. `testKasiski.py` — Test de Kasiski (simple)
- Recherche les séquences répétées (digrammes, trigrammes...) pour deviner la longueur de la clé Vigenère.
- Paramètre : longueur des séquences.

---

### 6. `indiceCoincidence.py` — Indice de Coïncidence
- Calcule la probabilité que deux lettres prises au hasard soient identiques.
- Permet de détecter si un texte est chiffré mono ou polyalphabétiquement.
- IC ≈ 0.065 pour du français clair, ≈ 0.038 pour Vigenère.

---

### 7. `chiffAffine.py` — Chiffrement Affine
- Chiffre avec la formule : `(a * x + b) mod 26`
- `a` doit être **premier avec 26**
- Exemple : `a=5, b=8`

---

### 8. `chiffPlayfair.py` — Chiffrement de Playfair
- Chiffrement par paires de lettres avec une grille 5x5 générée à partir d’une clé.
- `J` est fusionné avec `I`.
- Gère les lettres doublées et les `X` de remplissage.

---



## 🚀 Utilisation

Chaque fichier peut être lancé indépendamment :

```bash
python chiffcesar.py
python chiffVigenere.py

