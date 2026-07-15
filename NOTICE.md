# Attributions tierces

## Liste de mots (générateur de phrase de passe)

`src-tauri/src/wordlist_en.txt` est la **EFF Large Wordlist for Passphrases**
(Electronic Frontier Foundation), distribuée sous licence
**Creative Commons Attribution 3.0 (CC BY 3.0)**.

Source : https://www.eff.org/dice
Le fichier a été réduit aux seuls mots (la colonne des numéros de dés a été
retirée), et les quelques mots contenant un tiret ont été retirés pour éviter
toute ambiguïté avec le séparateur des phrases de passe.

## Polices

L'interface embarque quatre fichiers de polices dans `src/fonts/`, toutes sous
licence **SIL Open Font License 1.1** (texte complet : `src/fonts/OFL.txt`) :

- **Inter** (`inter-400.woff2`, `inter-600.woff2`) : Copyright (c) 2016 The Inter
  Project Authors (Rasmus Andersson). https://github.com/rsms/inter
- **Space Grotesk** (`space-grotesk-600.woff2`) : Copyright (c) 2020 Florian
  Karsten. https://github.com/floriankarsten/space-grotesk
- **IBM Plex Mono** (`ibm-plex-mono-400.woff2`) : Copyright (c) 2017 IBM Corp.
  https://github.com/IBM/plex

## Dépendances

Gestio est distribué sous GPL-3.0. Ses dépendances Rust sont majoritairement sous
licences permissives (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode-3.0), plus quelques
crates en MPL-2.0 utilisés sans modification, toutes compatibles avec la GPL-3.0.
La liste complète et versionnée des dépendances figure dans `src-tauri/Cargo.lock`.

Ces licences imposent de conserver leurs mentions de copyright dans les
distributions binaires. Un fichier d'agrégation complet des textes de licences
tierces peut être produit avec
[`cargo about`](https://github.com/EmbarkStudios/cargo-about) (après ajout d'un
fichier de configuration `about.toml`).
