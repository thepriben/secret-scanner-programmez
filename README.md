# Secrets, expressions régulières et Rust : détecter les tokens oubliés en construisant son propre scanner

> Code compagnon de l'article *« Secrets, expressions régulières et Rust : détecter les tokens oubliés en construisant son propre scanner »*, **_Programmez!_** hors-série n°24 « Hack Sécurité », pp. 23-27, 2026.

Un outil en ligne de commande écrit en [Rust](https://www.rust-lang.org/) qui repère les secrets laissés en clair dans un dépôt — jetons GitHub, clés AWS, JWT, mots de passe, fichiers `.env`, URLs contenant des identifiants — **avant** qu'un `git commit` ne les enregistre. L'article s'en sert de fil conducteur pour traiter trois questions : comment décrire un secret par une expression régulière, comment écarter les faux positifs, et comment brancher le résultat sur un hook Git et une GitHub Action.

## Ce que fait l'outil

```console
$ secret-scan .

config/settings.py
  ligne 2     [MOYEN] generic-secret-assignment — Affectation d'un mot de passe ou d'une clé en clair
               valeur : Zk29…Bd (20 caractères) · entropie 4.32
  ligne 3     [ÉLEVÉ] aws-access-key-id — Identifiant de clé d'accès AWS
               valeur : AKIA…VC (20 caractères) · entropie 4.22

.env
  (fichier)   [MOYEN] sensitive-file-name — Fichier destiné à contenir des secrets, non exclu par .gitignore
               valeur : .env
  ligne 2     [ÉLEVÉ] github-token — Jeton d'accès personnel GitHub (format classique)
               valeur : ghp_…r8 (40 caractères) · entropie 4.82

7 secret(s) potentiel(s) sur 5 fichiers analysés — 4 de gravité élevée.
```

Les valeurs détectées sont systématiquement masquées : un rapport de CI est archivé, lisible par d'autres, et n'a pas à divulguer le secret une seconde fois. Le code de retour vaut `1` dès qu'une alerte est levée, ce qui suffit à interrompre un hook ou une étape d'intégration continue.

## Règles de détection

| Règle | Gravité | Ce qu'elle repère |
| --- | --- | --- |
| `github-token` | élevée | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` suivis de 36 caractères |
| `github-pat-fine-grained` | élevée | jetons `github_pat_…` à permissions fines |
| `aws-access-key-id` | élevée | `AKIA…`, `ASIA…` et préfixes voisins |
| `aws-secret-access-key` | élevée | clé de 40 caractères affectée à `aws_secret_access_key` |
| `google-api-key` | élevée | clés `AIza…` |
| `slack-token` | élevée | jetons `xoxb-`, `xoxp-`… |
| `stripe-secret-key` | élevée | clés `sk_live_…` |
| `private-key-block` | élevée | en-tête `-----BEGIN … PRIVATE KEY-----` |
| `url-with-credentials` | élevée | `postgres://utilisateur:motdepasse@hôte` |
| `jwt` | moyenne | jetons à trois segments `eyJ….eyJ….…` |
| `generic-secret-assignment` | moyenne | `PASSWORD`, `TOKEN`, `API_KEY`… affectés à une chaîne littérale |
| `sensitive-file-name` | moyenne | `.env`, `id_rsa`, `*.pem` non exclus par `.gitignore` |

Trois filtres limitent les faux positifs : l'**entropie de Shannon** sur les règles génériques, une liste de **valeurs d'exemple**, anglaises et françaises (`changeme`, `your-token`, `AKIAIOSFODNN7EXAMPLE`, `motdepasse`, `votre-jeton`…), et la reconnaissance des **interpolations de variables** (`$TOKEN`, `${TOKEN}`, `{{ token }}`), qui désignent un secret sans le contenir.

Une ligne portant le commentaire `secret-scan:allow` est ignorée.

## Utilisation

```bash
cargo run -- .                    # analyser le répertoire courant
cargo run -- --staged             # n'analyser que les fichiers indexés
cargo run -- --json .             # rapport exploitable par un autre outil
cargo run -- --high-only .        # ne garder que la gravité élevée
```

## Essayer sur un dépôt de démonstration

Le script fabrique un petit projet contenant des secrets factices, ainsi que les pièges usuels : valeurs d'exemple dans la documentation, jeton enfoui dans `node_modules`, jeton présent dans un fichier binaire.

```bash
./demo/creer-depot-exemple.sh /tmp/depot-exemple
cargo run -- /tmp/depot-exemple
```

## Installer le hook pre-commit

```bash
cargo install --path .
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Le hook n'analyse que l'index Git, c'est-à-dire les fichiers que le commit s'apprête à enregistrer, et refuse le commit en cas d'alerte. `git commit --no-verify` permet de passer outre.

## Intégration continue

[`.github/workflows/secret-scan.yml`](.github/workflows/secret-scan.yml) compile le scanner, analyse le dépôt à chaque `push` et chaque pull request, et publie le rapport JSON en artefact lorsque l'analyse échoue.

## Structure

```
src/
├── main.rs       # interface en ligne de commande, code de retour
├── rules.rs      # règles de détection et filtres de faux positifs
├── entropy.rs    # entropie de Shannon
├── scanner.rs    # parcours du dépôt, lecture des fichiers, index Git
└── report.rs     # rapport texte et rapport JSON
```

## Limites

L'outil analyse l'**état courant** des fichiers, pas l'historique Git. Un secret retiré dans un commit récent reste lisible dans les commits antérieurs : la seule réponse valable est de **révoquer** le secret auprès de son fournisseur, la réécriture d'historique n'étant qu'un nettoyage complémentaire.

## Licence

MIT.
