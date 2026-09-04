#!/usr/bin/env bash
# Fabrique un petit dépôt de démonstration contenant des secrets factices,
# afin d'exercer le scanner sans jamais versionner de valeur sensible.
#
#   ./demo/creer-depot-exemple.sh /tmp/depot-exemple
#   cargo run -- /tmp/depot-exemple
#
# Les valeurs sont regroupées ici, chacune neutralisée par le marqueur
# d'exception : ce script est lui-même analysé par le scanner en intégration
# continue, et n'a pas à déclencher d'alerte.

set -euo pipefail

cible="${1:-/tmp/depot-exemple}"
rm -rf "$cible"
mkdir -p "$cible"/{config,src,docs,node_modules/gadget}

jeton_github="ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"           # secret-scan:allow
cle_aws="AKIAZ7QW3RTY9PLMNBVC"                                     # secret-scan:allow
secret_aws="Kq7vN2xR8pL4wZ1mT6yB3jH9sD5fG0cV7nQ2eA4u"              # secret-scan:allow
mot_de_passe_bdd="Zk29LmQp7Rt4Xw8Nv1Bd"                            # secret-scan:allow
url_cache="postgres://deploy:Tr0ub4dor3xK@db.interne:5432/facturation"  # secret-scan:allow
jeton_jwt="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0Mjc5IiwibmFtZSI6IkNJIiwiaWF0IjoxNzE1MDAwMDAwfQ.Rq7Wm2xPl9Nv4Zt6Bd1Hs8Kc3Jy5Fg0Aw"  # secret-scan:allow

cat > "$cible/.env" <<EOF
API_BASE_URL=https://api.interne.example.com
GITHUB_TOKEN=$jeton_github
EOF

cat > "$cible/config/settings.py" <<EOF
DEBUG = False
DATABASE_PASSWORD = "$mot_de_passe_bdd"
AWS_ACCESS_KEY_ID = "$cle_aws"
aws_secret_access_key = "$secret_aws"
EOF

cat > "$cible/src/api.js" <<EOF
const CACHE = "$url_cache";
const SESSION = "$jeton_jwt";
export { CACHE, SESSION };
EOF

# Documentation : uniquement des valeurs d'exemple, qui ne doivent pas être
# signalées.
cat > "$cible/docs/configuration.md" <<'EOF'
Renseignez vos identifiants avant le premier démarrage :

    GITHUB_TOKEN=ghp_your-token-here
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    DATABASE_PASSWORD=changeme
EOF

# Dépendance installée : ignorée par le parcours.
cat > "$cible/node_modules/gadget/index.js" <<EOF
module.exports = { token: "$jeton_github" };
EOF

# Fichier binaire : écarté par la détection de l'octet nul.
printf '\x89PNG\r\n\x1a\n\x00\x00%s' "$jeton_github" > "$cible/docs/logo.png"

echo "Dépôt de démonstration créé dans $cible"
