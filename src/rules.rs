use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;

/// Gravité associée à une règle.
///
/// `High` désigne un motif dont la forme est propre à un fournisseur donné
/// (un jeton GitHub ne ressemble à rien d'autre qu'à un jeton GitHub).
/// `Medium` désigne un motif générique, qui demande une relecture humaine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::High => "ÉLEVÉ",
            Severity::Medium => "MOYEN",
        }
    }
}

/// Une règle de détection.
///
/// `capture` indique le numéro du groupe de capture qui contient la valeur du
/// secret : 0 pour la totalité du motif, 1 pour le premier groupe entre
/// parenthèses. `min_entropy`, lorsqu'il est renseigné, impose à cette valeur
/// une entropie minimale avant de signaler quoi que ce soit.
pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub pattern: Regex,
    pub capture: usize,
    pub min_entropy: Option<f64>,
}

impl Rule {
    fn new(
        id: &'static str,
        description: &'static str,
        severity: Severity,
        pattern: &str,
        capture: usize,
        min_entropy: Option<f64>,
    ) -> Self {
        Self {
            id,
            description,
            severity,
            pattern: Regex::new(pattern).expect("motif de détection invalide"),
            capture,
            min_entropy,
        }
    }
}

/// Les règles sont compilées une seule fois, au premier accès.
///
/// Compiler une expression régulière coûte cher ; le faire à chaque fichier
/// dominerait le temps d'exécution du scanner.
pub static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    use Severity::{High, Medium};

    vec![
        Rule::new(
            "github-token",
            "Jeton d'accès personnel GitHub (format classique)",
            High,
            r"gh[pousr]_[A-Za-z0-9]{36}",
            0,
            None,
        ),
        Rule::new(
            "github-pat-fine-grained",
            "Jeton GitHub à permissions fines",
            High,
            r"github_pat_[A-Za-z0-9_]{22,}",
            0,
            None,
        ),
        Rule::new(
            "aws-access-key-id",
            "Identifiant de clé d'accès AWS",
            High,
            r"(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}",
            0,
            None,
        ),
        Rule::new(
            "aws-secret-access-key",
            "Clé secrète AWS",
            High,
            r#"(?i)aws_?secret_?access_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})"#,
            1,
            Some(3.5),
        ),
        Rule::new(
            "google-api-key",
            "Clé d'API Google",
            High,
            r"AIza[0-9A-Za-z_\-]{35}",
            0,
            None,
        ),
        Rule::new(
            "slack-token",
            "Jeton Slack",
            High,
            r"xox[baprs]-[A-Za-z0-9-]{10,}",
            0,
            None,
        ),
        Rule::new(
            "stripe-secret-key",
            "Clé secrète Stripe (environnement de production)",
            High,
            r"sk_live_[0-9a-zA-Z]{16,}",
            0,
            None,
        ),
        Rule::new(
            "private-key-block",
            "En-tête de clé privée",
            High,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            0,
            None,
        ),
        Rule::new(
            "url-with-credentials",
            "URL contenant un identifiant et un mot de passe",
            High,
            r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:([^/\s:@]{3,})@",
            1,
            None,
        ),
        Rule::new(
            "jwt",
            "Jeton JWT",
            Medium,
            r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
            0,
            None,
        ),
        Rule::new(
            "generic-secret-assignment",
            "Affectation d'un mot de passe ou d'une clé en clair",
            Medium,
            r#"(?i)[a-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key)[a-z0-9_.\-]*["']?\s*[:=]\s*["']([^"'\s]{8,})["']"#,
            1,
            Some(3.5),
        ),
    ]
});

/// Fichiers dont le nom seul justifie une alerte, sans regarder le contenu.
pub const SUSPICIOUS_FILE_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials",
    "secrets.json",
    "serviceaccount.json",
];

/// Extensions dont la présence signale un porteur de clé privée.
pub const SUSPICIOUS_FILE_EXTENSIONS: &[&str] = &["pem", "key", "p12", "pfx", "keystore", "jks"];

/// Marqueurs de valeur d'exemple.
///
/// La documentation d'un projet est remplie de secrets factices ; les signaler
/// noierait les vraies alertes.
const PLACEHOLDER_MARKERS: &[&str] = &[
    // Marqueurs anglais.
    "example",
    "changeme",
    "change_me",
    "placeholder",
    "your-",
    "your_",
    "yourtoken",
    "dummy",
    "sample",
    "redacted",
    "xxxxx",
    "aaaaa",
    "todo",
    "fixme",
    "notreal",
    "fake",
    // Marqueurs français : la documentation d'un projet francophone emploie
    // ses propres valeurs factices.
    "exemple",
    "motdepasse",
    "mot_de_passe",
    "motdepasseici",
    "votre-",
    "votre_",
    "utilisateur",
    "aremplacer",
    "a_remplacer",
];

/// Repère les valeurs manifestement destinées à la documentation.
pub fn looks_like_placeholder(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
        || value.starts_with('<')
        // Une interpolation de variable — « $TOKEN », « ${TOKEN} », « {{ token }} » —
        // désigne le secret sans le contenir.
        || value.starts_with('$')
        || value.starts_with("{{")
        || value.starts_with("%(")
}

#[cfg(test)]
mod tests {
    use super::{RULES, looks_like_placeholder};

    fn matches(rule_id: &str, line: &str) -> bool {
        RULES
            .iter()
            .find(|rule| rule.id == rule_id)
            .expect("règle inconnue")
            .pattern
            .is_match(line)
    }

    #[test]
    fn un_jeton_github_est_reconnu() {
        assert!(matches(
            "github-token",
            "const T = \"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\";" // secret-scan:allow
        ));
    }

    #[test]
    fn un_identifiant_aws_est_reconnu() {
        assert!(matches("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn une_url_avec_identifiants_est_reconnue() {
        assert!(matches(
            "url-with-credentials",
            "postgres://admin:Tr0ub4dor@db.interne:5432/app" // secret-scan:allow
        ));
    }

    #[test]
    fn un_prefixe_ne_masque_pas_le_mot_cle() {
        // Le nom de la variable est rarement le mot-clé seul : la règle doit
        // tolérer ce qui l'entoure dans un identifiant.
        assert!(matches(
            "generic-secret-assignment",
            "DATABASE_PASSWORD = \"Zk29LmQp7Rt4Xw8Nv1Bd\""
        ));
        assert!(matches(
            "generic-secret-assignment",
            "\"stripeApiKey\": \"Zk29LmQp7Rt4Xw8Nv1Bd\""
        ));
    }

    #[test]
    fn une_valeur_dexemple_est_ecartee() {
        assert!(looks_like_placeholder("your-token-here"));
        assert!(looks_like_placeholder("<API_KEY>"));
        assert!(!looks_like_placeholder("Zk29LmQp7Rt4Xw8Nv1Bd"));
    }

    #[test]
    fn une_valeur_dexemple_francophone_est_ecartee() {
        assert!(looks_like_placeholder("motdepasse"));
        assert!(looks_like_placeholder("votre-jeton"));
        assert!(looks_like_placeholder("cle_dexemple"));
    }

    #[test]
    fn une_interpolation_de_variable_est_ecartee() {
        assert!(looks_like_placeholder("$GITHUB_TOKEN"));
        assert!(looks_like_placeholder("${GITHUB_TOKEN}"));
        assert!(looks_like_placeholder("{{ github_token }}"));
    }
}
