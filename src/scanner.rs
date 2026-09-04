use crate::entropy::shannon;
use crate::rules::{
    RULES, SUSPICIOUS_FILE_EXTENSIONS, SUSPICIOUS_FILE_NAMES, Severity, looks_like_placeholder,
};
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use walkdir::WalkDir;

/// Répertoires écartés du parcours.
///
/// `.git` contient l'historique compressé, `target` et `node_modules` des
/// artefacts de compilation ou des dépendances : les scanner ferait exploser
/// le temps d'exécution sans rien apporter.
pub const IGNORED_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".mypy_cache",
    ".pytest_cache",
];

/// Taille maximale d'un fichier examiné, en octets.
pub const MAX_FILE_SIZE: u64 = 1_048_576;

/// Commentaire qui neutralise la détection sur la ligne où il figure.
pub const ALLOW_MARKER: &str = "secret-scan:allow";

/// Un secret potentiel, localisé dans un fichier.
#[derive(Debug, Serialize)]
pub struct Finding {
    pub path: PathBuf,
    pub line: usize,
    pub rule: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub redacted: String,
    pub entropy: f64,
}

/// Masque une valeur pour qu'elle puisse figurer dans un rapport ou un journal
/// de CI sans y être divulguée une seconde fois.
pub fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{head}…{tail} ({} caractères)", chars.len())
}

/// Détecte les fichiers binaires par la présence d'un octet nul.
///
/// Un fichier texte n'en contient pas ; une image ou un exécutable en contient
/// presque toujours dans ses premiers kilo-octets.
fn is_probably_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8_000).any(|&byte| byte == 0)
}

/// Interroge Git pour savoir si un chemin est déjà exclu par `.gitignore`.
///
/// La sortie d'erreur est neutralisée : hors d'un dépôt, `git check-ignore`
/// se plaint, et ce message n'a pas à polluer le rapport.
fn is_git_ignored(path: &Path) -> bool {
    Command::new("git")
        .args(["check-ignore", "-q"])
        .arg(path)
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Alerte fondée sur le seul nom du fichier.
fn scan_file_name(path: &Path) -> Option<Finding> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    let extension = path
        .extension()
        .map(|ext| ext.to_string_lossy().to_ascii_lowercase());

    let by_name = SUSPICIOUS_FILE_NAMES.contains(&name.as_str());
    let by_extension = extension
        .as_deref()
        .is_some_and(|ext| SUSPICIOUS_FILE_EXTENSIONS.contains(&ext));

    if !(by_name || by_extension) || is_git_ignored(path) {
        return None;
    }

    Some(Finding {
        path: path.to_path_buf(),
        line: 0,
        rule: "sensitive-file-name",
        description: "Fichier destiné à contenir des secrets, non exclu par .gitignore",
        severity: Severity::Medium,
        redacted: name,
        entropy: 0.0,
    })
}

/// Applique toutes les règles au contenu d'un fichier.
pub fn scan_file(path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(finding) = scan_file_name(path) {
        findings.push(finding);
    }

    let metadata = match path.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return findings,
    };
    if !metadata.is_file() || metadata.len() > MAX_FILE_SIZE {
        return findings;
    }

    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return findings,
    };
    if is_probably_binary(&bytes) {
        return findings;
    }
    let content = String::from_utf8_lossy(&bytes);

    // Un même secret peut satisfaire plusieurs règles ; on ne le signale
    // qu'une fois par ligne.
    let mut already_seen: HashSet<(usize, String)> = HashSet::new();

    for (index, line) in content.lines().enumerate() {
        if line.contains(ALLOW_MARKER) {
            continue;
        }
        let line_number = index + 1;

        for rule in RULES.iter() {
            for captures in rule.pattern.captures_iter(line) {
                let Some(matched) = captures.get(rule.capture) else {
                    continue;
                };
                let value = matched.as_str();

                if looks_like_placeholder(value) {
                    continue;
                }

                let entropy = shannon(value);
                if let Some(minimum) = rule.min_entropy
                    && entropy < minimum
                {
                    continue;
                }

                if !already_seen.insert((line_number, value.to_string())) {
                    continue;
                }

                findings.push(Finding {
                    path: path.to_path_buf(),
                    line: line_number,
                    rule: rule.id,
                    description: rule.description,
                    severity: rule.severity,
                    redacted: redact(value),
                    entropy,
                });
            }
        }
    }

    findings
}

/// Parcourt un répertoire et retourne les fichiers à examiner.
pub fn collect_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            !(entry.file_type().is_dir() && IGNORED_DIRS.contains(&name.as_ref()))
        })
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .collect()
}

/// Retourne les fichiers présents dans l'index Git, c'est-à-dire ceux qu'un
/// `git commit` est sur le point d'enregistrer.
///
/// `--diff-filter=ACM` retient les fichiers ajoutés, copiés ou modifiés, et
/// écarte les suppressions, dont le contenu n'existe plus.
pub fn staged_files() -> Result<Vec<PathBuf>, String> {
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
        .output()
        .map_err(|error| format!("git est introuvable : {error}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{is_probably_binary, redact, scan_file};
    use std::io::Write;

    #[test]
    fn la_valeur_est_masquee() {
        assert_eq!(redact("ghp_0123456789"), "ghp_…89 (14 caractères)");
        assert_eq!(redact("court"), "*****");
    }

    #[test]
    fn un_contenu_binaire_est_reconnu() {
        assert!(is_probably_binary(b"\x89PNG\r\n\x1a\n\x00\x00"));
        assert!(!is_probably_binary(b"let token = 42;"));
    }

    #[test]
    fn un_jeton_est_detecte_dans_un_fichier() {
        let mut file = tempfile();
        let jeton = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"; // secret-scan:allow
        writeln!(file.1, "let t = \"{jeton}\";").unwrap();
        let findings = scan_file(&file.0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "github-token");
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn le_marqueur_dexception_neutralise_la_ligne() {
        let mut file = tempfile();
        writeln!(
            file.1,
            "let t = \"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\"; // secret-scan:allow"
        )
        .unwrap();
        assert!(scan_file(&file.0).is_empty());
    }

    fn tempfile() -> (std::path::PathBuf, std::fs::File) {
        let path = std::env::temp_dir().join(format!(
            "secret-scan-test-{}-{:?}.txt",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = std::fs::File::create(&path).unwrap();
        (path, file)
    }
}
