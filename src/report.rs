use crate::scanner::Finding;
use serde::Serialize;

/// Rapport complet, tel qu'il est sérialisé en JSON.
#[derive(Serialize)]
pub struct Report<'a> {
    pub scanned_files: usize,
    pub findings_count: usize,
    pub findings: &'a [Finding],
}

/// Rapport lisible dans un terminal, groupé par fichier.
pub fn render_text(findings: &[Finding], scanned_files: usize) -> String {
    if findings.is_empty() {
        return format!("Aucun secret détecté ({scanned_files} fichiers analysés).\n");
    }

    let mut output = String::new();
    let mut current_file = None;

    for finding in findings {
        let path = finding.path.display().to_string();
        if current_file.as_deref() != Some(path.as_str()) {
            output.push_str(&format!("\n{path}\n"));
            current_file = Some(path);
        }

        let position = if finding.line == 0 {
            format!("  {:<11}", "(fichier)")
        } else {
            format!("  ligne {:<5}", finding.line)
        };

        output.push_str(&format!(
            "{position} [{}] {} — {}\n               valeur : {}",
            finding.severity.label(),
            finding.rule,
            finding.description,
            finding.redacted
        ));

        if finding.entropy > 0.0 {
            output.push_str(&format!(" · entropie {:.2}", finding.entropy));
        }
        output.push('\n');
    }

    let high = findings
        .iter()
        .filter(|finding| finding.severity == crate::rules::Severity::High)
        .count();

    output.push_str(&format!(
        "\n{} secret(s) potentiel(s) sur {scanned_files} fichiers analysés — {high} de gravité élevée.\n",
        findings.len()
    ));

    output
}

/// Rapport JSON, destiné à être consommé par un autre outil.
pub fn render_json(findings: &[Finding], scanned_files: usize) -> String {
    let report = Report {
        scanned_files,
        findings_count: findings.len(),
        findings,
    };
    serde_json::to_string_pretty(&report).expect("sérialisation JSON impossible")
}
