mod entropy;
mod report;
mod rules;
mod scanner;

use clap::Parser;
use rules::Severity;
use std::path::PathBuf;
use std::process::ExitCode;

/// Détecteur de secrets oubliés dans un dépôt.
#[derive(Parser)]
#[command(
    name = "secret-scan",
    version,
    about = "Repère les jetons, clés et mots de passe laissés en clair dans un dépôt."
)]
struct Cli {
    /// Répertoire à analyser.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// N'analyser que les fichiers ajoutés à l'index Git.
    #[arg(long)]
    staged: bool,

    /// Produire le rapport au format JSON.
    #[arg(long)]
    json: bool,

    /// Ne signaler que les alertes de gravité élevée.
    #[arg(long)]
    high_only: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let files = if cli.staged {
        match scanner::staged_files() {
            Ok(files) => files,
            Err(message) => {
                eprintln!("secret-scan : {message}");
                return ExitCode::from(2);
            }
        }
    } else {
        scanner::collect_files(&cli.path)
    };

    let mut findings: Vec<_> = files.iter().flat_map(|path| scanner::scan_file(path)).collect();

    if cli.high_only {
        findings.retain(|finding| finding.severity == Severity::High);
    }

    let rendered = if cli.json {
        report::render_json(&findings, files.len())
    } else {
        report::render_text(&findings, files.len())
    };
    print!("{rendered}");

    // Un code de retour non nul suffit à interrompre un hook Git ou une
    // étape de CI ; c'est tout ce qui est demandé à l'outil pour bloquer.
    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
