use clap::Args;
use colored::*;
use sanctifier_core::{Analyzer, SanctifyConfig};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Path to the contract directory or Cargo.toml
    #[arg(default_value = ".")]
    pub path: PathBuf,
}

pub fn exec(args: AnalyzeArgs) -> anyhow::Result<()> {
    let path = &args.path;

    if !is_soroban_project(path) {
        eprintln!(
            "{} Error: {:?} is not a valid Soroban project. (Missing Cargo.toml with 'soroban-sdk' dependency)",
            "❌".red(),
            path
        );
        std::process::exit(1);
    }

    println!(
        "{} Sanctifier: Valid Soroban project found at {:?}",
        "✨".green(),
        path
    );

    let config = SanctifyConfig::default();
    let analyzer = Analyzer::new(config);

    let mut collisions = Vec::new();

    if path.is_dir() {
        walk_dir(path, &analyzer, &mut collisions)?;
    } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
        if let Ok(content) = fs::read_to_string(path) {
            collisions.extend(analyzer.scan_storage_collisions(&content));
        }
    }

    if collisions.is_empty() {
        println!("\n{} No storage key collisions found.", "✅".green());
    } else {
        println!(
            "\n{} Found potential Storage Key Collisions!",
            "⚠️".yellow()
        );
        for collision in collisions {
            println!("   {} Value: {}", "->".red(), collision.key_value.bold());
            println!("      Type: {}", collision.key_type);
            println!("      Location: {}", collision.location);
            println!("      Message: {}", collision.message);
        }
    }

    Ok(())
}

fn walk_dir(
    dir: &Path,
    analyzer: &Analyzer,
    collisions: &mut Vec<sanctifier_core::StorageCollisionIssue>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir(&path, analyzer, collisions)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Ok(content) = fs::read_to_string(&path) {
                let mut issues = analyzer.scan_storage_collisions(&content);
                // Prefix location with filename
                let file_name = path.display().to_string();
                for issue in &mut issues {
                    issue.location = format!("{}:{}", file_name, issue.location);
                }
                collisions.extend(issues);
            }
        }
    }
    Ok(())
}

#[derive(Default, Debug)]
pub struct FileAnalysisResult {
    pub file_path: String,
    pub auth_gaps: Vec<sanctifier_core::AuthGapIssue>,
    pub panic_issues: Vec<sanctifier_core::PanicIssue>,
    pub arithmetic_issues: Vec<sanctifier_core::ArithmeticIssue>,
    pub size_warnings: Vec<sanctifier_core::SizeWarning>,
    pub unsafe_patterns: Vec<sanctifier_core::UnsafePattern>,
    pub collisions: Vec<sanctifier_core::StorageCollisionIssue>,
    pub event_issues: Vec<sanctifier_core::EventIssue>,
    pub unhandled_results: Vec<sanctifier_core::UnhandledResultIssue>,
    pub upgrade_reports: Vec<sanctifier_core::UpgradeReport>,
    pub smt_issues: Vec<sanctifier_core::SmtInvariantIssue>,
    pub sep41_issues: Vec<sanctifier_core::Sep41Issue>,
    pub vuln_matches: Vec<crate::vulndb::VulnMatch>,
    pub timed_out: bool,
}

pub fn load_config(_path: &Path) -> SanctifyConfig {
    SanctifyConfig::default()
}

pub fn collect_rs_files(dir: &Path, _ignore_paths: &[String]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_rs_files(&path, _ignore_paths));
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    files
}

pub fn analyze_single_file(
    _analyzer: &Analyzer,
    _vuln_db: &crate::vulndb::VulnDatabase,
    _content: &str,
    file_name: &str,
) -> FileAnalysisResult {
    FileAnalysisResult {
        file_path: file_name.to_string(),
        ..Default::default()
    }
}

pub fn run_with_timeout<F, T>(_timeout: Option<std::time::Duration>, f: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    Some(f())
}

pub fn is_soroban_project(path: &Path) -> bool {
    // Allow analysing individual .rs files directly (e.g. in tests)
    if path.is_file() {
        if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            return true;
        }
        if path.file_name().and_then(|s| s.to_str()) == Some("Cargo.toml") {
            if let Ok(content) = fs::read_to_string(path) {
                return content.contains("soroban-sdk");
            }
            return false;
        }
    }

    if path.is_dir() {
        let cargo_toml = path.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(content) = fs::read_to_string(&cargo_toml) {
                return content.contains("soroban-sdk");
            }
        }
        return false;
    }

    false
}
