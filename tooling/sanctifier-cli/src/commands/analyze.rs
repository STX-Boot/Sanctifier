use clap::Args;
use colored::*;
use sanctifier_core::{Analyzer, SanctifyConfig};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Path to the contract directory or Cargo.toml
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output format (text or json)
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: String,

    /// Exit with non-zero status when findings are present
    #[arg(long)]
    pub exit_code: bool,
}

pub fn exec(args: AnalyzeArgs) -> anyhow::Result<()> {
    let path = &args.path;

    if !is_soroban_project(path) {
        if args.format == "json" {
            let error_msg = format!(
                "{:?} is not a valid Soroban project. (Missing Cargo.toml with 'soroban-sdk' dependency)",
                path
            );
            println!(r#"{{"error": "{}"}}"#, error_msg);
        } else {
            eprintln!(
                "{} Error: {:?} is not a valid Soroban project. (Missing Cargo.toml with 'soroban-sdk' dependency)",
                "❌".red(),
                path
            );
        }
        std::process::exit(1);
    }

    let config = SanctifyConfig::default();
    let analyzer = Analyzer::new(config);

    let mut auth_gaps = Vec::new();
    let mut panics = Vec::new();
    let mut arithmetic_issues = Vec::new();
    let mut unsafe_patterns = Vec::new();
    let mut size_warnings = Vec::new();
    let mut collisions = Vec::new();

    // Read and analyze files
    if path.is_dir() {
        let mut buckets = AnalysisBuckets {
            auth_gaps: &mut auth_gaps,
            panics: &mut panics,
            arithmetic_issues: &mut arithmetic_issues,
            unsafe_patterns: &mut unsafe_patterns,
            size_warnings: &mut size_warnings,
            collisions: &mut collisions,
        };
        walk_dir_analyze(path, &analyzer, &mut buckets)?;
    } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
        if let Ok(content) = fs::read_to_string(path) {
            auth_gaps.extend(analyzer.scan_auth_gaps(&content));
            panics.extend(analyzer.scan_panics(&content));
            arithmetic_issues.extend(analyzer.scan_arithmetic_overflow(&content));
            unsafe_patterns.extend(analyzer.analyze_unsafe_patterns(&content));
            size_warnings.extend(analyzer.analyze_ledger_size(&content));
            collisions.extend(analyzer.scan_storage_collisions(&content));
        }
    }

    let total_findings = auth_gaps.len()
        + panics.len()
        + arithmetic_issues.len()
        + unsafe_patterns.len()
        + size_warnings.len()
        + collisions.len();

    if args.format == "json" {
        output_json(
            &auth_gaps,
            &panics,
            &arithmetic_issues,
            &unsafe_patterns,
            &size_warnings,
            &collisions,
            total_findings,
        );
    } else {
        output_text(
            &auth_gaps,
            &panics,
            &arithmetic_issues,
            &unsafe_patterns,
            &size_warnings,
            &collisions,
        );
    }

    if args.exit_code && total_findings > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn output_json(
    auth_gaps: &[String],
    panics: &[sanctifier_core::PanicIssue],
    arithmetic_issues: &[sanctifier_core::ArithmeticIssue],
    unsafe_patterns: &[sanctifier_core::UnsafePattern],
    size_warnings: &[sanctifier_core::SizeWarning],
    collisions: &[sanctifier_core::StorageCollisionIssue],
    total_findings: usize,
) {
    let has_critical = !auth_gaps.is_empty() || !panics.is_empty() || !arithmetic_issues.is_empty();
    let has_high =
        !size_warnings.is_empty() || !unsafe_patterns.is_empty() || !collisions.is_empty();
    let findings = json!({
        "storage_collisions": collisions
            .iter()
            .map(|c| {
                json!({
                    "code": "S005",
                    "key_value": &c.key_value,
                    "key_type": &c.key_type,
                    "location": &c.location,
                    "message": &c.message,
                })
            })
            .collect::<Vec<_>>(),
        "ledger_size_warnings": size_warnings
            .iter()
            .map(|s| {
                json!({
                    "code": "S004",
                    "struct_name": &s.struct_name,
                    "estimated_size": s.estimated_size,
                    "limit": s.limit,
                    "level": format!("{:?}", s.level),
                })
            })
            .collect::<Vec<_>>(),
        "unsafe_patterns": unsafe_patterns
            .iter()
            .map(|u| {
                json!({
                    "code": "S006",
                    "pattern_type": format!("{:?}", u.pattern_type),
                    "line": u.line,
                    "snippet": &u.snippet,
                })
            })
            .collect::<Vec<_>>(),
        "auth_gaps": auth_gaps
            .iter()
            .map(|f| json!({"code": "S001", "function": f}))
            .collect::<Vec<_>>(),
        "panic_issues": panics
            .iter()
            .map(|p| {
                json!({
                    "code": "S002",
                    "function_name": &p.function_name,
                    "issue_type": &p.issue_type,
                    "location": &p.location,
                })
            })
            .collect::<Vec<_>>(),
        "arithmetic_issues": arithmetic_issues
            .iter()
            .map(|a| {
                json!({
                    "code": "S003",
                    "function_name": &a.function_name,
                    "operation": &a.operation,
                    "suggestion": &a.suggestion,
                    "location": &a.location,
                })
            })
            .collect::<Vec<_>>(),
        "custom_rules": Vec::<serde_json::Value>::new(),
        "event_issues": Vec::<serde_json::Value>::new(),
        "unhandled_results": Vec::<serde_json::Value>::new(),
        "upgrade_risks": Vec::<serde_json::Value>::new(),
        "smt_issues": Vec::<serde_json::Value>::new(),
        "sep41_issues": Vec::<serde_json::Value>::new(),
        "timeouts": Vec::<serde_json::Value>::new(),
    });

    let summary = json!({
        "total_findings": total_findings,
        "storage_collisions": collisions.len(),
        "auth_gaps": auth_gaps.len(),
        "panic_issues": panics.len(),
        "arithmetic_issues": arithmetic_issues.len(),
        "size_warnings": size_warnings.len(),
        "unsafe_patterns": unsafe_patterns.len(),
        "custom_rule_matches": 0,
        "event_issues": 0,
        "unhandled_results": 0,
        "smt_issues": 0,
        "sep41_issues": 0,
        "timed_out_files": 0,
        "has_critical": has_critical,
        "has_high": has_high,
    });

    let result = json!({
        "schema_version": "1.0.0",
        "metadata": {
            "version": env!("CARGO_PKG_VERSION"),
            "timestamp": format!("{:?}", std::time::SystemTime::now()),
            "project_path": std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            "format": "sanctifier-ci-v1",
            "timeout_secs": 0,
        },
        "summary": summary,
        "findings": findings,
        "error_codes": [
            {"code": "S000", "category": "timeout", "description": "Analysis timeout occurred."},
            {"code": "S001", "category": "authentication", "description": "Missing authentication guard in public function."},
            {"code": "S002", "category": "runtime", "description": "Explicit panic/unwrap/expect usage."},
            {"code": "S003", "category": "arithmetic", "description": "Unchecked arithmetic operation may overflow."},
            {"code": "S004", "category": "ledger_size", "description": "Ledger entry size exceeds or approaches the configured limit."},
            {"code": "S005", "category": "storage", "description": "Potential storage key collision detected."},
            {"code": "S006", "category": "runtime", "description": "Unsafe language pattern detected."},
            {"code": "S007", "category": "custom", "description": "Custom regex rule matched contract source."},
            {"code": "S008", "category": "events", "description": "Event schema or topic issue detected."},
            {"code": "S009", "category": "result_handling", "description": "Unhandled Result value detected."},
            {"code": "S010", "category": "upgrade", "description": "Upgrade or admin mechanism risk detected."},
            {"code": "S011", "category": "smt", "description": "SMT invariant issue detected."},
            {"code": "S012", "category": "sep41", "description": "SEP-41 compliance issue detected."}
        ],
        "vulnerability_db_version": "unknown",
        "timed_out_files": Vec::<serde_json::Value>::new(),
        "sep41_checked_contracts": Vec::<serde_json::Value>::new(),
        "storage_collisions": collisions.iter().map(|c| {
            json!({
                "key_value": &c.key_value,
                "key_type": &c.key_type,
                "location": &c.location,
                "message": &c.message,
            })
        }).collect::<Vec<_>>(),
        "ledger_size_warnings": size_warnings
            .iter()
            .map(|s| {
                json!({
                    "struct_name": &s.struct_name,
                    "estimated_size": s.estimated_size,
                    "limit": s.limit,
                    "level": format!("{:?}", s.level),
                })
            })
            .collect::<Vec<_>>(),
        "unsafe_patterns": unsafe_patterns
            .iter()
            .map(|u| {
                json!({
                    "pattern_type": format!("{:?}", u.pattern_type),
                    "line": u.line,
                    "snippet": &u.snippet,
                })
            })
            .collect::<Vec<_>>(),
        "auth_gaps": auth_gaps,
        "panic_issues": panics
            .iter()
            .map(|p| {
                json!({
                    "function_name": &p.function_name,
                    "issue_type": &p.issue_type,
                    "location": &p.location,
                })
            })
            .collect::<Vec<_>>(),
        "arithmetic_issues": arithmetic_issues
            .iter()
            .map(|a| {
                json!({
                    "function_name": &a.function_name,
                    "operation": &a.operation,
                    "suggestion": &a.suggestion,
                    "location": &a.location,
                })
            })
            .collect::<Vec<_>>(),
        "custom_rules": Vec::<serde_json::Value>::new(),
        "event_issues": Vec::<serde_json::Value>::new(),
        "unhandled_results": Vec::<serde_json::Value>::new(),
        "upgrade_reports": Vec::<serde_json::Value>::new(),
        "smt_issues": Vec::<serde_json::Value>::new(),
        "sep41_issues": Vec::<serde_json::Value>::new(),
        "call_graph": Vec::<serde_json::Value>::new(),
        "vulnerability_db_matches": Vec::<serde_json::Value>::new(),
    });

    println!("{result}");
}

fn output_text(
    auth_gaps: &[String],
    panics: &[sanctifier_core::PanicIssue],
    arithmetic_issues: &[sanctifier_core::ArithmeticIssue],
    unsafe_patterns: &[sanctifier_core::UnsafePattern],
    size_warnings: &[sanctifier_core::SizeWarning],
    collisions: &[sanctifier_core::StorageCollisionIssue],
) {
    // Print results
    if !auth_gaps.is_empty() {
        println!("\n{} Found potential Authentication Gaps!", "🛑".red());
        for gap in auth_gaps {
            println!("   {} Function: {}", "->".red(), gap.bold());
        }
    }

    if !panics.is_empty() {
        println!("\n{} Found explicit Panics/Unwraps!", "🛑".red());
        for panic in panics {
            println!(
                "   {} Function: {} ({})",
                "->".red(),
                panic.function_name.bold(),
                panic.issue_type
            );
        }
    }

    if !arithmetic_issues.is_empty() {
        println!("\n{} Found unchecked Arithmetic Operations!", "🛑".red());
        for issue in arithmetic_issues {
            println!(
                "   {} Function: {} (operation: {})",
                "->".red(),
                issue.function_name.bold(),
                issue.operation
            );
        }
    }

    if !unsafe_patterns.is_empty() {
        println!("\n{} Found unsafe patterns!", "⚠️".yellow());
        for pattern in unsafe_patterns {
            println!(
                "   {} Line {}: {} ({})",
                "->".yellow(),
                pattern.line,
                pattern.snippet,
                format!("{:?}", pattern.pattern_type).to_lowercase()
            );
        }
    }

    if !size_warnings.is_empty() {
        println!("\n{} Found ledger size issues!", "⚠️".yellow());
        for warning in size_warnings {
            println!(
                "   {} Struct: {} ({} / {} bytes)",
                "->".yellow(),
                warning.struct_name.bold(),
                warning.estimated_size,
                warning.limit
            );
        }
    } else {
        println!("\n{} No ledger size issues found.", "✅".green());
    }

    if !collisions.is_empty() {
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
    } else {
        println!("\n{} No storage key collisions found.", "✅".green());
    }

    println!("\n{} Static analysis complete.", "✅".green());
}

struct AnalysisBuckets<'a> {
    auth_gaps: &'a mut Vec<String>,
    panics: &'a mut Vec<sanctifier_core::PanicIssue>,
    arithmetic_issues: &'a mut Vec<sanctifier_core::ArithmeticIssue>,
    unsafe_patterns: &'a mut Vec<sanctifier_core::UnsafePattern>,
    size_warnings: &'a mut Vec<sanctifier_core::SizeWarning>,
    collisions: &'a mut Vec<sanctifier_core::StorageCollisionIssue>,
}

fn walk_dir_analyze(
    dir: &Path,
    analyzer: &Analyzer,
    buckets: &mut AnalysisBuckets<'_>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir_analyze(&path, analyzer, buckets)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Ok(content) = fs::read_to_string(&path) {
                buckets.auth_gaps.extend(analyzer.scan_auth_gaps(&content));
                buckets.panics.extend(analyzer.scan_panics(&content));
                buckets
                    .arithmetic_issues
                    .extend(analyzer.scan_arithmetic_overflow(&content));
                buckets
                    .unsafe_patterns
                    .extend(analyzer.analyze_unsafe_patterns(&content));
                buckets
                    .size_warnings
                    .extend(analyzer.analyze_ledger_size(&content));
                buckets
                    .collisions
                    .extend(analyzer.scan_storage_collisions(&content));
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
