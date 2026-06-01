use clap::{Parser, Subcommand};

mod commands;
mod logging;
mod vulndb;

#[derive(Parser)]
#[command(
    name = "sanctifier",
    version,
    about = "Soroban smart contract security analyzer"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a Soroban contract directory or file
    Analyze(commands::analyze::AnalyzeArgs),
    /// Initialize a .sanctify.toml configuration file
    Init(commands::init::InitArgs),
    /// Language Server Protocol (LSP) for editor integration
    Lsp(commands::lsp::LspArgs),
    /// Generate a security report
    Report(commands::report::ReportArgs),
}

fn main() {
    let _ = logging::init(logging::LogOutput::Text);

    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Analyze(args) => commands::analyze::exec(args),
        Commands::Init(args) => commands::init::exec(args, None),
        Commands::Lsp(args) => commands::lsp::exec(args),
        Commands::Report(args) => commands::report::exec(args),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
