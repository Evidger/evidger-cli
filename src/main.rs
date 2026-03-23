mod cli;
mod engine;
mod errors;
mod format;
mod glob;
mod json;
mod models;
mod registry;

use clap::Parser;
use cli::commands::{Cli, Command};
use errors::{EvidgerError, Result};

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            if e.exit_code() == 0 {
                e.exit();
            }
            eprintln!("{}", EvidgerError::CliArgument(e.to_string()));
            std::process::exit(e.exit_code());
        }
    };

    if let Err(e) = run(cli) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let Cli { command, output: output_path } = cli;
    match command {
        Command::Check { files } => {
            let files = glob::expand(&files)?;
            let mut had_error = false;

            for file in &files {
                match engine::check::check_file(file) {
                    Ok(result) if result.is_valid() => {
                        println!("[OK] {} ({})", result.path, result.format);
                    }
                    Ok(result) => {
                        had_error = true;
                        eprintln!("[E0003] {} ({}):", result.path, result.format);
                        for f in &result.failures {
                            let loc = if f.instance_path.is_empty() {
                                "(root)".to_string()
                            } else {
                                f.instance_path.clone()
                            };
                            eprintln!("  - [{}] {}", loc, f.message);
                        }
                    }
                    Err(e) => {
                        had_error = true;
                        eprintln!("{e}");
                    }
                }
            }

            if had_error {
                std::process::exit(1);
            }
            Ok(())
        }

        Command::Diff { file_a, file_b } => {
            let result = engine::diff::diff_files(&file_a, &file_b)?;

            if result.is_identical() {
                println!("identical: no differences found");
                return Ok(());
            }

            use engine::diff::{ComponentChange, VulnerabilityChange};
            for c in &result.component_changes {
                match c {
                    ComponentChange::Added(comp) => println!(
                        "+ component  {}{}",
                        comp.name,
                        comp.version.as_deref().map(|v| format!("@{v}")).unwrap_or_default()
                    ),
                    ComponentChange::Removed(comp) => println!(
                        "- component  {}{}",
                        comp.name,
                        comp.version.as_deref().map(|v| format!("@{v}")).unwrap_or_default()
                    ),
                    ComponentChange::VersionChanged { name, from, to } => println!(
                        "~ component  {name}  {} -> {}",
                        from.as_deref().unwrap_or("<none>"),
                        to.as_deref().unwrap_or("<none>")
                    ),
                }
            }
            for v in &result.vulnerability_changes {
                match v {
                    VulnerabilityChange::Added(id) => println!("+ vulnerability  {id}"),
                    VulnerabilityChange::Removed(id) => println!("- vulnerability  {id}"),
                    VulnerabilityChange::StatusChanged { id, from, to } => {
                        println!("~ vulnerability  {id}  status: {from} -> {to}")
                    }
                    VulnerabilityChange::JustificationChanged { id, from, to } => println!(
                        "~ vulnerability  {id}  justification: {} -> {}",
                        from.as_deref().unwrap_or("<none>"),
                        to.as_deref().unwrap_or("<none>")
                    ),
                    VulnerabilityChange::ImpactStatementChanged { id, from, to } => println!(
                        "~ vulnerability  {id}  impact: {} -> {}",
                        from.as_deref().unwrap_or("<none>"),
                        to.as_deref().unwrap_or("<none>")
                    ),
                    VulnerabilityChange::ActionStatementChanged { id, from, to } => println!(
                        "~ vulnerability  {id}  action: {} -> {}",
                        from.as_deref().unwrap_or("<none>"),
                        to.as_deref().unwrap_or("<none>")
                    ),
                }
            }
            Ok(())
        }

        Command::Merge { files } => {
            let files = glob::expand(&files)?;
            if files.len() < 2 {
                return Err(EvidgerError::CliArgument(
                    "merge requires at least two files after glob expansion".to_string(),
                ));
            }

            let result = engine::merge::merge_files(&files)?;

            for c in &result.conflicts {
                eprintln!(
                    "conflict: {}  kept from {}  (overrides {})",
                    c.id, c.kept_from, c.overridden_from
                );
            }

            let json_val = format::serialize_document(&result.document);
            let output_str = serde_json::to_string_pretty(&json_val)?;

            match output_path {
                Some(path) => {
                    std::fs::write(&path, &output_str)?;
                    println!(
                        "merged {} sources → {}",
                        result.sources.len(),
                        path.display()
                    );
                }
                None => println!("{output_str}"),
            }
            Ok(())
        }

        Command::Convert { file, to } => {
            let json_val = engine::convert::convert_file(&file, &to)?;
            let output_str = serde_json::to_string_pretty(&json_val)?;
            match output_path {
                Some(path) => {
                    std::fs::write(&path, &output_str)?;
                    println!("converted {} → {} ({})", file.display(), path.display(), to);
                }
                None => println!("{output_str}"),
            }
            Ok(())
        }

        Command::Report { file, vex, minify } => {
            let out = engine::report::generate_report(&file, vex.as_deref(), output_path.as_deref(), minify)?;
            println!("report generated → {}", out.display());
            Ok(())
        }
    }
}
