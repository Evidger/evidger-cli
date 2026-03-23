use crate::registry::Format;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "evidger", about = "SBOM and VEX document processing tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Write output to file instead of stdout
    #[arg(short = 'o', long, global = true, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Validate one or more JSON files against their schema
    Check {
        /// JSON files to validate
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,
    },

    /// Show differences between two JSON files
    Diff {
        /// First file
        #[arg(value_name = "FILE_A")]
        file_a: PathBuf,

        /// Second file
        #[arg(value_name = "FILE_B")]
        file_b: PathBuf,
    },

    /// Merge two or more JSON files into one (glob patterns accepted)
    Merge {
        /// Files or glob patterns to merge (at least two required after expansion)
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,
    },

    /// Convert a document to a different format
    Convert {
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Target output format (cyclonedx, spdx, openvex, csaf)
        #[arg(long, value_name = "FORMAT")]
        to: Format,
    },

    /// Generate a summary report for a JSON file
    Report {
        /// SBOM or VEX JSON file to report on
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// VEX file to correlate with the SBOM (produces a correlated report)
        #[arg(long, value_name = "VEX_FILE")]
        vex: Option<PathBuf>,
        /// Minify the HTML output
        #[arg(long)]
        minify: bool,
    },
}
