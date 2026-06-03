mod parser;

use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use ars_format::ArsBuilder;
use clap::{Parser, Subcommand, ArgEnum};
use tracing::info;

#[derive(Parser)]
#[clap(name = "ars-convert", about = "Convert rule lists to .ars binary format", version)]
struct Cli {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Convert rule file(s) to .ars
    Convert {
        #[clap(required = true)]
        inputs: Vec<PathBuf>,
        #[clap(short, long, default_value = "output.ars")]
        output: PathBuf,
        #[clap(long, arg_enum)]
        format: Option<InputFormat>,
        #[clap(long)]
        description: Option<String>,
        #[clap(long)]
        no_compress: bool,
    },
    /// Show metadata from an .ars file
    Info { file: PathBuf },
}

#[derive(Clone, ArgEnum, Debug)]
enum InputFormat { Adguard, Mihomo, Domains }

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("ars_convert=info".parse()?))
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Convert { inputs, output, format, description, no_compress } =>
            cmd_convert(inputs, output, format, description, no_compress),
        Cmd::Info { file } => cmd_info(file),
    }
}

fn cmd_convert(
    inputs: Vec<PathBuf>, output: PathBuf,
    format_hint: Option<InputFormat>, _description: Option<String>, no_compress: bool,
) -> Result<()> {
    let mut builder = ArsBuilder::new();
    if no_compress {
        builder = builder.with_compression(ars_format::format::Compression::None);
    }

    let mut total = 0usize;
    for input in &inputs {
        let content = std::fs::read_to_string(input)
            .with_context(|| format!("Reading {}", input.display()))?;
        let fmt = format_hint.clone()
            .unwrap_or_else(|| detect_format(input, &content));
        info!(file = %input.display(), format = ?fmt, "Parsing");
        let rules = match fmt {
            InputFormat::Adguard => parser::parse_adguard(&content),
            InputFormat::Mihomo  => parser::parse_mihomo(&content)?,
            InputFormat::Domains => parser::parse_domain_list(&content),
        };
        info!(file = %input.display(), rules = rules.len(), "Parsed");
        total += rules.len();
        builder.add_rules(rules.into_iter().map(|mut r| {
            r.source = Some(input.file_name().unwrap().to_string_lossy().to_string());
            r
        }));
    }
    info!(total = total, "Total rules before dedup");

    let mut out = std::fs::File::create(&output)
        .with_context(|| format!("Creating {}", output.display()))?;
    let meta = builder.build(&mut out)?;
    println!("✓ {} rules → {}", meta.rule_counts.total(), output.display());
    println!("  block: exact={} suffix={} keyword={} regex={}",
        meta.rule_counts.block_exact, meta.rule_counts.block_suffix,
        meta.rule_counts.block_keyword, meta.rule_counts.block_regex);
    println!("  allow: exact={} suffix={}",
        meta.rule_counts.allow_exact, meta.rule_counts.allow_suffix);
    Ok(())
}

fn cmd_info(file: PathBuf) -> Result<()> {
    let reader = ars_format::ArsReader::from_file(&file)?;
    let m = &reader.metadata;
    let c = &m.rule_counts;
    println!("File:    {}", file.display());
    println!("Created: {}", m.created_at);
    if let Some(d) = &m.description { println!("Desc:    {d}"); }
    println!("Total:   {}", c.total());
    println!("  Block  exact={} suffix={} keyword={} regex={}",
        c.block_exact, c.block_suffix, c.block_keyword, c.block_regex);
    println!("  Allow  exact={} suffix={} keyword={} regex={}",
        c.allow_exact, c.allow_suffix, c.allow_keyword, c.allow_regex);
    println!("  Rewrite: {}", c.rewrite);
    Ok(())
}

fn detect_format(path: &Path, content: &str) -> InputFormat {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    match ext.as_str() {
        "yaml" | "yml" => InputFormat::Mihomo,
        _ if content.contains("||") || content.contains("@@") => InputFormat::Adguard,
        _ if content.contains("payload:") => InputFormat::Mihomo,
        _ => InputFormat::Domains,
    }
}
