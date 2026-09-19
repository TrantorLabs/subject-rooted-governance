use clap::{Parser, Subcommand};
use srg_harness::{
    output,
    scenarios::{self, Baseline},
};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "Subject-Rooted Governance research harness: raw evidence, independent verdicts, reproducible tables"
)]
struct Cli {
    #[arg(long, global = true, default_value = "results")]
    out: PathBuf,
    #[command(subcommand)]
    command: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    RunAll,
    Run {
        scenario: String,
        #[arg(long, default_value = "B3")]
        baseline: String,
    },
    Suite {
        name: String,
    },
    Tables,
    Audit {
        file: PathBuf,
    },
}
fn main() {
    if let Err(e) = execute() {
        eprintln!("error: {e}");
        std::process::exit(1)
    }
}
fn execute() -> output::AnyResult<()> {
    let cli = Cli::parse();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    match cli.command {
        Cmd::RunAll => {
            let mut unexpected = vec![];
            for b in [Baseline::B0, Baseline::B1, Baseline::B2, Baseline::B3] {
                for n in 0..20 {
                    let r = scenarios::run(n, b)?;
                    if matches!(b, Baseline::B2 | Baseline::B3) && !r.expectation_matched {
                        unexpected.push(format!("{b:?}/{}", r.scenario_id))
                    }
                    output::write_run(&cli.out, &r)?
                }
            }
            output::tables(&cli.out)?;
            srg_harness::composition::run(&cli.out)?;
            output::write_manifest(&cli.out, &root)?;
            println!(
                "raw records written for 20 scenarios x 4 baselines; expectation mismatches: {}",
                unexpected.len()
            );
            if !unexpected.is_empty() {
                return Err(format!("{:?}", unexpected).into());
            }
        }
        Cmd::Run { scenario, baseline } => {
            let n: usize = scenario
                .strip_prefix('S')
                .ok_or("scenario must look like S12")?
                .parse()?;
            let b = Baseline::parse(&baseline).ok_or("baseline must be one of B0/B1/B2/B3")?;
            let r = scenarios::run(n, b)?;
            output::write_run(&cli.out, &r)?;
            println!(
                "{} {} expectation_matched={}\n{}",
                r.scenario_id,
                r.description,
                r.expectation_matched,
                serde_json::to_string_pretty(&r.reports)?
            );
        }
        Cmd::Suite { name } => {
            if name == "p4" {
                srg_harness::composition::run(&cli.out)?;
                println!("P4 bounded composition evidence written");
                return Ok(());
            }
            let ns: Vec<usize> = match name.as_str() {
                "rbh" => (16..20).collect(),
                _ => return Err("suite must be rbh or p4".into()),
            };
            for n in ns {
                let r = scenarios::run(n, Baseline::B3)?;
                output::write_run(&cli.out, &r)?;
                if !r.expectation_matched {
                    return Err(format!("{}: expectation not matched", r.scenario_id).into());
                }
                println!("{}: expectation matched", r.scenario_id)
            }
        }
        Cmd::Tables => {
            println!(
                "tables generated from {} raw records",
                output::tables(&cli.out)?
            );
        }
        Cmd::Audit { file } => {
            let r: scenarios::ScenarioRun = serde_json::from_slice(&std::fs::read(file)?)?;
            let observed = srg_harness::checker::check_all(&r.evidence, &r.contract, &r.query);
            if observed != r.reports {
                return Err("re-check disagrees with the archived verdicts".into());
            }
            println!("archived evidence re-checks identically; fault/expected/truth were not read");
        }
    }
    Ok(())
}
