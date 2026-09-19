use std::{fs, path::PathBuf};
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or("all".into());
    let mut out = PathBuf::from("results/raw/explorer");
    while let Some(a) = args.next() {
        if a == "--out" {
            out = PathBuf::from(args.next().ok_or("missing output directory")?)
        } else {
            return Err(format!("unknown argument {a}").into());
        }
    }
    fs::create_dir_all(&out)?;
    match mode.as_str() {
        "p1" | "p2" => {
            let hist = mode == "p2";
            let weak = srg_explorer::collisions(hist, false);
            let strong = srg_explorer::collisions(hist, true);
            fs::write(
                out.join(format!("{mode}.json")),
                serde_json::to_vec_pretty(
                    &serde_json::json!({"weak_collisions":weak,"strong_collisions":strong,"worlds":srg_explorer::worlds(),"scope":"fixed finite-world instance; not a general theorem proof"}),
                )?,
            )?;
            println!(
                "{mode}: weak-observation collisions {}, strengthened-observation collisions {}",
                weak.len(),
                strong.len()
            );
            if weak.is_empty() || !strong.is_empty() {
                return Err("collision verification did not match expectation".into());
            }
        }
        "core" | "all" => {
            let results = srg_explorer::all_searches();
            for r in &results {
                println!(
                    "{:?}: {} states, {} properties with counterexamples",
                    r.mutation,
                    r.states,
                    r.violations.len()
                )
            }
            fs::write(out.join("core.json"), serde_json::to_vec_pretty(&results)?)?;
            if !results[0].violations.is_empty()
                || results.iter().skip(1).any(|r| r.violations.is_empty())
            {
                return Err("finite-model verification failed".into());
            }
            if mode == "all" {
                for (name, hist) in [("p1", false), ("p2", true)] {
                    fs::write(
                        out.join(format!("{name}.json")),
                        serde_json::to_vec_pretty(
                            &serde_json::json!({"weak_collisions":srg_explorer::collisions(hist,false),"strong_collisions":srg_explorer::collisions(hist,true)}),
                        )?,
                    )?;
                }
            }
        }
        _ => return Err("usage: srg-explorer p1|p2|core|all [--out DIR]".into()),
    }
    Ok(())
}
