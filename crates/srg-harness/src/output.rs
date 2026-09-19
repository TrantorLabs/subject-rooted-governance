//! 原始结果、审计轨迹和论文表格的机械导出。
use crate::scenarios::{Baseline, ScenarioRun};
use sha2::{Digest, Sha256};
use srg_core::*;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
pub type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;
fn save<T: serde::Serialize>(path: &Path, value: &T) -> AnyResult<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
pub fn source_fingerprint(root: &Path) -> AnyResult<String> {
    fn walk(p: &Path, root: &Path, v: &mut Vec<PathBuf>) -> std::io::Result<()> {
        for x in fs::read_dir(p)? {
            let x = x?;
            let path = x.path();
            let name = x.file_name();
            let n = name.to_string_lossy();
            if [
                "target",
                "results",
                ".git",
                ".tools",
                "FILE_MANIFEST.sha256.json",
                "VERIFICATION.md",
            ]
            .contains(&n.as_ref())
            {
                continue;
            }
            if path.is_dir() {
                walk(&path, root, v)?
            } else if path.is_file() {
                v.push(path.strip_prefix(root).unwrap().to_owned());
            }
        }
        Ok(())
    }
    let mut files = vec![];
    walk(root, root, &mut files)?;
    files.sort();
    let mut h = Sha256::new();
    for p in files {
        h.update(p.to_string_lossy().as_bytes());
        h.update([0]);
        h.update(fs::read(root.join(p))?);
        h.update([0]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn cmd(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|x| x.status.success())
        .map(|x| String::from_utf8_lossy(&x.stdout).trim().to_string())
}
pub fn write_run(out: &Path, r: &ScenarioRun) -> AnyResult<()> {
    let base = format!("{:?}", r.baseline);
    save(
        &out.join("raw/scenarios")
            .join(&base)
            .join(format!("{}.json", r.scenario_id)),
        r,
    )?;
    save(
        &out.join("traces")
            .join(&base)
            .join(format!("{}.json", r.scenario_id)),
        &r.trace,
    )?;
    save(
        &out.join("evidence")
            .join(&base)
            .join(format!("{}.json", r.scenario_id)),
        &r.evidence,
    )?;
    Ok(())
}
pub fn write_manifest(out: &Path, root: &Path) -> AnyResult<()> {
    let hash = |p: &Path| fs::read(p).ok().map(|b| format!("{:x}", Sha256::digest(b)));
    save(
        &out.join("manifests/run_manifest.json"),
        &serde_json::json!({"artifact_version":env!("CARGO_PKG_VERSION"),"source_sha256":source_fingerprint(root)?,"cargo_lock_sha256":hash(&root.join("Cargo.lock")),"rustc":cmd("rustc",&["--version","--verbose"]),"git_commit":cmd("git",&["rev-parse","HEAD"]),"git_dirty":cmd("git",&["status","--porcelain"]).map(|s|!s.is_empty()),"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"contract":"ReferenceContractV1","scenario_registry":"S00-S19-v1","identity_provider":"deterministic","soulauth_live":"NOT_RUN","formal_core_sha256":hash(&root.join("formal/P2_Core.tla")),"formal_observability_sha256":hash(&root.join("formal/P2_Observability.tla")),"timestamp_unix":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()}),
    )
}
pub fn label(v: &CheckOutcome<PropertyVerdict>) -> &'static str {
    match v {
        CheckOutcome::NotApplicable { .. } => "N/A",
        CheckOutcome::Evaluated(PropertyVerdict::Satisfied) => "SATISFIED",
        CheckOutcome::Evaluated(PropertyVerdict::Violated) => "VIOLATED",
        CheckOutcome::Evaluated(PropertyVerdict::Unadjudicable) => "UNADJUDICABLE",
        CheckOutcome::Evaluated(PropertyVerdict::EvidenceConflict) => "EVIDENCE_CONFLICT",
    }
}
pub fn accountability_label(v: &CheckOutcome<AccountabilityVerdict>) -> &'static str {
    match v {
        CheckOutcome::NotApplicable { .. } => "N/A",
        CheckOutcome::Evaluated(AccountabilityVerdict::Closed) => "CLOSED",
        CheckOutcome::Evaluated(AccountabilityVerdict::Unadjudicable) => "UNADJUDICABLE",
        CheckOutcome::Evaluated(AccountabilityVerdict::ConfirmedRbh) => "CONFIRMED_RBH",
        CheckOutcome::Evaluated(AccountabilityVerdict::EvidenceConflict) => "EVIDENCE_CONFLICT",
    }
}
fn cell(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}
pub fn tables(out: &Path) -> AnyResult<usize> {
    let mut runs = vec![];
    let raw = out.join("raw/scenarios");
    if !raw.exists() {
        return Err("no raw results; `tables` does not silently re-run the experiments".into());
    }
    for b in fs::read_dir(raw)? {
        let b = b?.path();
        if !b.is_dir() {
            continue;
        }
        for f in fs::read_dir(b)? {
            let p = f?.path();
            if p.extension().and_then(|x| x.to_str()) == Some("json") {
                runs.push(serde_json::from_slice::<ScenarioRun>(&fs::read(p)?)?)
            }
        }
    }
    runs.sort_by_key(|r| (format!("{:?}", r.baseline), r.scenario_id.clone()));
    let mut text="baseline,scenario,description,G1,G2,G3,G4,G5,G6,O1,O2,O3,accountability,expectation_matched,eligible_progress\n".to_string();
    for r in &runs {
        let mut row = vec![
            format!("{:?}", r.baseline),
            r.scenario_id.clone(),
            cell(&r.description),
        ];
        for k in ["G1", "G2", "G3", "G4", "G5", "G6", "O1", "O2", "O3"] {
            row.push(label(&r.reports.properties[k].outcome).into())
        }
        row.push(accountability_label(&r.reports.accountability.outcome).into());
        row.push(if matches!(r.baseline, Baseline::B2 | Baseline::B3) {
            r.expectation_matched.to_string()
        } else {
            "N/A-reference-expectation".into()
        });
        row.push(
            r.eligible_progress
                .map(|x| x.to_string())
                .unwrap_or("N/A".into()),
        );
        text.push_str(&row.join(","));
        text.push('\n')
    }
    fs::create_dir_all(out.join("tables"))?;
    fs::write(out.join("tables/scenario_matrix.csv"), &text)?;
    fs::write(out.join("tables/baseline_matrix.csv"), &text)?;
    let mut ab = "scenario,primary_property,observed_property_verdict,test_expectation_matched\n"
        .to_string();
    let mut rb = "scenario,accountability_verdict,test_expectation_matched\n".to_string();
    for r in &runs {
        if r.baseline != Baseline::B3 {
            continue;
        }
        if let Some(p) = &r.expected_property {
            ab.push_str(&format!(
                "{},{},{},{}\n",
                r.scenario_id,
                p,
                label(&r.reports.properties[p].outcome),
                r.expectation_matched
            ))
        }
        if r.expected_accountability.is_some() {
            rb.push_str(&format!(
                "{},{},{}\n",
                r.scenario_id,
                accountability_label(&r.reports.accountability.outcome),
                r.expectation_matched
            ))
        }
    }
    fs::write(out.join("tables/g_ablation_matrix.csv"), ab)?;
    fs::write(out.join("tables/rbh_matrix.csv"), rb)?;
    let failures: Vec<_> = runs
        .iter()
        .filter(|r| r.baseline == Baseline::B3 && !r.expectation_matched)
        .map(|r| r.scenario_id.clone())
        .collect();
    save(
        &out.join("summary.json"),
        &serde_json::json!({"records":runs.len(),"b3_scenarios":runs.iter().filter(|r|r.baseline==Baseline::B3).count(),"b3_unexpected":failures,"property_violation_is_not_test_failure":true,"probabilistic_safety_rate":null}),
    )?;
    Ok(runs.len())
}
