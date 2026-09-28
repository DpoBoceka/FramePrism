//! The run entry points (the two bin dispatch targets):
//! `run_audit` (the fast integrity pass — the discovery-driven
//! surface set: the sidecar audit + the object-sha sidecars +
//! the clip subdirs + the ingest / offload / MHL / reel record
//! arms + the ops-ledger row) + `run_restore` (the repair —
//! the master arbiter, the atomic swap, the root-boundary
//! guard + the durability seam).

use std::process::ExitCode;

use crate::jxl;
use super::model::{AuditArgs, Offender, RestoreArgs, SidecarReport};
use super::records::{
    audit_ingest_manifests, audit_offload_manifests,
    discover_ingest_manifests, discover_members_records,
    discover_offload_mirror_manifests, is_no_sidecar_error,
};
use super::sidecars::{
    ObjectShaAudit, audit_dir, audit_object_sha,
    discover_clip_subdirs, discover_object_sha_sidecars, print_reports,
};

/// `frameprism audit` — the fast integrity pass. rc=0 clean, rc=1
/// offenders, rc=2 usage. A COMPLETED audit appends the ops-ledger row
/// (command=audit, verdict OK/FAIL — the A3 rotation report's input);
/// the usage-class rc=2s below append nothing (no run completed).
pub fn run_audit(args: &AuditArgs) -> ExitCode {
    let t0 = std::time::Instant::now();
    let input = &args.input;
    if !input.is_dir() {
        eprintln!("error: input is not a directory: {}", input.display());
        return ExitCode::from(2);
    }
    // The --eject gate's precondition (the usage-class refusal — the
    // eject is the CARD verdict's additive action: no verdict exists
    // without a source, so no eject does either — named, rc=2;
    // documented in the flag's help).
    if args.eject && args.source.is_none() {
        eprintln!(
            "error: --eject requires --source (a CARD verdict does not exist without a source — the eject gate is the audit's CARD verdict)"
        );
        return ExitCode::from(2);
    }
    // The ingest-continuity surface: present
    // when the dir carries a `*.ingest-manifest.tsv` record. A dir
    // without one keeps the existing sidecar-only behavior
    // byte-identical (incl. the no-sidecar rc=2).
    let has_ingest = !discover_ingest_manifests(input).is_empty();
    // The standalone offload re-verify surface: present when the
    // dir carries a `*.offload-manifest.tsv` record (top level OR
    // one level deep — the mirrored clip roots, the standalone
    // `offload` mirror's shape). A dir without one keeps the
    // existing sidecar-only behavior byte-identical (R-INV).
    let has_offload = !discover_offload_mirror_manifests(input).is_empty();
    // B6: a tree carrying object sha sidecars is auditable
    // THROUGH the sidecars — a flipped/moved object is the NAMED
    // OFFENDER (rc=1), so a bake-manifest sweep error in such a tree
    // degrades to the offender class (the object's bytes are already
    // proven wrong by the sidecar). A pre-B6 tree (no .sha256
    // sidecars) keeps the EXISTING rc=2 sweep error (R-INV).
    let b6_shas: Option<Vec<ObjectShaAudit>> =
        if discover_object_sha_sidecars(input).is_empty() {
            None
        } else {
            Some(
                discover_object_sha_sidecars(input)
                    .iter()
                    .map(|p| audit_object_sha(input, p))
                    .collect(),
            )
        };
    // B5: the reel-manifest detection —
    // <input>/reel.reel-manifest.tsv present = the reel audit surface
    // (the tree-bake out dir, the --iso mount): the per-row archive +
    // per-clip manifest re-verify (the offenders NAMED as clip +
    // object) + the existing clip surfaces + the reel verdict line.
    // A malformed manifest = the named hard rc=2 (the usage contract —
    // the record is untrustable, exactly like a bad sidecar).
    // The MHL re-verify surface's detection (the ascmhl
    // read side): the `ascmhl/` history dir's PRESENCE (the
    // write side's placement — the scope's top level). Absent = the
    // arm is inert (the pre-existing audit, byte-identical — the R-INV).
    let has_mhl = input.join(crate::ascmhl::ASCMHL_DIR_NAME).is_dir();
    let reel_path = input.join(crate::reel::REEL_MANIFEST_NAME);
    let (reel_m, reel_offenders) = if reel_path.is_file() {
        match crate::reel::parse(&reel_path) {
            Ok(m) => {
                let off = crate::reel::check_rows(&m, input);
                for (clip, object, problem) in &off {
                    println!("FAIL clip {clip}: {object} — {problem}");
                }
                (Some(m), off)
            }
            Err(err) => {
                eprintln!("error: audit (reel manifest): {err}");
                return ExitCode::from(2);
            }
        }
    } else {
        (None, Vec::new())
    };
    let sidecar_result = audit_dir(input, args.jobs, true);
    // The recursive clip-dir surface (B5) — consulted ONLY when the
    // root has no archive sidecar (the tree shape: the per-clip
    // sidecars live in the clip subdirs). A root-sidecar dir takes the
    // existing path byte-identical (R-INV).
    let mut clip_sections: Vec<(String, Vec<SidecarReport>, Vec<ObjectShaAudit>)> =
        Vec::new();
    // The standalone offload branch's fired flag (the arm below sets
    // it — the offload sweep's discovery depth + the surface's
    // verdict line key off it).
    let mut offload_standalone = false;
    let (reports, object_shas, sweep_error) = match &sidecar_result {
        Ok(r) => (Some(&r.0), Some(&r.1), None),
        Err(err) if has_ingest && is_no_sidecar_error(err) => {
            // An ingest-manifest-only dir (the two-destination /
            // source-dir shape — the flow): no archive
            // sidecar to sweep; the ingest record is audited on its
            // own (rc from the re-derivation). A dir with NEITHER an
            // ingest manifest nor a sidecar keeps the rc=2 below.
            eprintln!(
                "note: no archive sidecar in {} — auditing the ingest-continuity record only",
                input.display()
            );
            (None, None, None)
        }
        Err(err) if has_offload && is_no_sidecar_error(err) => {
            // The standalone offload mirror (the verified-copy
            // shape: the per-clip offload records + the mirrored
            // files, NO archive sidecar): no archive sidecar to
            // sweep; the offload records are re-verified on their
            // own (rc from the sweep — ALL records, never stopping at
            // the first offender). A dir with NEITHER an offload
            // record nor a sidecar keeps the rc=2 below.
            offload_standalone = true;
            eprintln!(
                "note: no archive sidecar in {} — auditing the offload re-verify record only",
                input.display()
            );
            (None, None, None)
        }
        Err(err) if is_no_sidecar_error(err) => {
            // The no-sidecar-at-root dir: the recursive audit (the
            // per-clip sidecars in the clip subdirs) — and/or, on a
            // reel-manifest tree, the reel rows are the surface (a
            // named note; the reel verdict decides rc); and/or, the ascmhl/ history is the MHL re-verify surface
            // (the offload-carve-out's exact shape, the MHL
            // phrasing — the import fact: a foreign tool's scope may
            // carry ONLY its ascmhl history). Neither = the
            // existing rc=2 below.
            clip_sections = discover_clip_subdirs(input, args.jobs);
            if !clip_sections.is_empty() || reel_m.is_some() {
                let mut what = String::new();
                if reel_m.is_some() {
                    what.push_str("the reel manifest rows");
                }
                if !clip_sections.is_empty() {
                    if !what.is_empty() {
                        what.push_str(" + ");
                    }
                    what.push_str(&format!(
                        "the {} clip subdir(s) (recursive)",
                        clip_sections.len()
                    ));
                }
                eprintln!(
                    "note: no archive sidecar in {} — auditing {}",
                    input.display(),
                    what
                );
                (None, None, None)
            } else if has_mhl {
                // The MHL-only dir (the ascmhl read side):
                // no archive sidecar, but the ascmhl/ history is the
                // surface (the MHL arm below decides the rc — a
                // clean re-verify = rc=0, the named note).
                eprintln!(
                    "note: no archive sidecar in {} — auditing the MHL re-verify record only",
                    input.display()
                );
                (None, None, None)
            } else {
                eprintln!("error: audit: {err}");
                return ExitCode::from(2);
            }
        }
        Err(err) if b6_shas.is_some() => {
            eprintln!(
                "note: audit: the sidecar sweep aborted ({err}) — the B6 object-sha verdicts stand (the flipped/moved object is the named offender, rc=1; pre-B6 trees keep the rc=2)"
            );
            (None, b6_shas.as_ref(), Some(err))
        }
        Err(_) => {
            if let Err(err) = &sidecar_result {
                eprintln!("error: audit: {err}");
            }
            return ExitCode::from(2);
        }
    };
    let sweep_offenders: Vec<String> = match sweep_error {
        Some(err) => vec![format!("sidecar sweep — {err}")],
        None => Vec::new(),
    };
    let mut bad: usize = reports
        .map(|rs| rs.iter().map(|r| r.offenders.len()).sum())
        .unwrap_or(0)
        + object_shas
            .map(|os| os.iter().filter(|o| o.problem.is_some()).count())
            .unwrap_or(0)
        + sweep_offenders.len()
        + clip_sections
            .iter()
            .map(|(_, rs, os)| {
                rs.iter().map(|r| r.offenders.len()).sum::<usize>()
                    + os.iter().filter(|o| o.problem.is_some()).count()
            })
            .sum::<usize>()
        + reel_offenders.len();
    match (reports, object_shas) {
        (Some(rs), Some(os)) => print_reports(rs, os),
        (Some(rs), None) => print_reports(rs, &[]),
        (None, Some(os)) => print_reports(&[], os),
        (None, None) => {}
    }
    // B5: the per-clip clip-dir sections (the recursive audit — no
    // root sidecar; the reel audit's clip dirs when present): the
    // existing per-sidecar lines under the clip heading (one section
    // per clip; the single reel verdict line lands at the end).
    for (key, rs, os) in &clip_sections {
        println!("audit: clip {key} (recursive):");
        print_reports(rs, os);
    }
    for line in &sweep_offenders {
        println!("FAIL {line}");
    }
    if has_ingest {
        match audit_ingest_manifests(input) {
            Ok(Some(res)) => {
                for line in &res.lines {
                    println!("{line}");
                }
                bad += res.bad;
            }
            Ok(None) => {
                unreachable!("ingest manifests were discovered above")
            }
            Err(err) => {
                eprintln!("error: audit (ingest continuity): {err}");
                return ExitCode::from(2);
            }
        }
    }
    // The offload re-verify surface (the re-audit/verify path):
    // re-read every row's DEST file against the recorded size + the
    // canonical source sha256 — a post-run dest corruption (or a
    // vanished dest file/dir) is named on that row (rc=1 — the audit
    // philosophy: loud, named, no silent skip). The encode-side
    // shape (a sidecar-carrying dir) sweeps the top-level record(s)
    // only — the pre-existing discovery, the pre-existing lines, UNCHANGED
    // (R-INV); the standalone mirror branch (the no-sidecar dir
    // carrying the records) sweeps the two-level discovery (root +
    // the mirrored clip roots) + lands the surface's verdict line.
    // A bad manifest (parse) is a hard named rc=2 (the usage
    // contract).
    match audit_offload_manifests(input, offload_standalone) {
        Ok(Some(res)) => {
            for line in &res.lines {
                println!("{line}");
            }
            bad += res.bad;
        }
        Ok(None) => {
            // No offload record in the dir — nothing to print (the
            // existing sidecar-only output + rc stand unchanged).
        }
        Err(err) => {
            eprintln!("error: audit (offload): {err}");
            return ExitCode::from(2);
        }
    }
    // The member record surface: present
    // when the dir carries a `*.members.tsv` record (the clip's non-
    // frame members — the additive next-to record, the v3 sidecar's
    // sibling). The re-audit/verify path: re-read every row's file
    // (resolved CLIP-RELATIVE against the tree the record lives in —
    // path-independent: the rows are clip-relative + the record sits
    // at the tree root next to the clip dir, so a MOVE of the whole
    // tree keeps the record verifiable) against the recorded size +
    // sha256 — a post-run member corruption (or a vanished file) is
    // named on that row (rc=1 — the audit philosophy: loud, named, no
    // silent skip). A bad record (parse) is a hard named rc=2 (the
    // usage contract, the offload-manifest convention).
    for p in discover_members_records(input) {
        let m = match crate::report::parse_members_record(&p) {
            Ok(m) => m,
            Err(err) => {
                eprintln!("error: audit (members): {err}");
                return ExitCode::from(2);
            }
        };
        let (lines, bad_members) = crate::report::reverify_members(&m, input);
        for line in &lines {
            println!("{line}");
        }
        bad += bad_members;
    }
    // The MHL re-verify surface (the ascmhl read side):
    // the latest manifest (the chain's last record — the
    // single-manifest no-chain carve-out — the named refusals
    // otherwise) is RE-VERIFIED against the scope: the per-file
    // C4ID recompute (the size pre-filter; the offload row
    // vocabulary — a post-run dest corruption, a vanished file, or a
    // resized file is named on its row — rc=1, the audit philosophy:
    // loud, named, no silent skip) + the roothash seal (the content
    // + structure over the WHOLE scope with the MANIFEST'S OWN
    // ignore patterns — the import fact: a foreign tool's record
    // verifies against its own values; the unrecorded ADDED file
    // keeps the sweep clean + breaks the roothash — its named
    // catch). A malformed record (the parse + the selection's
    // corrupt classes) = the named hard rc=2 (the B5 posture — the
    // record is untrustable). A dir without ascmhl/ never reaches
    // this arm (the R-INV).
    if has_mhl {
        match crate::ascmhl::audit_mhl(input, args.jobs) {
            Ok(out) => {
                for line in &out.lines {
                    println!("{line}");
                }
                bad += out.offenders;
                println!("{}", out.summary);
            }
            Err(err) => {
                eprintln!("error: audit (mhl): {err}");
                return ExitCode::from(2);
            }
        }
    }
    // The run-report surface (additive): the verdict line of every
    // per-clip + run report present in the dir (the record's echo —
    // the encode-time gate is the verdict's authority; no rc change
    // from this surface, a present-but-corrupt record is named, not
    // skipped).
    for line in crate::report::audit_report_lines(input) {
        println!("{line}");
    }
    //: the signature line (the reel manifest's .sig — the
    // keyless CONTENT CLAIM: the envelope well-formedness + the
    // manifest `manifest_sha256` re-hash; the signature itself is
    // `frameprism verify --key <pubkey>`'s surface). The ABSENT line is
    // the universal honesty line (every audit names the reel
    // manifest's signature state — the signature is OPTIONAL for the
    // audit PASS: pre-signing archives stay valid); VALID-CONTENT /
    // ABSENT leave the verdict untouched; INVALID-CONTENT = the named
    // offender (the audit-side findings ride rc=1 —
    // a broken provenance claim is worse than its absence — the
    // envelope lies), printed with the other named findings BEFORE the
    // reel verdict line (its count includes it).
    let (sig_line, sig_bad) = crate::provenance::audit_signature_line(&reel_path);
    if sig_bad {
        bad += 1;
        println!("{sig_line}");
    }
    // B5: the reel verdict line — the exact wording. Present for
    // the reel-manifest surface (the tree-bake out dir, the --iso
    // mount) and the recursive audit (no reel manifest); the
    // sidecar-only dirs keep the existing per-sidecar lines only.
    if let Some(m) = &reel_m {
        let (n_clips, frames) = (m.rows.len(), m.frames_total());
        if bad == 0 {
            println!(
                "audit: reel {}: {} clip(s), {} frame(s) OK (reel manifest v1)",
                input.display(),
                n_clips,
                frames
            );
        } else {
            println!(
                "audit: reel {}: {} clip(s), {} frame(s) FAIL ({} named offender(s)) (reel manifest v1)",
                input.display(),
                n_clips,
                frames,
                bad
            );
        }
    } else if !clip_sections.is_empty() {
        let frames: usize = clip_sections
            .iter()
            .map(|(_, rs, _)| rs.iter().map(|r| r.rows.len()).sum::<usize>())
            .sum();
        if bad == 0 {
            println!(
                "audit: reel {}: {} clip(s), {} frame(s) OK (recursive — no reel manifest)",
                input.display(),
                clip_sections.len(),
                frames
            );
        } else {
            println!(
                "audit: reel {}: {} clip(s), {} frame(s) FAIL ({} named offender(s)) (recursive — no reel manifest)",
                input.display(),
                clip_sections.len(),
                frames,
                bad
            );
        }
    }
    //: the signature line's informational classes (VALID-
    // CONTENT / ABSENT — the audit verdict is unaffected; the
    // INVALID-CONTENT line already printed with the named findings
    // above the reel verdict line).
    if !sig_bad {
        println!("{sig_line}");
    }
    //: the verify-against-source surface (`--source`): the
    // archive's `<CLIP>.sources.tsv` records re-verified against the
    // LIVE source (the mounted card) + the CARD verdict (the
    // release-gate claim — the tool never wipes the card; the verdict
    // is the human's release). Absent flag = the pre-existing audit,
    // unchanged (no source lines, no CARD line, the OK/FAIL verdicts
    // stand — the byte-identity carve-out). The surface runs AFTER
    // the archive's own surfaces + the reel verdict line (the source
    // rows are a separate surface: a dirty card row is not an archive
    // offender — the archive audit is unaffected), and BEFORE the
    // ledger row (the verdict column carries the CARD outcome).
    let card_class: Option<crate::sourcecheck::CardClass> = match &args.source {
        Some(card_root) => match crate::sourcecheck::audit_sources(input, card_root) {
            Err(err) => {
                // The records-class refusal (a corrupt record / a
                // clip-key mismatch): the named hard rc=2 — ZERO
                // partial verdicts (the usage-class semantics: no
                // ledger row, no CARD line).
                eprintln!("error: audit (sources): {err}");
                return ExitCode::from(2);
            }
            Ok(None) => {
                // The UNVERIFIABLE class (the named honesty line — an
                // unmounted card / a pre-existing archive is NOT a
                // failure of the archive; the rc follows the archive
                // audit result — the human cannot release the card on
                // this audit run).
                let line = if !card_root.is_dir() {
                    format!(
                        "CARD UNVERIFIABLE (the source at {} is absent — the source rows are NOT verified; the archive audit is unaffected)",
                        card_root.display()
                    )
                } else {
                    format!(
                        "CARD UNVERIFIABLE (the source record is absent in {} — the source rows are NOT verified; the archive audit is unaffected)",
                        input.display()
                    )
                };
                println!("{line}");
                Some(crate::sourcecheck::CardClass::Unverifiable)
            }
            Ok(Some(v)) => {
                for line in &v.lines {
                    println!("{line}");
                }
                let (class, line) = crate::sourcecheck::card_verdict(v.verified, v.dirty, bad);
                println!("{line}");
                Some(class)
            }
        },
        None => None,
    };
    //: the --eject surface (the release gate's ADDITIVE action — the
    // eject runs AFTER the CARD verdict line has printed: the
    // verdict's own words stand — the refusal leaves the audit's rc
    // UNCHANGED; only the requested-but-failed eject is the named
    // rc=1 — the requested action did not happen). `--eject` without
    // `--source` is the named rc=2 above (the eject gate IS the
    // verdict), so with `--eject` the class is always present (the
    // records-class Err arm returned rc=2 before the ledger row — a
    // refused record ejects nothing: no verdict exists to gate on).
    let eject_outcome: Option<crate::sourcecheck::EjectOutcome> = if args.eject {
        let class = card_class.expect(
            "internal: --eject implies the CARD class (the rc=2 arms above stand first)",
        );
        let card_root = args
            .source
            .as_ref()
            .expect("internal: --eject implies --source (the named rc=2 refusal above)");
        let eo = crate::sourcecheck::eject_after_verdict(class, card_root);
        println!("{}", eo.line);
        Some(eo)
    } else {
        None
    };
    // The A3 ops-ledger row (the rotation report's input): the
    // completed audit run — OK/FAIL only (the REFUSED_* classes are
    // the run paths'; the usage-class rc=2s above append nothing).
    // A write failure is the named WARN (the audit's verdict is
    // untouched — the journal degrades loudly).
    //: with `--source` the verdict column carries the CARD
    // outcome (the QC_GATE-style additive verdict: CARD_OK /
    // CARD_REFUSED / CARD_UNVERIFIABLE — the verdict column is a
    // free string, the ledger's machinery is unchanged); the audit
    // WITHOUT `--source` keeps the existing OK/FAIL verdicts,
    // unchanged.
    //: with `--eject` the verdict column carries the eject outcome
    // (the additive token: CARD_OK_EJECTED / CARD_OK_EJECT_REFUSED /
    // CARD_OK_EJECT_FAIL / CARD_REFUSED_EJECT_REFUSED /
    // CARD_UNVERIFIABLE_EJECT_REFUSED — the named line above).
    let audit_frames: usize = if let Some(m) = &reel_m {
        // The reel manifest is the canonical frame count for the reel
        // surface (the member-sweep rows re-verify the same frames
        // through the per-clip manifests — no double count).
        m.frames_total() as usize
    } else {
        reports
            .map(|rs| rs.iter().map(|r| r.rows.len()).sum())
            .unwrap_or(0)
            + object_shas.map(|os| os.len()).unwrap_or(0)
            + clip_sections
                .iter()
                .map(|(_, rs, os)| rs.iter().map(|r| r.rows.len()).sum::<usize>() + os.len())
                .sum::<usize>()
    };
    let audit_codec = if let Some(m) = &reel_m {
        // B5: the reel class — the manifest's codec set (single = as
        // is, mixed = '+'-joined, the BakeOutcome convention).
        let codes: std::collections::BTreeSet<String> =
            m.rows.iter().map(|r| r.codec.clone()).collect();
        codes.into_iter().collect::<Vec<String>>().join("+")
    } else if let Some(rs) = reports {
        if !rs.is_empty() {
            let names: Vec<&str> = rs.iter().map(|r| r.sidecar.as_str()).collect();
            if names.iter().any(|n| n.ends_with(".jxl-checksums.tsv")) {
                "jxl".to_string()
            } else if names.iter().any(|n| n.ends_with(".checksums.tsv")) {
                "j92".to_string()
            } else {
                "bake".to_string() // the bake-manifest class only
            }
        } else if object_shas.map(|os| !os.is_empty()).unwrap_or(false) {
            "bake".to_string() // the object-sha sidecars only (the B6 dir)
        } else {
            "-".to_string()
        }
    } else if object_shas.map(|os| !os.is_empty()).unwrap_or(false) {
        // The sweep aborted (the B6 offender path) — the tree carried
        // object-sha sidecars: the bake class.
        "bake".to_string()
    } else {
        "-".to_string() // the ingest-record-only carve-out
    };
    let verdict = match (card_class, &eject_outcome) {
        (Some(_), Some(eo)) => eo.ledger,
        (Some(class), None) => class.ledger_verdict(),
        (None, _) => {
            if bad == 0 {
                "OK"
            } else {
                "FAIL"
            }
        }
    };
    crate::ledger::append_quiet(&crate::ledger::Row {
        created: crate::ledger::now_secs(),
        command: "audit".into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        input: crate::ledger::canon(input),
        output: String::new(),
        codec: audit_codec,
        frames: audit_frames as u64,
        verdict: verdict.into(),
        duration_s: t0.elapsed().as_secs(),
        dest: String::new(),
        // The audit verb has no selection flags (v1 — the encode +
        // bake verbs carry them): the column is always empty here.
        selection: String::new(),
        // The audit verb never runs under --subset (the encode verbs
        // carry the flag): the column is always empty here.
        context: String::new(),
    });
    //: the CARD rc (the audit-side
    // re-derived violations ride rc=1; UNVERIFIABLE follows
    // the archive audit result — an unmounted card is not a
    // failure of the archive): the --eject surface's additive rc
    // effect (the refusal leaves the rc UNCHANGED; only the
    // requested-but-failed eject is the named rc=1).
    let rc = match (card_class, &eject_outcome) {
        (Some(class), Some(eo)) => eo
            .result
            .rc_override()
            .unwrap_or_else(|| class.rc(bad)),
        (Some(class), None) => class.rc(bad),
        (None, _) => {
            if bad == 0 {
                0
            } else {
                1
            }
        }
    };
    ExitCode::from(rc)
}

/// `frameprism restore` — repair the offenders from a pristine master.
/// rc=0 all restored + final audit clean, rc=1 unrestorable / final not
/// clean, rc=2 usage.
pub fn run_restore(args: &RestoreArgs) -> ExitCode {
    let input = args.input.as_path();
    let master = args.from.as_path();
    if !input.is_dir() {
        eprintln!("error: input is not a directory: {}", input.display());
        return ExitCode::from(2);
    }
    if !master.is_dir() {
        eprintln!(
            "error: --from is not a directory: {}",
            master.display()
        );
        return ExitCode::from(2);
    }
    let ci = input.canonicalize().unwrap_or_else(|_| input.to_path_buf());
    let cm = master.canonicalize().unwrap_or_else(|_| master.to_path_buf());
    if ci == cm {
        eprintln!("error: input and --from must be different directories");
        return ExitCode::from(2);
    }

    // (1) the audit pass over <input> (the arbiter is ITS sidecar;
    // restore's repair semantics are loose-file — bake manifests are
    // NOT restore sidecars).
    let reports = match audit_dir(input, args.jobs, false) {
        Ok((r, _)) => r,
        Err(err) => {
            eprintln!("error: restore: {err}");
            return ExitCode::from(2);
        }
    };
    let mut all: Vec<&Offender> = reports
        .iter()
        .flat_map(|r| r.offenders.iter())
        .collect();
    if all.is_empty() {
        println!("audit clean — nothing to restore");
        return ExitCode::SUCCESS;
    }

    // (4) --frame N (1-based over the sorted distinct frame stems =
    // the decode convention) restricts the offender set.
    if let Some(n) = args.frame {
        let mut stems: Vec<String> = Vec::new();
        for r in &reports {
            for row in &r.rows {
                if !stems.contains(&row.stem) {
                    stems.push(row.stem.clone());
                }
            }
        }
        stems.sort();
        if n == 0 || (n as usize) > stems.len() {
            eprintln!(
                "error: --frame {n} is out of range (frame numbers are 1-based; 1..={})",
                stems.len()
            );
            return ExitCode::from(2);
        }
        let stem = stems[(n - 1) as usize].clone();
        all.retain(|o| o.row.stem == stem);
        if all.is_empty() {
            println!("audit clean — nothing to restore (frame {n})");
            return ExitCode::SUCCESS;
        }
    }

    // (2)–(3) per offender (sorted sidecar order): candidate check +
    // evidence + atomic swap (the master is never modified).
    let mut restored = 0usize;
    let mut unrestorable = 0usize;
    for o in &all {
        let target = &o.target;
        let candidate = master.join(&o.row.file);
        if !candidate.exists() {
            unrestorable += 1;
            println!(
                "UNRESTORABLE {} — master candidate missing: {}",
                o.row.file,
                candidate.display()
            );
            continue;
        }
        // The streaming master verify (the bounded read:
        // the O(1) size stat + the `SHA256_CHUNK`-buffered sha — the
        // one-shot `fs::read` of the whole master is gone; the
        // "verify BEFORE write" order is unchanged: the swap's copy
        // runs below, only after the row passes).
        let csize = match std::fs::metadata(&candidate).map(|m| m.len()) {
            Ok(s) => s,
            Err(err) => {
                unrestorable += 1;
                println!(
                    "UNRESTORABLE {} — cannot read master candidate: {err}",
                    o.row.file
                );
                continue;
            }
        };
        let csha = match jxl::sha256_stream_path(&candidate) {
            Ok(s) => s,
            Err(err) => {
                unrestorable += 1;
                println!(
                    "UNRESTORABLE {} — cannot read master candidate: {err}",
                    o.row.file
                );
                continue;
            }
        };
        if csize != o.row.size || csha != o.row.sha {
            unrestorable += 1;
            println!(
                "UNRESTORABLE {} — master candidate fails the sidecar row (size + sha256) — refusing to swap a bad master",
                o.row.file
            );
            continue;
        }
        // The write-path root-boundary invariant (the
        // named residual — the intermediate-dir symlink class):
        // the restore swap's write-path PARENT (the dir the tmp + the
        // rename land in, under `input`) must be inside the input
        // root's canonical form (a planted symlinked DIR component
        // below the input would redirect the swap into an outside dir;
        // the sync seam below does not see it). The guard checks
        // the PARENT (not the target itself): a link at the target's
        // final component is the rename-REPLACES class (the rename
        // atomically replaces the link — safe); the threat is the
        // intermediate DIR the tmp is created in. The root = the input
        // AS GIVEN. Fires BEFORE the .pre-restore move (the
        // metadata move) + the swap (the byte-write) — zero-partial
        // for the row. On violation: the named UNRESTORABLE line
        // (the root-boundary class is distinct from the existing
        // "swap failed" line — the honest vocabulary) + the row
        // stays unrestorable + named.
        if let Some(parent) = target.parent() {
            if let Err(err) = crate::offload::check_root_bound(parent, input) {
                unrestorable += 1;
                println!("UNRESTORABLE {} — root-boundary: {err}", o.row.file);
                continue;
            }
        }
        let pre = input.join(format!("{}.pre-restore", o.row.file));
        if target.exists() {
            if pre.exists() && !args.force {
                eprintln!(
                    "error: {} exists (use --force to overwrite)",
                    pre.display()
                );
                return ExitCode::from(2);
            }
            if let Err(err) = std::fs::rename(target, &pre) {
                unrestorable += 1;
                println!(
                    "UNRESTORABLE {} — cannot move the corrupt original to .pre-restore: {err}",
                    o.row.file
                );
                continue;
            }
        }
        let tmp = input.join(format!("{}.restore-tmp", o.row.file));
        // The streaming restore copy (the bounded second
        // pass: `io::copy`'s internal buffer, never the whole file —
        // the verified master's bytes, the same tmp + rename seam).
        // The theoretical master-mutation window between the verify
        // pass and this copy is closed by the FINAL full audit pass
        // (step 5) below.
        let done = std::fs::File::open(&candidate)
            .and_then(|mut src| {
                let mut dst = std::fs::File::create(&tmp)?;
                std::io::copy(&mut src, &mut dst)?;
                // The durability seam (extended
                // from the offload scope): the
                // restored bytes are filesystem-synchronized BEFORE
                // the rename — a power loss in the post-rename window
                // no longer lands the rename while the restored bytes
                // are still page-cache-only (the restore's detection
                // class — the FINAL full audit pass — names the lost
                // file, it cannot restore the durability window). A
                // sync failure rides the chain's EXISTING error path
                // (the chain Err → `done = false` → the tmp removal +
                // the existing named `UNRESTORABLE … — swap failed`
                // line — the wording unchanged: the swap indeed
                // failed; the raw io error propagates
                // a named sync context would
                // be dead text — `.is_ok()` never surfaces it).
                dst.sync_all()?;
                Ok(())
            })
            .and_then(|_| std::fs::rename(&tmp, target))
            .is_ok();
        if done {
            restored += 1;
            println!(
                "restored {} (from {})",
                o.row.file,
                candidate.display()
            );
        } else {
            let _ = std::fs::remove_file(&tmp);
            unrestorable += 1;
            println!("UNRESTORABLE {} — swap failed", o.row.file);
        }
    }

    // (5) the FINAL full audit pass over <input> (evidence).
    match audit_dir(input, args.jobs, false) {
        Ok((final_reports, _)) => {
            print_reports(&final_reports, &[]);
            let clean = final_reports.iter().all(|r| r.offenders.is_empty());
            println!(
                "restore: {restored} restored, {unrestorable} unrestorable, final audit {}",
                if clean { "clean" } else { "NOT clean" }
            );
            if unrestorable == 0 && clean {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => {
            eprintln!("error: final audit: {err}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testutil::*;

    #[test]
    fn audit_no_sidecar_and_no_ingest_manifest_rc2() {
        let tmp = std::env::temp_dir().join(format!("frameprism-a12-ns-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("notes.txt"), b"nothing to audit").unwrap();
        // The existing contract: a dir with no sidecar of ANY kind (and no
        // ingest manifest) = the no-sidecar rc=2, unchanged.
        assert_eq!(run(&tmp), ExitCode::from(2));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn audit_ingest_manifest_parse_errors_named() {
        let tmp = std::env::temp_dir().join(format!("frameprism-a12-pe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // A bad magic → the named parse error (rc=2 via run_audit's
        // ingest-continuity error arm).
        std::fs::write(tmp.join("bad.ingest-manifest.tsv"), b"# not a manifest\nclip: A\n").unwrap();
        assert_eq!(run(&tmp), ExitCode::from(2), "a corrupt ingest manifest = the named rc=2, not a silent skip");
        // A row before the column line → named.
        std::fs::write(
            tmp.join("bad.ingest-manifest.tsv"),
            b"# frameprism ingest manifest\nclip: A\nA\t3\t-\t1..3\t-\t-\n",
        )
        .unwrap();
        assert_eq!(run(&tmp), ExitCode::from(2));
        // A non-6-column row → named.
        std::fs::write(
            tmp.join("bad.ingest-manifest.tsv"),
            b"# frameprism ingest manifest\nclip: A\nclip\tframes\nA\t3\n",
        )
        .unwrap();
        assert_eq!(run(&tmp), ExitCode::from(2));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // -------------------------------------------------------------------
    //: the verify-against-source surface (`audit --source`)
    // -------------------------------------------------------------------

    #[test]
    fn p8c8_audit_source_clean_unlocked_rc0_and_ledger_card_ok() {
        // The clean full-set: the archive sweep clean + every source
        // row verified against the live source → rc=0 (the UNLOCKED
        // line) + the ledger's CARD_OK verdict (the QC_GATE-style
        // additive verdict — the column, not a new column).
        let (archive, card, _rec) = mk_source_audit_dir("unlocked");
        let (rc, verdict) = run_locked(&archive, Some(&card));
        assert_eq!(rc, ExitCode::SUCCESS, "clean source + clean archive = the rc=0 class (CARD UNLOCKED)");
        assert_eq!(verdict.as_deref(), Some("CARD_OK"));
        let _ = std::fs::remove_dir_all(archive.parent().unwrap());
    }

    #[test]
    fn p8c8_audit_source_dirty_refused_rc1_and_ledger_card_refused() {
        // One flipped card byte → the named SHA_MISMATCH row → the
        // card must stay locked: rc=1 (the audit's documented
        // offender class) + CARD_REFUSED.
        let (archive, card, _rec) = mk_source_audit_dir("refused");
        let mut flipped = b"encoded-frame-bytes".to_vec();
        flipped[3] ^= 0xFF;
        std::fs::write(card.join("f1.DNG"), &flipped).unwrap();
        let (rc, verdict) = run_locked(&archive, Some(&card));
        assert_eq!(rc, ExitCode::from(1), "a dirty source row keeps the card locked (CARD REFUSED)");
        assert_eq!(verdict.as_deref(), Some("CARD_REFUSED"));
        let _ = std::fs::remove_dir_all(archive.parent().unwrap());
    }

    #[test]
    fn p8c8_audit_source_clean_card_dirty_archive_refused_rc1() {
        // The full-set claim's other direction: a CLEAN card + a DIRTY
        // archive (the encoded frame corrupted after the encode) →
        // the card is NOT released (the UNLOCKED line requires the
        // archive audit clean too): rc=1 + CARD_REFUSED.
        let (archive, card, _rec) = mk_source_audit_dir("dirty-archive");
        let mut corrupt = b"encoded-frame-bytes".to_vec();
        corrupt.pop();
        std::fs::write(archive.join("f1.DNG"), &corrupt).unwrap();
        let (rc, verdict) = run_locked(&archive, Some(&card));
        assert_eq!(rc, ExitCode::from(1), "the archive's named offender keeps the card locked");
        assert_eq!(verdict.as_deref(), Some("CARD_REFUSED"));
        let _ = std::fs::remove_dir_all(archive.parent().unwrap());
    }

    #[test]
    fn p8c8_audit_source_absent_unverifiable_follows_archive() {
        // (a) the card root absent + the archive clean → the named
        // UNVERIFIABLE honesty line, rc=0 (an unmounted card is NOT a
        // failure of the archive).
        let (archive, _card, _rec) = mk_source_audit_dir("unverifiable-clean");
        let (rc, verdict) = run_locked(&archive, Some(&archive.join("absent-card")));
        assert_eq!(rc, ExitCode::SUCCESS, "the rc follows the (clean) archive audit");
        assert_eq!(verdict.as_deref(), Some("CARD_UNVERIFIABLE"));
        // (b) the card root absent + the archive dirty → rc=1 (the
        // archive's offender stands; the source rows are not
        // verified — they do not add to the verdict).
        let (archive2, _card2, _rec2) = mk_source_audit_dir("unverifiable-dirty");
        std::fs::write(archive2.join("f1.DNG"), b"corrupted-after-encode").unwrap();
        let (rc, verdict) = run_locked(&archive2, Some(&archive2.join("absent-card")));
        assert_eq!(rc, ExitCode::from(1), "the rc follows the (dirty) archive audit");
        assert_eq!(verdict.as_deref(), Some("CARD_UNVERIFIABLE"));
        let _ = std::fs::remove_dir_all(archive.parent().unwrap());
        let _ = std::fs::remove_dir_all(archive2.parent().unwrap());
    }

    #[test]
    fn p8c8_audit_source_absent_record_unverifiable() {
        // The record absent (a pre-existing archive): the named
        // UNVERIFIABLE line (the record is absent), the archive audit
        // stands, rc follows it.
        let base = std::env::temp_dir().join("frameprism_audit_source_norecord");
        let _ = std::fs::remove_dir_all(&base);
        let archive = base.join("out");
        let card = base.join("card");
        std::fs::create_dir_all(&archive).unwrap();
        std::fs::create_dir_all(&card).unwrap();
        let frame = b"encoded-frame-bytes";
        std::fs::write(archive.join("f1.DNG"), frame).unwrap();
        std::fs::write(card.join("f1.DNG"), frame).unwrap();
        let crc = crate::checksums::crc32c(frame);
        let sha = crate::jxl::sha256_hex(frame);
        std::fs::write(
            archive.join("CLIP.checksums.tsv"),
            format!("file\tsize\tcrc32c\tsha256\nf1.DNG\t{}\t{crc:08x}\t{sha}\n", frame.len()),
        )
        .unwrap();
        let (rc, verdict) = run_locked(&archive, Some(&card));
        assert_eq!(rc, ExitCode::SUCCESS, "the archive audit stands (the record is absent, not a failure)");
        assert_eq!(verdict.as_deref(), Some("CARD_UNVERIFIABLE"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn p8c8_audit_source_corrupt_record_named_rc2_no_ledger_row() {
        // A corrupt record (bad magic) = the named hard rc=2 (the
        // records-class refusal — never a silent skip; the
        // usage-class semantics: no ledger row, zero partial
        // verdicts).
        let (archive, card, rec) = mk_source_audit_dir("corrupt-record");
        std::fs::write(&rec, "# not a source record\nclip: \n").unwrap();
        let rc = run_source(&archive, &card);
        assert_eq!(rc, ExitCode::from(2), "the corrupt record is the named hard rc=2");
        // No ledger row (the usage-class refusal appended nothing —
        // the ledger file is absent: the helper redirects to it,
        // and a refused run appends no row, so the file is never
        // created).
        assert!(!archive.join(".ledger-test.tsv").exists(), "no ledger row on the rc=2 refusal");
        // A bad column count is the same class.
        let (archive2, card2, rec2) = mk_source_audit_dir("bad-columns");
        std::fs::write(
            &rec2,
            format!("{0}\nversion: 1\nclip: \n{1}\nf1.DNG\t4\n", crate::sourcecheck::SOURCES_MAGIC, crate::sourcecheck::SOURCES_COLUMNS),
        )
        .unwrap();
        let rc = run_source(&archive2, &card2);
        assert_eq!(rc, ExitCode::from(2));
        let _ = std::fs::remove_dir_all(archive.parent().unwrap());
        let _ = std::fs::remove_dir_all(archive2.parent().unwrap());
    }

    #[test]
    fn p8c8_audit_source_clip_key_mismatch_named_rc2() {
        // The clip key = the folder name (the tree-aware convention):
        // a mismatch = the named rc=2, zero partial verdicts.
        let (archive, _card, _rec) = mk_source_audit_dir("mismatch");
        // The card tree: one clip folder (A001_007).
        let base = archive.parent().unwrap().to_path_buf();
        let tree = base.join("tree-card");
        let _ = std::fs::remove_dir_all(&tree);
        std::fs::create_dir_all(tree.join("A001_007")).unwrap();
        std::fs::write(tree.join("A001_007/f1.DNG"), b"encoded-frame-bytes").unwrap();
        // (a) the flat record (clip "" — the fixture's `.sources.tsv`)
        // + the tree root = the named refusal (zero partial verdicts).
        let rc = run_source(&archive, &tree);
        assert_eq!(rc, ExitCode::from(2), "the flat record against a tree root is the named rc=2");
        // (b) the matching tree clip verifies (the rc=0 class): the
        // flat record is replaced by the A001_007 record.
        let _ = std::fs::remove_file(archive.join(".sources.tsv"));
        crate::sourcecheck::write_sources_record(
            &archive,
            "A001_007",
            &[("f1.DNG".to_string(), 19, crate::jxl::sha256_hex(b"encoded-frame-bytes"))],
        )
        .unwrap();
        let (rc, _) = run_locked(&archive, Some(&tree));
        assert_eq!(rc, ExitCode::SUCCESS, "the matching tree clip verifies (the rc=0 class)");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn p8c8_audit_without_source_flag_keeps_existing_verdicts() {
        // The byte-identity carve-out: an audit WITHOUT --source on a
        // tree that carries a sources record = the pre-existing output +
        // rc + the OK/FAIL verdicts (no CARD line, no CARD verdict).
        let (archive, card, _rec) = mk_source_audit_dir("no-flag");
        let (rc, verdict) = run_locked(&archive, None);
        assert_eq!(rc, ExitCode::SUCCESS);
        assert_eq!(verdict.as_deref(), Some("OK"), "the verdict stands (no --source)");
        let _ = std::fs::remove_dir_all(archive.parent().unwrap());
        let _ = std::fs::remove_dir_all(&card);
    }

    // -------------------------------------------------------------------
    //: the --eject surface (the verify-before-unmount auto-eject —
    // the gating matrix end-to-end, via the FP_EJECT_CMD seam + the
    // inline-generated fake eject binary; the pure half — the wordings,
    // the tokens, the /proc/mounts resolution — is the sourcecheck
    // module's tests)
    // -------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn p8c9_audit_eject_unlocked_ejects_mount_and_ledger_card_ok_ejected() {
        // The gating matrix's UNLOCKED case: a clean source + a clean
        // archive + `--eject` → the eject IS run (the fake records
        // the mount point = the `--source` arg), the audit's rc is
        // UNCHANGED (0) + the ledger's CARD_OK_EJECTED token.
        let (archive, card, _rec) = mk_source_audit_dir("eject-unlocked");
        let base = archive.parent().unwrap().to_path_buf();
        let fake = base.join("fake-eject.sh");
        write_fake_eject(&fake);
        let log = base.join("eject.log");
        let (rc, verdict) = run_eject(&archive, Some(&card), &fake, &log, None);
        assert_eq!(rc, ExitCode::SUCCESS, "UNLOCKED + eject = the audit's rc UNCHANGED (0)");
        assert_eq!(verdict.as_deref(), Some("CARD_OK_EJECTED"));
        let recorded = std::fs::read_to_string(&log).unwrap_or_default();
        assert_eq!(
            recorded.trim(),
            card.to_str().unwrap(),
            "the fake recorded the mount point (the --source arg)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn p8c9_audit_eject_refused_never_ejects_and_ledger_card_refused_eject_refused() {
        // The gating matrix's REFUSED case (a corrupted source row):
        // the named EJECT REFUSED line — the eject is NEVER attempted
        // (the fake is not called — the card stays as evidence), the
        // audit's rc is UNCHANGED (1) + the ledger's
        // CARD_REFUSED_EJECT_REFUSED token.
        let (archive, card, _rec) = mk_source_audit_dir("eject-refused");
        let base = archive.parent().unwrap().to_path_buf();
        let mut flipped = b"encoded-frame-bytes".to_vec();
        flipped[3] ^= 0xFF;
        std::fs::write(card.join("f1.DNG"), &flipped).unwrap();
        let fake = base.join("fake-eject.sh");
        write_fake_eject(&fake);
        let log = base.join("eject.log");
        let (rc, verdict) = run_eject(&archive, Some(&card), &fake, &log, None);
        assert_eq!(
            rc,
            ExitCode::from(1),
            "a dirty source row keeps the card locked (CARD REFUSED) — the rc UNCHANGED by --eject"
        );
        assert_eq!(verdict.as_deref(), Some("CARD_REFUSED_EJECT_REFUSED"));
        assert!(!log.exists(), "the REFUSED class never spawns the eject (the card stays as evidence)");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn p8c9_audit_eject_unverifiable_never_ejects_and_ledger_card_unverifiable_eject_refused() {
        // The gating matrix's UNVERIFIABLE case (the card absent):
        // the named EJECT REFUSED line — the eject is NEVER attempted,
        // the rc follows the archive audit (UNCHANGED by the flag) +
        // the ledger's CARD_UNVERIFIABLE_EJECT_REFUSED token.
        let (archive, _card, _rec) = mk_source_audit_dir("eject-unverifiable");
        let base = archive.parent().unwrap().to_path_buf();
        let absent = base.join("absent-card");
        let fake = base.join("fake-eject.sh");
        write_fake_eject(&fake);
        let log = base.join("eject.log");
        let (rc, verdict) = run_eject(&archive, Some(&absent), &fake, &log, None);
        assert_eq!(rc, ExitCode::SUCCESS, "the rc follows the (clean) archive audit — UNCHANGED by --eject");
        assert_eq!(verdict.as_deref(), Some("CARD_UNVERIFIABLE_EJECT_REFUSED"));
        assert!(!log.exists(), "the UNVERIFIABLE class never spawns the eject (the rows are not verified)");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn p8c9_audit_eject_without_source_is_named_rc2() {
        // `--eject` without `--source`: the usage-class named refusal
        // (a CARD verdict does not exist without a source — the eject
        // gate IS the verdict): rc=2, the eject is never attempted,
        // and no ledger row is appended.
        let (archive, _card, _rec) = mk_source_audit_dir("eject-nosource");
        let base = archive.parent().unwrap().to_path_buf();
        let fake = base.join("fake-eject.sh");
        write_fake_eject(&fake);
        let log = base.join("eject.log");
        let (rc, verdict) = run_eject(&archive, None, &fake, &log, None);
        assert_eq!(rc, ExitCode::from(2), "--eject without --source = the named rc 2 (a CARD verdict does not exist without a source)");
        assert_eq!(verdict, None, "the usage-class refusal appends no ledger row");
        assert!(!log.exists(), "the refusal never spawns the eject");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn p8c9_audit_eject_failure_named_fail_rc1_and_ledger_card_ok_eject_fail() {
        // The gating matrix's failure case (the eject command exits 1
        // — e.g. the device is busy): the named EJECT FAIL line +
        // rc=1 (the requested action did not happen — the operator
        // must know) + the ledger's CARD_OK_EJECT_FAIL token (the
        // eject WAS attempted — the fake records the mount point,
        // then exits 1).
        let (archive, card, _rec) = mk_source_audit_dir("eject-fail");
        let base = archive.parent().unwrap().to_path_buf();
        let fake = base.join("fake-eject.sh");
        write_fake_eject(&fake);
        let log = base.join("eject.log");
        let (rc, verdict) = run_eject(&archive, Some(&card), &fake, &log, Some(1));
        assert_eq!(rc, ExitCode::from(1), "the requested-but-failed eject = the named rc 1 (the requested action did not happen)");
        assert_eq!(verdict.as_deref(), Some("CARD_OK_EJECT_FAIL"));
        let recorded = std::fs::read_to_string(&log).unwrap_or_default();
        assert_eq!(
            recorded.trim(),
            card.to_str().unwrap(),
            "the fake WAS called with the mount point (then exited 1)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    // R-INV: a sidecar-only dir WITHOUT ascmhl/ audits EXACTLY as
    // pre-existing (the MHL arm is inert — its detection is the ascmhl/
    // dir's presence). The full-stdout byte-identity is the
    // live-gate's re-derivation (the suite asserts the rc + the
    // ledger's verdict — stdout is not captured in-process).
    #[test]
    fn audit_mhl_inv() {
        let base = std::env::temp_dir().join("frameprism_audit_mhl_inv");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let frame = b"encoded-frame-bytes";
        std::fs::write(base.join("f1.DNG"), frame).unwrap();
        let crc = crate::checksums::crc32c(frame);
        let sha = crate::jxl::sha256_hex(frame);
        std::fs::write(
            base.join("CLIP.checksums.tsv"),
            format!(
                "file\tsize\tcrc32c\tsha256\nf1.DNG\t{}\t{crc:08x}\t{sha}\n",
                frame.len()
            ),
        )
        .unwrap();
        assert!(
            !base.join(crate::ascmhl::ASCMHL_DIR_NAME).exists(),
            "the fixture carries no ascmhl/ (the R-INV precondition)"
        );
        assert_eq!(
            run(&base),
            ExitCode::SUCCESS,
            "the sidecar-only dir audits as pre-existing (the MHL arm is inert)"
        );
        assert_eq!(
            ledger_verdict(&base),
            Some("OK".to_string()),
            "the ledger's verdict stands"
        );
    }

    /// The restore seam's benign functional test (the
    /// `clean_run_frozen` shape — the restore
    /// seam's success path was covered by NOTHING (no test calls
    /// `run_restore`; its only caller is the CLI dispatch); the
    /// repair seam's is the `repair_end_to_end_selective_named_and_
    /// deterministic` precedent, which stays green = its behavior
    /// proof). One corrupt row (the same-size byte flip — the
    /// sha256-mismatch offender class) + the pristine master: the
    /// seam's success path (create + copy + sync + rename), the
    /// restored bytes BYTE-identical to the master's, the
    /// `.pre-restore` backup holds the corrupt original (the corrupt
    /// bytes are preserved — never destroyed by the swap), NO
    /// `<file>.restore-tmp` residue (the atomic seam: nothing
    /// half-written), the master untouched, rc=0 (= `unrestorable
    /// == 0` + the final audit clean — the rc logic's own contract).
    #[test]
    fn audit_restore_seam_clean_run_bytes_frozen() {
        let base = std::env::temp_dir().join(format!(
            "frameprism_audit_restore_seam_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let master = base.join("master");
        let input = base.join("input");
        let clip = "A001_001";
        let frames: Vec<(String, Vec<u8>)> = vec![
            (
                format!("{clip}/f1.DNG"),
                synthetic_dng(Some(tc_payload(&tc_of(0, 0, 0, 10)))),
            ),
            (
                format!("{clip}/f2.DNG"),
                synthetic_dng(Some(tc_payload(&tc_of(0, 0, 0, 11)))),
            ),
        ];
        // The pristine master + its v3 sidecar (the real sha256 +
        // crc32c — the sweep's contract columns).
        std::fs::create_dir_all(master.join(clip)).unwrap();
        let mut tsv = String::new();
        tsv.push_str(crate::checksums::V3_MAGIC);
        tsv.push('\n');
        tsv.push_str("version: 3\n");
        tsv.push_str("tool_version: restore-seam-test\n");
        tsv.push_str(crate::checksums::V3_COLUMNS);
        tsv.push('\n');
        for (name, bytes) in &frames {
            std::fs::write(master.join(name), bytes).unwrap();
            tsv.push_str(&format!(
                "{}\t{}\t{:08x}\t{}\t\t\t\t\n",
                name,
                bytes.len(),
                crate::checksums::crc32c(bytes),
                jxl::sha256_hex(bytes)
            ));
        }
        let sidecar = format!("{clip}.checksums.tsv");
        std::fs::write(master.join(&sidecar), &tsv).unwrap();
        // The input = the identical tree (the deterministic synthetic
        // bytes), THEN the corruption: the same-size byte flip of f1
        // (the sha256-mismatch offender; the size stays the row's).
        std::fs::create_dir_all(input.join(clip)).unwrap();
        for (name, bytes) in &frames {
            std::fs::write(input.join(name), bytes).unwrap();
        }
        std::fs::write(input.join(&sidecar), &tsv).unwrap();
        let corrupt = input.join(format!("{clip}/f1.DNG"));
        let mut c = std::fs::read(&corrupt).unwrap();
        c[0] ^= 0xFF;
        std::fs::write(&corrupt, &c).unwrap();
        // The restore: the seam's success path.
        let rc = run_restore(&RestoreArgs {
            input: input.clone(),
            from: master.clone(),
            frame: None,
            jobs: 1,
            force: false,
        });
        assert_eq!(rc, ExitCode::SUCCESS, "the restore lands (rc=0)");
        // The headline: the restored bytes are BYTE-identical to the
        // master's (the seam wrote the master's bytes, nothing else).
        let master_bytes = std::fs::read(master.join(format!("{clip}/f1.DNG"))).unwrap();
        assert_eq!(
            std::fs::read(&corrupt).unwrap(),
            master_bytes,
            "the restored file is byte-identical to the master"
        );
        // The `.pre-restore` backup holds the CORRUPT original (the
        // corrupt bytes are preserved — never destroyed by the swap).
        let pre = input.join(format!("{clip}/f1.DNG.pre-restore"));
        assert!(pre.is_file(), "the .pre-restore backup exists");
        assert_eq!(
            std::fs::read(&pre).unwrap(),
            c,
            "the backup holds the corrupt bytes"
        );
        // No half-written residue: the tmp+rename seam left nothing.
        assert!(
            !input.join(format!("{clip}/f1.DNG.restore-tmp")).exists(),
            "no <file>.restore-tmp residue (the atomic seam)"
        );
        // The master is never modified.
        assert_eq!(
            std::fs::read(master.join(format!("{clip}/f1.DNG"))).unwrap(),
            master_bytes,
            "the master is untouched"
        );
        // The clean row is untouched.
        assert_eq!(
            std::fs::read(input.join(format!("{clip}/f2.DNG"))).unwrap(),
            frames[1].1,
            "the clean row is untouched"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
