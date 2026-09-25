//! The offload's form validation: the standalone
//! `frameprism offload` args + the form (the 1-dest legacy / the
//! multi-source), the settle (the form's selection + the refusals),
//! the self-referential + nesting refusal band (the shared encode
//! `--to` guard), the form dispatch.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::Args as ClapArgs;

use super::report::{run_offload_multi, run_offload_multi_sources};
use super::traversal::{canonicalize_path, is_path_prefix};

/// The `frameprism offload` CLI arguments (the `Cmd::Offload` payload —
/// the subcommand args live here, not in `main.rs`, per the shared CLI
/// restructure contract). The two forms: the SINGLE-SOURCE form — the
/// positional `in` (the source) + the positional `to` dests (the legacy
/// shape, byte-identical) — and the MULTI-SOURCE form — `--source
/// <SOURCE>...` (the sources) + `--dest <DEST>...` (the dests; no
/// positionals — the invocation shape `offload --source <treeA>
/// <treeB> --dest <d1> <d2>`; a single `--source` = the single-source
/// multi-shape, incl. single-dest: `offload --source s1 --dest d1`).
/// The positionals are the single-source form's: the mixed-form
/// refusals (the bands (i)–(iv)) + the all-absent refusal (b) are the
/// named rc=2 pre-write refusals (zero partial writes).
/// The usage line is OVERRIDDEN to the pinned rendering (clap's
/// default buckets the optional flags into `[OPTIONS]` and renders
/// the now-parse-optional `to` as `[to]...` — the pinned line names
/// both flags explicitly and keeps `<to>...`'s single-source-form
/// shape): `frameprism offload [in] <to>... [--source <SOURCE>... --dest
/// <DEST>...]`.
#[derive(ClapArgs, Debug)]
#[command(override_usage = "frameprism offload [in] <to>... [--source <SOURCE>... --dest <DEST>...]")]
pub struct Args {
    /// The source tree (the card dir — recursed; read-only, never
    /// modified). Every file is a first-class row: the frames + the
    /// sidecars (WAV/XMP/manifests — any format). The single-source
    /// form: the positional `in` (the legacy shape — byte-identical
    /// behavior). It is the single-source form's INPUT — the
    /// multi-source form's sources are named with `--source` (its
    /// dests with `--dest`): naming `in` alongside `--source` or
    /// `--dest` is a named refusal before any write (the bands (i)/
    /// (ii) — rc=2, zero partial writes).
    #[arg(name = "in", required = false)]
    pub input: Option<PathBuf>,
    /// The sources — the multi-source form (the bandwidth-maximizing
    /// class: every source fanned to every dest in one job). The
    /// per-source work (the detection scan + the read-once/write-M
    /// copy+verify core + the per-clip manifests) runs CONCURRENTLY —
    /// one std::thread per source, the sources do not wait on each
    /// other (the card reads overlap). The per-dest-root artifacts
    /// (the run report, the job report, the ascmhl history) are
    /// written in a serialized tail after ALL sources join (one
    /// ascmhl generation per dest per JOB — a run = the whole job).
    /// A single `--source` is the single-source MULTI-SHAPE form (the
    /// uniform multi rendering — not the legacy shape). The dests are
    /// named with `--dest` (the positional `to` is the single-source
    /// form's — the multi-form has no positionals). The pre-write
    /// refusals: the self-mirror guard per (source, dest) pair, the
    /// duplicate-dest refusal, the per-source dir check, the
    /// nested-source refusal, the cross-source top-level name
    /// collision, the shared source-basename refusal, the per-dest
    /// writability probe — all before any write (zero partial
    /// writes).
    #[arg(long, num_args = 1.., value_name = "SOURCE")]
    pub source: Vec<PathBuf>,
    /// The multi-source form's dests (the `--dest` flag — repeatable,
    /// one or more value per occurrence). The `dest` vocabulary
    /// matches the offload surface (the per-dest manifests, the
    /// `dest:` header rows, the pair lines' dest slots). The
    /// multi-form's dest names — the positional `to` is the
    /// single-source form's (the band (ii) guard). `--source` is
    /// required alongside it (the band (iv) guard); a single-dest
    /// multi-job is this flag's minimum (`--source s1 --dest d1`).
    /// The multi-form's pre-write bands (the duplicate-dest refusal,
    /// the per-pair self-mirror guard, the per-dest writability
    /// probes, the shared-basename refusal) apply to these
    /// values.
    #[arg(long, num_args = 1.., value_name = "DEST")]
    pub dest: Vec<PathBuf>,
    /// The mirror dest dirs — N destinations in one pass (the
    /// multi-destination fan-out: every source file's bytes are read
    /// ONCE and written to EVERY dest — the card read is the
    /// bottleneck; each dest file is re-scanned after its write).
    /// Each dest: created if missing, mirrored subpaths,
    /// mtime-preserving; an existing dest file is OVERWRITTEN (a
    /// re-run is idempotent + re-verified). Every dest gets its own
    /// per-clip offload manifests (at the mirrored clip roots — the
    /// `dest` header row is that dest) + the run report at its own
    /// dest root (the report carries the whole run — every dest's
    /// status). The single-source form's positional dests — the
    /// multi-source form names its dests with `--dest` (the band
    /// (iii)/(iv) guards). Optional at the parse level: a legacy
    /// invocation with no positional dests falls into
    /// `run_offload_multi`'s own named `needs at least one dest`
    /// band (the rc=2 pre-write class). The pre-write refusals cover
    /// EVERY dest before any copy: the self-mirror guard per dest, a
    /// duplicate dest is refused named (never silently deduped), the
    /// per-dest writability probe.
    #[arg(name = "to", num_args = 1.., required = false)]
    pub to: Vec<PathBuf>,
}


/// The settled offload form (the form bands' `Ok` — the pipeline to
/// run; the bands themselves are the named rc=2 pre-write refusals —
/// `settle_form`'s `Err` band, ZERO partial writes: no dest is even
/// created before the form is settled). The single-source form: the
/// positional input + the positional dests (the legacy shape —
/// byte-identical when the flags are absent). The multi-source form:
/// the `--source` + `--dest` values (the given order; no positionals
/// — the invocation shape).
#[derive(Debug)]
pub enum OffloadForm {
    /// The single-source form (the legacy shape — `run_offload_multi`
    /// untouched: the byte-identical anchor).
    Legacy {
        /// The positional input (the source tree).
        input: PathBuf,
        /// The positional dests (the `to` values — the given order).
        dests: Vec<PathBuf>,
    },
    /// The multi-source form (the `--source` + `--dest` values — the
    /// given order; a single `--source` = the single-source
    /// multi-shape, incl. single-dest).
    Multi {
        /// The `--source` values (the given order).
        sources: Vec<PathBuf>,
        /// The `--dest` values (the given order).
        dests: Vec<PathBuf>,
    },
}


/// The form bands' pure dispatch (the named rc=2 pre-parse
/// refusals — the evaluation order (i) → (ii) → (iii) → (iv) → (b),
/// the first hit wins; ZERO partial writes — a band fires before any
/// dest is created): the single-source form = the positional input +
/// the positional dests (the legacy shape — byte-identical when the
/// flags are absent); the multi-source form = `--source <SOURCE>...`
/// and `--dest <DEST>...` (no positionals — the invocation shape:
/// `offload --source <treeA> <treeB> --dest <d1> <d2>`; a single
/// `--source` = the single-source multi-shape, incl. single-dest:
/// `offload --source s1 --dest d1`). The positionals are the
/// single-source form's — the positional `in` never flips to a
/// multi-form dest (the write-side hazard: a stray `--source` on a
/// legacy invocation must be the loud rc=2, not a silent
/// re-classification of what the positionals mean).
pub fn settle_form(args: &Args) -> Result<OffloadForm> {
    if args.source.is_empty() && args.dest.is_empty() {
        // The single-source form (the flags are absent — the legacy
        // shape): the positional input names the source, the
        // positional dests name the dests. The all-absent case (the
        // bare `offload`) = the named refusal; a legacy
        // invocation with no positional dests falls into
        // `run_offload_multi`'s own named `needs at least one dest`
        // band (the rc=2 pre-write class).
        let input = args.input.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "the offload needs a source: the positional input (the single-source form) or --source (the multi-source form)"
            )
        })?;
        return Ok(OffloadForm::Legacy { input, dests: args.to.clone() });
    }
    // (i) `--source` given AND the positional input given (the
    // EXISTING wording verbatim — the guard, not the trap: the
    // positional `in` is the single-source form's INPUT — it never
    // flips to a multi-form dest; before any write).
    if !args.source.is_empty() && args.input.is_some() {
        bail!(
            "the sources are named once: either the positional input (the single-source form) or --source (the multi-source form) — not both"
        );
    }
    // (ii) `--dest` given AND the positional input given (the
    // parallel guard: the positional dests are the single-source
    // form's — `--dest` names the multi-source form's; before any
    // write).
    if !args.dest.is_empty() && args.input.is_some() {
        bail!(
            "the dests are named once: either the positional dests (the single-source form) or --dest (the multi-source form) — not both"
        );
    }
    // (iii) `--source` given AND `--dest` absent (the multi-form's
    // dests are named with `--dest` — the positional dests are the
    // single-source form's).
    if !args.source.is_empty() && args.dest.is_empty() {
        bail!(
            "the multi-source form names its dests with --dest (the positional dests are the single-source form's)"
        );
    }
    // (iv) `--dest` given AND `--source` absent (the symmetric band —
    // `--dest` names the multi-source form's dests; the single-source
    // form names its input positionally).
    if args.source.is_empty() && !args.dest.is_empty() {
        bail!(
            "--dest names the multi-source form's dests (the single-source form names its input positionally)"
        );
    }
    // Here: the multi-source form (both flags named, the positionals
    // absent — `input` is `None` by (i)/(ii)). The positional-`to`-
    // present variant of this state is CLI-unreachable (clap fills
    // `in` first with any positional token — (i)/(ii) would have
    // fired); a direct `run()` call with it = the (iii) band (the
    // positional dests are the single-source form's).
    if !args.to.is_empty() {
        bail!(
            "the multi-source form names its dests with --dest (the positional dests are the single-source form's)"
        );
    }
    Ok(OffloadForm::Multi {
        sources: args.source.clone(),
        dests: args.dest.clone(),
    })
}


/// The `Cmd::Offload` match arm (main.rs): run the standalone
/// offload (the form dispatch — `settle_form`'s settled form: the
/// positional single-source form — the legacy shape, byte-identical —
/// or the `--source` + `--dest` multi-source form), return the
/// process exit code (rc=2 the pre-write refusal — the form bands +
/// the phase-0 bands, before any copy; rc=1 the dirty row(s) named
/// AFTER the run — any dirty pair — or a source-thread failure;
/// rc=0 every row OK at every pair).
pub fn run(args: &Args) -> ExitCode {
    let form = match settle_form(args) {
        Ok(form) => form,
        Err(err) => {
            eprintln!("error: {err:#}");
            return ExitCode::from(2);
        }
    };
    let outcome = match form {
        OffloadForm::Legacy { input, dests } => run_offload_multi(&input, &dests),
        OffloadForm::Multi { sources, dests } => run_offload_multi_sources(&sources, &dests),
    };
    match outcome {
        Ok(rc) => rc,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}


/// The encode `--to` band (the two encode
/// entry points: the j92 `worker::process_dir` + the jxl
/// `jxl::process_dir` — this helper is the SINGLE code path the
/// both call; the per-codec wiring is proven by the per-codec test
/// batteries). The `--to` dest must be DISJOINT from the encode
/// input AND the encode output: the post-encode offload mirrors
/// the RAW input to the dest (`offload_to` → `offload_core`), so a
/// self-referential `--to` (identity or nesting, either
/// direction, either pair) overwrites the encode product with the
/// raw source / writes the mirror into the source tree — AFTER
/// the run reports success (the HIGH case: the total + silent
/// product loss). The named refusal is the rc=2 BEFORE any frame
/// (the caller's placement — before the dest probe's dir
/// creation: the zero-residue refusal). The canonical forms are
/// the parent-walk best-effort (`canonicalize_path` — a missing
/// dest resolves through its existing ancestor). The identity
/// topology is the verify-only no-op (benign but useless —
/// refused, not documented). A canonicalize
/// failure (the symlink-loop class) skips that pair's checks —
/// the writability-probe band names it there (the existing
/// idiom).
pub(crate) fn check_to_band(input: &Path, output: &Path, dest: &Path) -> Result<()> {
    let (in_c, out_c, to_c) = (
        canonicalize_path(input),
        canonicalize_path(output),
        canonicalize_path(dest),
    );
    if let (Some(ref i), Some(ref d)) = (&in_c, &to_c) {
        if *i == *d {
            bail!(
                "--to dest {} is the encode input (the post-encode mirror would just re-verify the source in place — name a dest outside both the input and the output)",
                dest.display()
            );
        }
        if is_path_prefix(i, d) {
            bail!(
                "--to dest {} is inside the encode input {} (the post-encode mirror would write the source tree's mirror into the input — name a dest outside both the input and the output)",
                dest.display(),
                input.display()
            );
        }
        if is_path_prefix(d, i) {
            bail!(
                "--to dest {} contains the encode input {} (the post-encode mirror would write into the dest root that holds the input tree — the mirrored paths may overwrite its pre-existing content; name a dest outside both the input and the output)",
                dest.display(),
                input.display()
            );
        }
    }
    if let (Some(ref o), Some(ref d)) = (&out_c, &to_c) {
        if *o == *d {
            bail!(
                "--to dest {} is the encode output {} (the post-encode mirror would overwrite the encode product with the raw source — name a dest outside both the input and the output)",
                dest.display(),
                output.display()
            );
        }
        if is_path_prefix(o, d) {
            bail!(
                "--to dest {} is inside the encode output {} (the post-encode mirror would write the source tree's mirror into the encode product tree — name a dest outside both the input and the output)",
                dest.display(),
                output.display()
            );
        }
        if is_path_prefix(d, o) {
            bail!(
                "--to dest {} contains the encode output {} (the post-encode mirror would write into the dest root that holds the product tree — the mirrored paths may overwrite its pre-existing content; name a dest outside both the input and the output)",
                dest.display(),
                output.display()
            );
        }
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    use super::super::run_offload;

    use crate::offload::testutil::*;
    /// The shared encode `--to` band's six topologies +
    /// the disjoint pass (every topology
    /// over both pairs gets the named refusal; the
    /// disjoint config is the only pass). The helper is the SINGLE
    /// code path for both encode entry points (the j92 `worker`
    /// + the jxl — the per-codec wiring is proven by the per-codec
    /// integration batteries). The exact-line assertions (the
    /// refusal idiom). The helper is metadata-only: the
    /// missing-dest topologies resolve through the parent-walk
    /// without creating anything (the zero-residue proof).
    #[test]
    fn to_band_six_topologies_refuse_named() {
        let base = std::env::temp_dir().join(format!(
            "frameprism-band-topologies-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        // The fixture layout: the input + output in SEPARATE parent
        // trees (a dest containing one must not contain the other —
        // the pair order checks the input pair first).
        let input = base.join("in-wrap").join("in");
        let output = base.join("outer").join("out");
        std::fs::create_dir_all(&input).unwrap();
        std::fs::create_dir_all(&output).unwrap();
        // (1) identity output — the headline case (the total +
        // silent product loss).
        let err = check_to_band(&input, &output, &output).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "--to dest {} is the encode output {} (the post-encode mirror would overwrite the encode product with the raw source — name a dest outside both the input and the output)",
                output.display(),
                output.display()
            ),
            "the identity-output refusal verbatim"
        );
        // (2) dest nested in the output.
        let sub = output.join("sub");
        let err = check_to_band(&input, &output, &sub).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "--to dest {} is inside the encode output {} (the post-encode mirror would write the source tree's mirror into the encode product tree — name a dest outside both the input and the output)",
                sub.display(),
                output.display()
            ),
            "the nested-in-output refusal verbatim (the missing dest resolves through the parent-walk)"
        );
        assert!(!sub.exists(), "the helper writes nothing (the zero-residue proof)");
        // (3) the output nested in the dest (the dest holds the
        // product tree — the mirrored paths may overwrite its
        // pre-existing content).
        let err = check_to_band(&input, &output, &base.join("outer")).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "--to dest {} contains the encode output {} (the post-encode mirror would write into the dest root that holds the product tree — the mirrored paths may overwrite its pre-existing content; name a dest outside both the input and the output)",
                base.join("outer").display(),
                output.display()
            ),
            "the containing-output refusal verbatim"
        );
        // (4) identity input — the verify-only no-op (benign but
        // useless — refused, not documented).
        let err = check_to_band(&input, &output, &input).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "--to dest {} is the encode input (the post-encode mirror would just re-verify the source in place — name a dest outside both the input and the output)",
                input.display()
            ),
            "the identity-input refusal verbatim"
        );
        // (5) dest nested in the input (the mirror would write into
        // the source tree).
        let insub = input.join("sub");
        let err = check_to_band(&input, &output, &insub).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "--to dest {} is inside the encode input {} (the post-encode mirror would write the source tree's mirror into the input — name a dest outside both the input and the output)",
                insub.display(),
                input.display()
            ),
            "the nested-in-input refusal verbatim"
        );
        assert!(!insub.exists(), "the helper writes nothing (the zero-residue proof)");
        // (6) the input nested in the dest.
        let err = check_to_band(&input, &output, &base.join("in-wrap")).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "--to dest {} contains the encode input {} (the post-encode mirror would write into the dest root that holds the input tree — the mirrored paths may overwrite its pre-existing content; name a dest outside both the input and the output)",
                base.join("in-wrap").display(),
                input.display()
            ),
            "the containing-input refusal verbatim"
        );
        // (7) the disjoint config PASSES (the band must not
        // over-refuse — the benign pin's unit half; the per-codec
        // integration pin is the worker's
        // `to_outside_both_completes`). The missing disjoint
        // dest resolves through the parent-walk + is not created.
        let disjoint = base.join("dest");
        assert!(check_to_band(&input, &output, &disjoint).is_ok(), "the disjoint --to passes");
        assert!(!disjoint.exists(), "the disjoint pass writes nothing");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The offload forms' (source, dest) nesting refusals
    /// (both directions, EVERY form the entry-point
    /// inventory names: the single-source form (the Legacy CLI
    /// positionals — `run_offload` rides it transitively) + the
    /// multi-source form). Each: the named refusal BEFORE any write
    /// + the source tree UNTOUCHED + zero dest files (the band fires
    /// before the probe's dir creation — the zero-residue refusal;
    /// the missing-dest topology resolves through the parent-walk).
    #[test]
    fn offload_dest_nesting_refusals() {
        profile_override_a001();
        let (base, card_a, _card_b) = multi_trees("dest-nesting");
        // The source-untouched proof (the card tree's entry count +
        // the frame bytes, before any case).
        let card_entries = || {
            std::fs::read_dir(&card_a).map(|rd| rd.flatten().count()).unwrap_or(0)
        };
        let frame = std::fs::read(card_a.join("A001_001/f1.DNG")).unwrap();
        let n0 = card_entries();
        // (a) The single-source form — the dest nested IN the source
        // (the headline case: the mirror would write the mirrored
        // tree into the source + re-runs multiply it).
        let d_inside = card_a.join("mirror");
        let err = run_offload(&card_a, &d_inside).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "the offload dest {} is inside the source {} (the mirror would write the mirrored tree into the source — name a dest outside the source)",
                d_inside.display(),
                card_a.display()
            ),
            "the single-form dest-inside-source refusal verbatim (the missing dest resolved through the parent-walk)"
        );
        assert!(!d_inside.exists(), "the refusal leaves NOTHING (the probe never ran)");
        assert_eq!(card_entries(), n0, "the source tree is untouched (a)");
        // (b) The single-source form — the source nested IN the dest
        // (the mirror would write into the dest root that holds the
        // source — the pre-existing content at the mirrored paths
        // is overwritten via the mismatch path).
        let err = run_offload(&card_a, &base).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "the offload source {} is inside the dest {} (the mirror would write into the dest root that holds the source — the mirrored paths may overwrite its pre-existing content; name a dest outside the source)",
                card_a.display(),
                base.display()
            ),
            "the single-form source-inside-dest refusal verbatim"
        );
        // The dest root (base) holds only the two card dirs — no
        // mirror entry was written at its top level (sorted — the
        // `read_dir` order is not guaranteed).
        let base_entries = || {
            let mut v: Vec<String> = std::fs::read_dir(&base)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        };
        assert_eq!(base_entries(), vec!["cardA".to_string(), "cardB".to_string()], "base untouched");
        // (c) The multi-source form — the per-pair band: the dest
        // nested in ONE source (the first violating pair names
        // itself).
        let d_inside2 = card_a.join("mirror2");
        let err = run_offload_multi_sources(&[card_a.clone()], &[d_inside2.clone()])
            .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "the offload dest {} is inside the source {} (the mirror would write the mirrored tree into the source — name a dest outside the source)",
                d_inside2.display(),
                card_a.display()
            ),
            "the multi-form dest-inside-source refusal verbatim (the pair named)"
        );
        assert!(!d_inside2.exists(), "the refusal leaves NOTHING (the probe never ran)");
        assert_eq!(card_entries(), n0, "the source tree is untouched (c)");
        assert_eq!(std::fs::read(card_a.join("A001_001/f1.DNG")).unwrap(), frame, "the frame bytes are intact");
        // (d) The multi-source form — the source nested in the dest
        // (every (source, dest) pair — the first pair fires).
        let err = run_offload_multi_sources(
            &[card_a.clone(), base.join("cardB").clone()],
            &[base.clone()],
        )
        .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "the offload source {} is inside the dest {} (the mirror would write into the dest root that holds the source — the mirrored paths may overwrite its pre-existing content; name a dest outside the source)",
                card_a.display(),
                base.display()
            ),
            "the multi-form source-inside-dest refusal verbatim (the pair named)"
        );
        assert_eq!(base_entries(), vec!["cardA".to_string(), "cardB".to_string()], "base still untouched");
        let _ = std::fs::remove_dir_all(&base);
    }


}
