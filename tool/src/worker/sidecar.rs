//! The sidecar + cleanup — the sidecar-row emission.
//!
//! `append_sidecar_row`: the incremental sidecar row (the on-disk
//! crash-recovery record + the in-memory row set — the final canonical
//! rewrite's input). `plan_row` = the verified plan row reused for a
//! skip (no re-read); None = a fresh re-hash of the on-disk output (the
//! Done case — the verification, not the trust). Read/header failures
//! land in `meta_errors` (named — the run fails before the final
//! sidecar, the pre-existing write_checksums bail parity); the append
//! itself never fails the run (the additive contract — the final
//! rewrite is the product write). `emit_frame_line`: the per-frame
//! progress line (the live-metrics delta rendering). `ChecksumsRow`:
//! the `--checksums` sidecar row shape (file, size, crc32c, sha256,
//! the 4 camera-metadata columns). The "cleanup" half of the part's
//! name (the board's 67 item): the inline best-effort tmp removals ride
//! in the `report` part's `process_dir` + the `encode` part's `run` —
//! no standalone cleanup item.

use std::path::Path;
use std::time::Instant;

use super::checksums::read_frame_metadata;
use super::report::clip_key_of;

// The `--checksums` sidecar row (file, size, crc32c, sha256, the 4 camera-metadata columns).
pub(crate) type ChecksumsRow = (String, u64, u32, String, [String; 4]);

///: append one frame's row to the incremental sidecar (the
/// on-disk file — the crash-recovery record) + the in-memory row set
/// (the final canonical rewrite's input). `plan_row` = the verified
/// plan row reused for a skip (no re-read); None = a fresh re-hash of
/// the on-disk output (the Done case — the verification, not the
/// trust). Read/header failures land in `meta_errors` (named — the
/// run fails before the final sidecar, the pre-existing write_checksums
/// bail parity); the append itself never fails the run (the additive
/// contract — the final rewrite is the product write).
pub(crate) fn append_sidecar_row(
    dst: &Path,
    rel: &str,
    checksums: bool,
    clip0: &Option<String>,
    rows: &std::sync::Mutex<&mut Vec<ChecksumsRow>>,
    file: &std::sync::Mutex<Option<std::fs::File>>,
    meta_errors: &std::sync::Mutex<Vec<String>>,
    plan_row: Option<&crate::resume::Row>,
) {
    if !checksums {
        return;
    }
    if clip0.is_none() {
        return;
    }
    let (size, crc, sha, meta) = match plan_row {
        Some(r) => (r.size, r.crc, r.sha.clone(), r.meta.clone()),
        None => {
            // The streaming triple (size + crc + sha in one
            // bounded pass); the note wording is the pre-existing one.
            let (size, sha, crc) = match crate::jxl::digest_stream_path(dst) {
                Ok(t) => t,
                Err(err) => {
                    meta_errors.lock().unwrap().push(format!(
                        "read the output frame {} for the sidecar row: {err}",
                        dst.display()
                    ));
                    return;
                }
            };
            let meta = match read_frame_metadata(dst) {
                Ok(m) => m,
                Err(err) => {
                    meta_errors.lock().unwrap().push(err);
                    return;
                }
            };
            (
                size,
                crc,
                sha,
                crate::checksums::meta_columns(&meta),
            )
        }
    };
    let line = crate::checksums::row_line(rel, size, crc, &sha, &meta);
    rows.lock()
        .unwrap()
        .push((rel.to_string(), size, crc, sha.clone(), meta));
    if let Ok(mut g) = file.lock() {
        if let Some(f) = g.as_mut() {
            use std::io::Write as _;
            let _ = f.write_all(line.as_bytes());
        }
    }
}

///: the per-frame status line (the `phase:"encode"` event —
/// `resumed` 1|0: the verified plan skip vs an encode / a naive skip).
/// The rate/eta are the instantaneous measured values (0 until the
/// first measurable interval — the `est_eta_s` stands in then).
pub(crate) fn emit_frame_line(
    src: &Path,
    dst: &Path,
    input: &Path,
    output: &Path,
    resumed: bool,
    done_count: &std::sync::atomic::AtomicUsize,
    total: usize,
    est_eta_s: u64,
    t_start: &Instant,
) {
    let Some(st) = crate::status::current() else { return };
    let n = done_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let el = t_start.elapsed().as_secs_f64();
    let (rate, eta) = if el >= 0.1 {
        let r = n as f64 / el;
        (r, (total.saturating_sub(n)) as f64 / r)
    } else {
        (0.0, est_eta_s as f64)
    };
    let frame_rel = dst
        .strip_prefix(output)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();
    st.emit(&format!(
        "{{\"phase\":{},\"clip\":{},\"frame\":{},\"frames_done\":{n},\"frames_total\":{total},\"resumed\":{rf},\"rate_fps\":{rate:.2},\"eta_s\":{eta:.0}}}",
        crate::status::jstr("encode"),
        crate::status::jstr(&clip_key_of(input, src)),
        crate::status::jstr(&frame_rel),
        rf = usize::from(resumed)
    ));
}
