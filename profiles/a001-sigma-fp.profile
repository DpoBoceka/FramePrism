# frameprism camera profile
# A001 (Sigma fp) — written FROM the measurement
# (verified against clip A001_001, firmware Ver.5.02.0.V91; the four
# readout geometries — the 3856×2170 + 1936×1090 x the three native depths from
# the CINEMA batch, plus the 2016×1344 Open Gate 2K rows (the 12-bit
# row from the measurement (the modified firmware 5.02 — the version string is
# unchanged, the gyro recording is additive); the 10/8-bit rows from the
# measurement — the 12-clip batch), plus the
# 3024×2010 12-bit Open Gate 3K row from the measurement (the
# UNOFFICIAL mode 98 of the modified firmware 5.02 line — the per-clip GyroFlow
# calibration names it "3024x2010 @24.000 (mode 98)", official: false; the
# version string is unchanged; the gyro recording is
# additive; measured on clip A001_006, 114 frames, 24 fps), plus the
# 3024×2010 10/8-bit Open Gate 3K rows from the measurement — the 12-clip batch
# (the mirrored clips: A001_011 @10 · A001_012 @8)). This
# profile = the tool's embedded A001 constants (tileenc.rs's
# TILE_W/TILE_H 482×272 default + the GATE_* set — the per-gate grids
# (measured): GATE_3K_* 252×252, GATE_FHD_*
# 242×274/484×274 per depth, GATE_OG2K_* 252×336; + worker/encode.rs's TILE_W_FRAME_2K/TILE_H_FRAME_2K +
# the is_tile_layout / is_archive_layout predicates): the encode output
# is byte-invariant at the gates whose measured structure is unchanged
# (the byte-invariance contract — the oracles + the unchanged
# (geometry × depth) combinations). `geometry` rows pin
# which of the shipped predicates apply per readout/depth (`tile` =
# is_tile_layout, `archive` = is_archive_layout). `naming` is the measured
# frame-file convention (informational — the resolver does not match
# on file names).
version: 1
tool_version: 0.1.0
camera: a001-sigma-fp
make: SIGMA
model: SIGMA fp
photometric: 32803
naming: <CLIP>_<YYYYMMDD>_<NNNNNN>.DNG
geometry: 3856 2170 12 tile,archive
geometry: 3856 2170 10 archive
geometry: 3856 2170 8 archive
geometry: 1936 1090 12 archive
geometry: 1936 1090 10 archive
geometry: 1936 1090 8 archive
geometry: 2016 1344 12 archive
geometry: 2016 1344 10 archive
geometry: 2016 1344 8 archive
geometry: 3024 2010 12 archive
geometry: 3024 2010 10 archive
geometry: 3024 2010 8 archive
