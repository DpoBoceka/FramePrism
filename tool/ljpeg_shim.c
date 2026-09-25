/* Raw libjpeg lossless (SOF3) FFI shim for frameprism tileenc.
 *
 * Why a shim: struct jpeg_compress_struct / jpeg_decompress_struct layouts
 * are internal (jpegint.h is not installed by Homebrew), so the Rust side
 * uses opaque handles. Only the PUBLIC libjpeg C API is used here
 * (verified against the installed libjpeg-turbo 3.2.0 headers).
 *
 * Fixed to this project's needs: 2-component lossless, data precision 10 or
 * 12 (12 = lossless mode, 10 = log10 mode), Ss (PSV) selectable (7 =
 * (left+up)/2, libjpeg/DNG-SDK numbering), Se=0, Pt=0.
 *
 * SAMPLE LAYOUT — CRITICAL (the pixel-order fix): for multi-component
 * raw input libjpeg expects scanline rows PER-PIXEL INTERLEAVED:
 *   row y = [c0(x=0), c1(x=0), c0(x=1), c1(x=1), ..., c0(x=W-1), c1(x=W-1)]
 * `null_convert` (JCS_UNKNOWN, nc=2, jccolor.c) de-interleaves exactly that
 * layout: comp[ci][x] = row[x*nc + ci]. Passing component-BLOCK rows
 * ([c0 row][c1 row], the pre-fix bug) makes the encoder silently encode
 * DE-INTERLEAVED PLANES: the bitstream is still standard T.81 and libjpeg's
 * own decode cancels the error (self-roundtrip "passes"), but standard
 * decoders (LibRaw/DNG-SDK/Resolve, tool/src/ljpeg_ref.rs) read wrong
 * pixels (78% mismatch on A001 f1). The Rust side (tileenc::encode_planes)
 * now builds per-pixel rows.
 *
 * Output (ljpeg_decode_lossless) is per-pixel interleaved as well:
 * row y = [c0(x=0), c1(x=0), ...] — the Rust side splits it into the two
 * component planes.
 *
 * Encode notes (libjpeg-turbo 3.2.0, BITS_IN_JSAMPLE=8 build):
 * - 10/12-bit precision lossless input MUST go through
 *   jpeg12_write_scanlines (the 12-bit variant rejects
 *   data_precision < 9 in lossless mode; jpeg_write_scanlines, the
 *   8-bit variant, accepts 2..8).
 * - 8-bit precision lossless MUST go through the plain
 *   jpeg_write_scanlines / jpeg_read_scanlines (8-bit JSAMPLE rows, the
 *   same APIs the DCT lossy path below uses); the input rows are
 *   converted from the interleaved shorts at the boundary (values fit
 *   in a byte), and the decode output is converted back to the
 *   interleaved shorts — the short* ABI contract is unchanged.
 * - in_color_space=JCS_UNKNOWN + input_components=2 makes jpeg_set_defaults
 *   (and the lossless re-default in jinit_compress_master) keep
 *   num_components=2 with 1x1 sampling (JCS_GRAYSCALE/RGB would force 1/3).
 * - jpeg_enable_lossless sets master->lossless + Ss/Se/Ah/Al; lossless mode
 *   forces optimize_coding=TRUE inside libjpeg → 2-pass encode with
 *   per-stream (per-tile) optimized Huffman tables (the DNG "per-tile
 *   tables" property). Per-component tables (the Resolve media-
 * offline fix): reference emits TWO DC tables — table 0 fitted to
 *   component 0 (left-diff stream) and table 1 fitted to component 1
 *   (up-diff stream) — with SOS selectors (0,0),(1,0). libjpeg's lossless
 *   path supports this natively for statistics (jclhuff count_ptrs are
 *   keyed by dc_tbl_no, bound when the gather pass starts) and for DHT
 *   emission (write_scan_header emits dc_tbl_no per component in lossless
 *   mode). Two unpatched-libjpeg blockers, both fixed by
 *   deps/libjpeg-percomp-lossless.patch (build with deps/build-libjpeg.sh,
 *   JPEG_TURBO_PREFIX): (1) jpeg_default_colorspace() inside
 *   jinit_c_master_control — i.e. DURING jpeg_start_compress, before the
 *   gather pass binds the count tables — resets dc_tbl_no to 0 (this is
 *   why the original "force dc_tbl_no=1" attempt looked ineffective);
 *   (2) emit_sos() writes the DC selector nibble only when Ss==0 &&
 *   Ah==0, and in lossless mode Ss = PSV (7), so it would emit (0,0),
 *   (0,0) for any table assignment. Setting comp_info[1].dc_tbl_no=1
 *   here sticks with the patched library; against an unpatched one the
 *   values are reset and the encoder falls back to the legacy single
 * merged-DHT output (valid, but not reference-compatible).
 */
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jpeglib.h>

/* Extended error manager: the jpeg_error_mgr plus our own jmpbuf (the
 * library's struct has no jmpbuf member). */
typedef struct {
  struct jpeg_error_mgr pub;
  jmp_buf env;
} my_err;

typedef struct {
  struct jpeg_compress_struct c;
  my_err e;
  char errbuf[256];
} ljpeg_comp;

typedef struct {
  struct jpeg_decompress_struct c;
  my_err e;
  char errbuf[256];
} ljpeg_decomp;

/* Error exit: format the message with the DEFAULT handler (do NOT override
 * format_message with this function — it would recurse into itself), copy
 * it into the handle's errbuf, longjmp back. */
static void shim_err_exit(j_common_ptr cinfo) {
  void *h = cinfo->client_data;
  char buf[256];
  (*cinfo->err->format_message)(cinfo, buf);
  if (cinfo->is_decompressor) {
    ljpeg_decomp *d = (ljpeg_decomp *)h;
    strncpy(d->errbuf, buf, sizeof(d->errbuf) - 1);
    d->errbuf[sizeof(d->errbuf) - 1] = 0;
  } else {
    ljpeg_comp *cc = (ljpeg_comp *)h;
    strncpy(cc->errbuf, buf, sizeof(cc->errbuf) - 1);
    cc->errbuf[sizeof(cc->errbuf) - 1] = 0;
  }
  longjmp(((my_err *)cinfo->err)->env, 1);
}

/* ---------------------------------------------------------------- encode */

ljpeg_comp *ljpeg_comp_new(void) {
  ljpeg_comp *h = (ljpeg_comp *)calloc(1, sizeof(ljpeg_comp));
  return h;
}

void ljpeg_comp_free(ljpeg_comp *h) { free(h); }

/* Free a buffer returned by ljpeg_encode_lossless2 (malloc'd by libjpeg's
 * jpeg_mem_dest). */
void ljpeg_free_buffer(void *p) { free(p); }

const char *ljpeg_comp_error(ljpeg_comp *h) {
  if (h->errbuf[0] != 0) return h->errbuf;
  return "unknown libjpeg error";
}

/* Encode `height` rows x `width` samples (2 components, PER-PIXEL
 * interleaved per row: row y = [c0(0), c1(0), c0(1), c1(1), ...], see the
 * file header for why) as a lossless SOF3 JPEG stream of `precision` bits
 * per sample (8, 10 or 12 — the SOF3 precision field and the DC category
 * width follow it). `rows` must hold height * 2 * width shorts. On
 * success returns 0; *outbuf is malloc'd by libjpeg (caller frees with
 * free()). Nonzero return: see ljpeg_comp_error. `psv` = predictor
 * selection value (1..7, libjpeg numbering). */
int ljpeg_encode_lossless2(ljpeg_comp *h, const short *rows, int width,
                           int height, int psv, int precision,
                           unsigned char **outbuf, unsigned long *outsize) {
  h->errbuf[0] = 0;
  *outbuf = NULL;
  *outsize = 0;

  if (precision < 8 || precision > 12) {
    snprintf(h->errbuf, sizeof(h->errbuf),
             "unsupported data precision %d (lossless needs 8..12)", precision);
    return -1;
  }

  jpeg_std_error(&h->e.pub); // default handlers (output_message, emit_message, format_message)
  h->e.pub.error_exit = shim_err_exit;
  h->c.err = &h->e.pub;
  h->c.client_data = h;

  if (setjmp(h->e.env)) {
    jpeg_destroy_compress(&h->c);
    return -1;
  }

  jpeg_create_compress(&h->c);
  h->c.image_width = (JDIMENSION)width;
  h->c.image_height = (JDIMENSION)height;
  h->c.in_color_space = JCS_UNKNOWN;
  h->c.input_components = 2;
  jpeg_set_defaults(&h->c);
  /* Per-component lossless Huffman tables (reference structure): component
   * 1 uses DC table 1 → its own optimized DHT (TT=01) + SOS selector
   * (1,0). Requires the patched libjpeg (deps/build-libjpeg.sh): unpatched
   * libjpeg's jpeg_default_colorspace() resets dc_tbl_no during
   * jpeg_start_compress (before the gather pass binds the per-sample
   * count tables), silently collapsing this back to the single merged
   * DHT. */
  if (h->c.num_components >= 2)
    h->c.comp_info[1].dc_tbl_no = 1;
  h->c.data_precision = precision;
  jpeg_enable_lossless(&h->c, psv, 0 /* Pt */);
  jpeg_mem_dest(&h->c, outbuf, outsize);
  jpeg_start_compress(&h->c, TRUE);

  /* Write in 64-row chunks (rows are contiguous: row y is at rows + y*2*width).
   * Precision 8 goes through the plain 8-bit scanline API (see the header
   * notes); 10/12 through jpeg12_write_scanlines. */
  if (precision <= 8) {
    /* Per-pixel interleaved u8 rows (2*width bytes per row), converted
     * from the interleaved short rows (the values fit in a byte at
     * data_precision <= 8). */
    size_t rowbytes = (size_t)height * 2 * (size_t)width;
    unsigned char *u8 = (unsigned char *)malloc(rowbytes);
    if (u8 == NULL) {
      snprintf(h->errbuf, sizeof(h->errbuf), "out of memory");
      jpeg_destroy_compress(&h->c);
      return -1;
    }
    for (size_t i = 0; i < rowbytes; i++)
      u8[i] = (unsigned char)rows[i];
    JSAMPROW rowptr[64];
    while (h->c.next_scanline < h->c.image_height) {
      int y0 = (int)h->c.next_scanline;
      int n = (int)(h->c.image_height - (JDIMENSION)y0);
      if (n > 64) n = 64;
      for (int i = 0; i < n; i++)
        rowptr[i] = u8 + (size_t)(y0 + i) * 2 * (size_t)width;
      (void)jpeg_write_scanlines(&h->c, rowptr, (JDIMENSION)n);
    }
    free(u8);
  } else {
    J12SAMPROW rowptr[64];
    while (h->c.next_scanline < h->c.image_height) {
      int y0 = (int)h->c.next_scanline;
      int n = (int)(h->c.image_height - (JDIMENSION)y0);
      if (n > 64) n = 64;
      for (int i = 0; i < n; i++)
        rowptr[i] = (J12SAMPROW)(rows + (JDIMENSION)(y0 + i) * 2 * width);
      (void)jpeg12_write_scanlines(&h->c, rowptr, (JDIMENSION)n);
    }
  }

  jpeg_finish_compress(&h->c);
  jpeg_destroy_compress(&h->c);
  return 0;
}

/* ----------------------------------------------------------------- decode */

ljpeg_decomp *ljpeg_decomp_new(void) {
  ljpeg_decomp *h = (ljpeg_decomp *)calloc(1, sizeof(ljpeg_decomp));
  return h;
}

void ljpeg_decomp_free(ljpeg_decomp *h) { free(h); }
const char *ljpeg_decomp_error(ljpeg_decomp *h) {
  if (h->errbuf[0] != 0) return h->errbuf;
  return "unknown libjpeg error";
}

/* Decode a lossless (SOF3) JPEG stream (any component count; this project
 * uses 2; precision 8, 10 or 12). `expected_precision` = 0 accepts any
 * precision, otherwise the stream's SOF3 precision must match it. On
 * success returns 0 and *out is a malloc'd array of height * ncomp * width
 * shorts, rows PER-PIXEL interleaved ([comp0(x=0), comp1(x=0), comp0(x=1),
 * ...] — the standard libjpeg multi-component output layout). Caller frees
 * with free(). Returns 2 if the stream precision does not match. */
int ljpeg_decode_lossless(ljpeg_decomp *h, const unsigned char *buf, long len,
                          short **out, int *width, int *height, int *ncomp,
                          int expected_precision) {
  h->errbuf[0] = 0;
  *out = NULL;

  jpeg_std_error(&h->e.pub);
  h->e.pub.error_exit = shim_err_exit;
  h->c.err = &h->e.pub;
  h->c.client_data = h;

  if (setjmp(h->e.env)) {
    jpeg_destroy_decompress(&h->c);
    return -1;
  }

  jpeg_create_decompress(&h->c);
  jpeg_mem_src(&h->c, buf, (unsigned long)len);
  jpeg_read_header(&h->c, TRUE);
  if (expected_precision != 0 && h->c.data_precision != expected_precision) {
    char msg[64];
    snprintf(msg, sizeof(msg), "unexpected data precision %d (need %d)",
             h->c.data_precision, expected_precision);
    strncpy(h->errbuf, msg, sizeof(h->errbuf) - 1);
    h->errbuf[sizeof(h->errbuf) - 1] = 0;
    jpeg_destroy_decompress(&h->c);
    return 2;
  }
  jpeg_start_decompress(&h->c);

  int w = (int)h->c.output_width;
  int ht = (int)h->c.output_height;
  int nc = h->c.num_components;
  *width = w;
  *height = ht;
  *ncomp = nc;

  short *data = (short *)malloc((size_t)ht * nc * w * sizeof(short));
  if (data == NULL) {
    snprintf(h->errbuf, sizeof(h->errbuf), "out of memory");
    jpeg_destroy_decompress(&h->c);
    return -1;
  }

  if (h->c.data_precision <= 8) {
    /* Precision 8: the plain 8-bit scanline API (the 12-bit variant
     * rejects data_precision < 9 in lossless mode). Read u8 rows and
     * convert to the interleaved short output (the ABI contract). */
    JSAMPROW rowptr[64];
    size_t outw = (size_t)nc * (size_t)w;
    unsigned char *u8row = (unsigned char *)malloc(outw);
    if (u8row == NULL) {
      snprintf(h->errbuf, sizeof(h->errbuf), "out of memory");
      jpeg_destroy_decompress(&h->c);
      free(data);
      return -1;
    }
    int y = 0;
    while (y < ht) {
      int n = ht - y;
      if (n > 64) n = 64;
      for (int i = 0; i < n; i++)
        rowptr[i] = u8row + (size_t)i * outw;
      JDIMENSION got = jpeg_read_scanlines(&h->c, rowptr, (JDIMENSION)n);
      if (got == 0) {
        snprintf(h->errbuf, sizeof(h->errbuf),
                 "decode stopped at row %d of %d", y, ht);
        jpeg_destroy_decompress(&h->c);
        free(data);
        free(u8row);
        return -1;
      }
      for (int i = 0; i < (int)got; i++)
        for (size_t x = 0; x < outw; x++)
          data[(size_t)(y + i) * outw + x] = (short)u8row[(size_t)i * outw + x];
      y += (int)got;
    }
    free(u8row);
  } else {
    J12SAMPROW rowptr[64];
    int y = 0;
    while (y < ht) {
      int n = ht - y;
      if (n > 64) n = 64;
      for (int i = 0; i < n; i++)
        rowptr[i] = (J12SAMPROW)(data + (size_t)(y + i) * nc * w);
      /* Lossless mode: the main controller yields at most ONE output row per
       * call (one iMCU row = one sample row), so advance by the returned
       * count, never by the requested count. */
      JDIMENSION got = jpeg12_read_scanlines(&h->c, rowptr, (JDIMENSION)n);
      if (got == 0) {
        snprintf(h->errbuf, sizeof(h->errbuf),
                 "decode stopped at row %d of %d", y, ht);
        jpeg_destroy_decompress(&h->c);
        free(data);
        return -1;
      }
      y += (int)got;
    }
  }

  jpeg_finish_decompress(&h->c);
  jpeg_destroy_decompress(&h->c);
  *out = data;
  return 0;
}

/* ----------------------------------------------------------- lossy (DCT) */

/* Baseline DCT (SOF0) encode, SINGLE component, 8-bit. This is the lossy
 * cDNG (Compression 34892, LinearRaw) tile encoder: each DNG tile is ONE
 * self-contained baseline JPEG whose SOF width/height EQUAL the tile area
 * and whose component count EQUALS the plane count (1 for mono LinearRaw).
 * The reference decoders enforce both: the DNG SDK dng_read_image::
 * DecodeLossyJPEG checks imageWidth==tileArea.W() && imageHeight==
 * tileArea.H() && numComponents==planes, and LibRaw lossy_dng_load_raw
 * checks cinfo.output_components==colors. `rows` holds height*width bytes,
 * row-major (1 sample/px). On success returns 0; *outbuf is malloc'd by
 * libjpeg (caller frees with ljpeg_free_buffer). Nonzero: ljpeg_comp_error.
 * `quality` is 1..100 (JPEG quality; higher = larger file). */
int ljpeg_encode_lossy1(ljpeg_comp *h, const unsigned char *rows, int width,
                         int height, int quality,
                         unsigned char **outbuf, unsigned long *outsize) {
  h->errbuf[0] = 0;
  *outbuf = NULL;
  *outsize = 0;

  if (quality < 1) quality = 1;
  if (quality > 100) quality = 100;

  jpeg_std_error(&h->e.pub);
  h->e.pub.error_exit = shim_err_exit;
  h->c.err = &h->e.pub;
  h->c.client_data = h;

  if (setjmp(h->e.env)) {
    jpeg_destroy_compress(&h->c);
    return -1;
  }

  jpeg_create_compress(&h->c);
  h->c.image_width = (JDIMENSION)width;
  h->c.image_height = (JDIMENSION)height;
  h->c.in_color_space = JCS_GRAYSCALE;
  h->c.input_components = 1;
  jpeg_set_defaults(&h->c);
  jpeg_set_quality(&h->c, quality, TRUE /* force baseline DCT */);
  jpeg_mem_dest(&h->c, outbuf, outsize);
  jpeg_start_compress(&h->c, TRUE);

  JSAMPROW rowptr[64];
  while (h->c.next_scanline < h->c.image_height) {
    int y0 = (int)h->c.next_scanline;
    int n = (int)(h->c.image_height - (JDIMENSION)y0);
    if (n > 64) n = 64;
    for (int i = 0; i < n; i++)
      rowptr[i] = (JSAMPROW)(rows + (size_t)(y0 + i) * width);
    (void)jpeg_write_scanlines(&h->c, rowptr, (JDIMENSION)n);
  }

  jpeg_finish_compress(&h->c);
  jpeg_destroy_compress(&h->c);
  return 0;
}

/* Baseline DCT (SOF1) encode, SINGLE component, **12-bit samples**,
 * custom 16-bit quantization table. The reference tag-7 (Compression 7,
 * "12-bit DCT parity tiles") encoder leg: one call encodes ONE parity
 * plane (1928x544) of ONE tile; the Rust side stitches the two planes
 * into the two-scan reference tile. Verified: this exact pipeline (12-bit centered at
 * 2048, islow DCT, DC chain from 0) is what the tag-7 decoder unwinds
 * with vpred0 = 16384 = 8 x 2048 (islow DC scale) — a standard 12-bit
 * encode round-trips through the tag-7 decoder (flat-image MAE 0.0).
 * `table` is 64 quantization values in zigzag order (16-bit precision;
 * libjpeg stores them verbatim — values <= 4095 keep the 12-bit
 * coefficient range legal). `optimize_coding` is forced: the standard
 * 12-bit DC Huffman table has only 12 code lengths, but 12-bit DC
 * differences can need up to 15 (libjpeg's own 12-bit path forces this
 * for standard tables; with a custom table the caller must). The stream
 * layout is SOI [+JFIF APP0] DQT (8-bit if all table values <= 255,
 * 16-bit otherwise) DHT 00/10 SOF0/1 SOS scandata EOI; the Rust side
 * strips the APP0, re-emits the DQT as 16-bit, relabels the second
 * plane's DHTs to 01/11, builds the 2-component SOF1 and patches the
 * reference SOS payloads. `rows` holds height*width 16-bit samples
 * (0..4095), row-major. On success returns 0; *outbuf is malloc'd by
 * libjpeg (caller frees with ljpeg_free_buffer). Nonzero:
 * ljpeg_comp_error. */
int ljpeg_encode_dct12(ljpeg_comp *h, const short *rows, int width,
                        int height, const unsigned short *table,
                        unsigned char **outbuf, unsigned long *outsize) {
  h->errbuf[0] = 0;
  *outbuf = NULL;
  *outsize = 0;

  jpeg_std_error(&h->e.pub);
  h->e.pub.error_exit = shim_err_exit;
  h->c.err = &h->e.pub;
  h->c.client_data = h;

  if (setjmp(h->e.env)) {
    jpeg_destroy_compress(&h->c);
    return -1;
  }

  jpeg_create_compress(&h->c);
  h->c.image_width = (JDIMENSION)width;
  h->c.image_height = (JDIMENSION)height;
  h->c.input_components = 1;
  h->c.in_color_space = JCS_GRAYSCALE;
  /* precision BEFORE set_defaults (the example.c order; set_defaults
   * seeds the 12-bit pipeline + the per-precision tables from it). */
  h->c.data_precision = 12;
  jpeg_set_defaults(&h->c);
  unsigned int table32[64];
  for (int k = 0; k < 64; k++) table32[k] = table[k];
  /* This libjpeg-turbo build's API: (cinfo, which_tbl, basic_table,
   * scale_factor, force_baseline) — the table is in zigzag/interchange
   * order; scale_factor 100 = use it verbatim (any other value scales
   * the table and a 1 meant "1%" = an all-ones table). */
  jpeg_add_quant_table(&h->c, 0, table32, 100 /* as-is */, TRUE /* baseline */);
  h->c.optimize_coding = TRUE;
  jpeg_mem_dest(&h->c, outbuf, outsize);
  jpeg_start_compress(&h->c, TRUE);

  J12SAMPROW rowptr[64];
  while (h->c.next_scanline < h->c.image_height) {
    int y0 = (int)h->c.next_scanline;
    int n = (int)(h->c.image_height - (JDIMENSION)y0);
    if (n > 64) n = 64;
    for (int i = 0; i < n; i++)
      rowptr[i] = (J12SAMPROW)(rows + (size_t)(y0 + i) * width);
    (void)jpeg12_write_scanlines(&h->c, rowptr, (JDIMENSION)n);
  }

  jpeg_finish_compress(&h->c);
  jpeg_destroy_compress(&h->c);
  return 0;
}

/* Baseline (SOF1) encode from PRE-COMPUTED DCT coefficients, SINGLE
 * component, 12-bit. The fix: this libjpeg-
turbo rebuild's 12-bit islow forward DCT writes odd-frequency-row
 * coefficients at the wrong per-row scale (measured: row v = 3, 5, 7 at
 * 2.09x / 3.25x / 4.45x the islow convention; the 8-bit workhorse path is
 * correct), so the Rust side computes the DCT itself (exact inverse of the
 * reference-verified dct2s IDCT) and hands the encoder dequantized
 * coefficients through libjpeg's raw-coefficient API (jpeg_write_
 * coefficients) — libjpeg does only the DC prediction + 2-pass Huffman
 * optimization + bitstream, and emits the same stream structure as
 * ljpeg_encode_dct12 (SOI APP0 DQT DHT 00/10 SOF1 SOS data EOI).
 * `coeffs` holds (height/8 * width/8 * 64) 16-bit dequantized
 * coefficients, natural (row-major 8x8) order, blocks in raster order;
 * the DC (slot 0 of each block) is CENTERED (the dequantized islow DC:
 * 8 * (block mean - 2048)), matching the decoder's vpred chain
 * (vpred0 = 16384 = 8 * 2048). AC values are the dequantized coefficient
 * (rounded X_orth * q), i.e. exact multiples of the corresponding table
 * entry indexed by FILE/zigzag position. `table` is 64 quantization
 * values in zigzag order. On success returns 0; *outbuf is malloc'd by
 * libjpeg (caller frees with ljpeg_free_buffer). Nonzero:
 * ljpeg_comp_error. */
int ljpeg_encode_coeff12(ljpeg_comp *h, const short *coeffs, int width,
                          int height, const unsigned short *table,
                          unsigned char **outbuf, unsigned long *outsize) {
  h->errbuf[0] = 0;
  *outbuf = NULL;
  *outsize = 0;

  if ((width % 8) != 0 || (height % 8) != 0) {
    snprintf(h->errbuf, sizeof(h->errbuf),
             "raw-coefficient encode needs block-multiple dims (%dx%d)",
             width, height);
    return -1;
  }

  jpeg_std_error(&h->e.pub);
  h->e.pub.error_exit = shim_err_exit;
  h->c.err = &h->e.pub;
  h->c.client_data = h;

  if (setjmp(h->e.env)) {
    jpeg_destroy_compress(&h->c);
    return -1;
  }

  jpeg_create_compress(&h->c);
  h->c.image_width = (JDIMENSION)width;
  h->c.image_height = (JDIMENSION)height;
  h->c.input_components = 1;
  h->c.in_color_space = JCS_GRAYSCALE;
  /* precision BEFORE set_defaults (same order as ljpeg_encode_dct12). */
  h->c.data_precision = 12;
  jpeg_set_defaults(&h->c);
  unsigned int table32[64];
  for (int k = 0; k < 64; k++) table32[k] = table[k];
  jpeg_add_quant_table(&h->c, 0, table32, 100 /* as-is */, TRUE /* baseline */);
  h->c.optimize_coding = TRUE;
  jpeg_mem_dest(&h->c, outbuf, outsize);

  /* Virtual coefficient array (one component): height/8 rows of
   * width/8 JBLOCKs. */
  JDIMENSION blk_w = (JDIMENSION)(width / 8);
  JDIMENSION blk_h = (JDIMENSION)(height / 8);
  jvirt_barray_ptr va = (*h->c.mem->request_virt_barray)
    ((j_common_ptr)&h->c, JPOOL_IMAGE, TRUE /* pre_zero */,
     blk_w, blk_h, blk_h /* max access: all rows at once */);
  /* The array must be REALIZED before access (the transcode flow realizes
   * caller-supplied arrays before jpeg_write_coefficients; ours is fresh). */
  (*h->c.mem->realize_virt_arrays) ((j_common_ptr)&h->c);
  JBLOCKARRAY arr = (*h->c.mem->access_virt_barray)
    ((j_common_ptr)&h->c, va, 0, blk_h, TRUE);
  for (JDIMENSION r = 0; r < blk_h; r++)
    memcpy(arr[r], coeffs + (size_t)r * blk_w * 64, blk_w * 64 * sizeof(short));

  jpeg_write_coefficients(&h->c, &va);
  jpeg_finish_compress(&h->c);
  jpeg_destroy_compress(&h->c);
  return 0;
}

/* Baseline DCT (SOF0) decode, 8-bit. Inverse of ljpeg_encode_lossy1. On
 * success returns 0 and out is a malloc'd array of height*ncomp*width
 * bytes (row-major), with width, height and ncomp set from the stream's SOF.
 * Caller frees out with ljpeg_free_buffer. */
int ljpeg_decode_lossy1(ljpeg_decomp *h, const unsigned char *buf, long len,
                         unsigned char **out, int *width, int *height,
                         int *ncomp) {
  h->errbuf[0] = 0;
  *out = NULL;

  jpeg_std_error(&h->e.pub);
  h->e.pub.error_exit = shim_err_exit;
  h->c.err = &h->e.pub;
  h->c.client_data = h;

  if (setjmp(h->e.env)) {
    jpeg_destroy_decompress(&h->c);
    return -1;
  }

  jpeg_create_decompress(&h->c);
  jpeg_mem_src(&h->c, buf, (unsigned long)len);
  jpeg_read_header(&h->c, TRUE);
  jpeg_start_decompress(&h->c);

  int w = (int)h->c.output_width;
  int ht = (int)h->c.output_height;
  int nc = (int)h->c.output_components;
  *width = w;
  *height = ht;
  *ncomp = nc;

  unsigned char *data =
      (unsigned char *)malloc((size_t)ht * nc * w);
  if (data == NULL) {
    snprintf(h->errbuf, sizeof(h->errbuf), "out of memory");
    jpeg_destroy_decompress(&h->c);
    return -1;
  }

  JSAMPROW rowptr[64];
  int y = 0;
  while (y < ht) {
    int n = ht - y;
    if (n > 64) n = 64;
    for (int i = 0; i < n; i++)
      rowptr[i] = (JSAMPROW)(data + (size_t)(y + i) * nc * w);
    JDIMENSION got = jpeg_read_scanlines(&h->c, rowptr, (JDIMENSION)n);
    if (got == 0) {
      snprintf(h->errbuf, sizeof(h->errbuf),
               "decode stopped at row %d of %d", y, ht);
      jpeg_destroy_decompress(&h->c);
      free(data);
      return -1;
    }
    y += (int)got;
  }

  jpeg_finish_decompress(&h->c);
  jpeg_destroy_decompress(&h->c);
  *out = data;
  return 0;
}