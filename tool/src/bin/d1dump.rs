//! t20a scratch: dump the standard 1-component 12-bit JPEG that encode_plane
//! emits (pre-stitch), so independent decoders (Pillow, djpeg) can verify
//! whether libjpeg's 12-bit DCT coefficients are faithful to the input.
use frameprism::lossydct;

fn main() {
    let plane: Vec<u16> = (0..(lossydct::PLANE_W * lossydct::PLANE_H))
        .map(|i| if i % 2 == 0 { 2148 } else { 1948 })
        .collect();
    let tile = lossydct::encode_plane(&plane, &lossydct::BASE_TABLE).unwrap();
    std::fs::write("/tmp/d1_plane.jpg", &tile).unwrap();
    println!("wrote /tmp/d1_plane.jpg ({} bytes)", tile.len());
}
