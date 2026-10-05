//! Amlogic `@AML` image containers.
//!
//! Clean-room implementation from the layout observed on a real device tree image, with every
//! field cross-checked against that file rather than copied from a reference.
//!
//! Layout (little-endian), as observed on STB-JHSD200-5.7.1 `dt.img`:
//!
//! ```
//! 0x0000  magic          4 bytes  "@AML"
//! 0x0004  version        u32      4 on the observed file
//! 0x0010  image_size     u32      length of the payload that follows the header
//! 0x0014  align_size     u32      header is padded to this; 512 on the observed file
//! 0x0018  payload        image_size bytes
//! ```
//!
//! The invariant `file_len == align_size + image_size` holds on the observed file exactly
//! (512 + 80384 = 80896), which is what this parser checks.
//!
//! SECURE BOOT: on the observed device the payload is encrypted - Shannon entropy 7.997 bits
//! per byte across every 4 KiB block. An encrypted container cannot be unpacked without a
//! device key, so this module identifies and describes the container and says plainly that the
//! payload is encrypted. It never guesses at plaintext.
use anyhow::{Context, Result, ensure};

/// The magic every Amlogic image container starts with.
pub const MAGIC: [u8; 4] = *b"@AML";

/// True when `head` could be the start of an Amlogic container.
pub fn is_aml(head: &[u8]) -> bool {
    head.len() >= 4 && head[..4] == MAGIC
}

/// A parsed Amlogic image header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u32,
    /// Length of the payload after the aligned header.
    pub image_size: u32,
    /// The header is padded out to this many bytes.
    pub align_size: u32,
}

impl Header {
    /// Where the payload starts.
    pub fn payload_offset(&self) -> u64 {
        self.align_size as u64
    }
}

/// Parse the header of a container, cross-checking it against the real file length.
pub fn parse(data: &[u8]) -> Result<Header> {
    ensure!(is_aml(data), "not an Amlogic container: missing @AML magic");
    ensure!(data.len() >= 0x18, "Amlogic header is truncated");
    let le = |off: usize| u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
    let h = Header {
        version: le(4),
        image_size: le(0x10),
        align_size: le(0x14),
    };
    ensure!(
        h.align_size >= 0x18,
        "align size {} is smaller than the header",
        h.align_size
    );
    // The strongest check available: the declared sizes must account for the whole file.
    let declared = h.payload_offset() + h.image_size as u64;
    ensure!(
        declared == data.len() as u64,
        "Amlogic header accounts for {declared} bytes but the file is {}",
        data.len()
    );
    Ok(h)
}

/// Shannon entropy of `data`, in bits per byte.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Above this entropy a payload is treated as encrypted or compressed rather than a plain
/// device tree. Text and device-tree data sit far below 8.
pub const ENCRYPTED_THRESHOLD: f64 = 7.9;

/// A container, described.
#[derive(Debug, Clone)]
pub struct Image {
    pub header: Header,
    pub file_len: u64,
    /// Entropy of the payload region.
    pub payload_entropy: f64,
}

impl Image {
    /// True when the payload looks encrypted rather than plain data.
    pub fn is_encrypted(&self) -> bool {
        self.payload_entropy >= ENCRYPTED_THRESHOLD
    }
}

/// Describe a container held in memory.
pub fn describe(data: &[u8]) -> Result<Image> {
    let header = parse(data)?;
    let start = header.payload_offset() as usize;
    let payload = data.get(start..).unwrap_or_default();
    Ok(Image {
        header,
        file_len: data.len() as u64,
        payload_entropy: entropy(payload),
    })
}

/// Describe a container on disk.
pub fn describe_file(path: &std::path::Path) -> Result<Image> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    describe(&data)
}

/// A human-readable summary. Says plainly when the payload is encrypted.
pub fn to_text(img: &Image, name: &str) -> String {
    let mut o = Vec::new();
    o.push(format!("{name}: Amlogic image container (@AML)"));
    o.push(format!("  version      {}", img.header.version));
    o.push(format!(
        "  header       {} bytes (aligned)",
        img.header.align_size
    ));
    o.push(format!("  payload      {} bytes", img.header.image_size));
    o.push(format!("  total        {} bytes", img.file_len));
    o.push(format!(
        "  entropy      {:.3} bits/byte",
        img.payload_entropy
    ));
    if img.is_encrypted() {
        o.push(String::from(
            "  status       PAYLOAD IS ENCRYPTED (secure boot) - it cannot be read without a",
        ));
        o.push(String::from(
            "               device key. This is expected on a production Amlogic image.",
        ));
    } else {
        o.push(String::from(
            "  status       payload is plain data and can be inspected",
        ));
    }
    o.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a container with the same shape as the observed real file.
    fn synth(payload_len: usize, version: u32, entropy_payload: bool) -> Vec<u8> {
        let align = 512u32;
        let mut v = vec![0u8; align as usize + payload_len];
        v[..4].copy_from_slice(&MAGIC);
        v[4..8].copy_from_slice(&version.to_le_bytes());
        v[0x10..0x14].copy_from_slice(&(payload_len as u32).to_le_bytes());
        v[0x14..0x18].copy_from_slice(&align.to_le_bytes());
        if entropy_payload {
            // A cheap deterministic spread so entropy is high without a dependency.
            let mut x: u32 = 0x1234_5678;
            for b in &mut v[align as usize..] {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *b = (x >> 16) as u8;
            }
        }
        v
    }

    #[test]
    fn a_valid_header_parses_and_accounts_for_the_whole_file() {
        let d = synth(4096, 4, false);
        let h = parse(&d).unwrap();
        assert_eq!(h.version, 4);
        assert_eq!(h.align_size, 512);
        assert_eq!(h.image_size, 4096);
        assert_eq!(h.payload_offset(), 512);
    }

    #[test]
    fn a_wrong_magic_is_refused() {
        let mut d = synth(16, 4, false);
        d[0] = b'X';
        assert!(parse(&d).is_err());
        assert!(!is_aml(&d));
    }

    #[test]
    fn a_lying_size_is_refused_rather_than_trusted() {
        let mut d = synth(4096, 4, false);
        d[0x10..0x14].copy_from_slice(&999_999u32.to_le_bytes());
        let e = parse(&d).unwrap_err().to_string();
        assert!(e.contains("accounts for"), "{e}");
    }

    #[test]
    fn a_truncated_file_is_an_error_not_a_panic() {
        for n in [0usize, 3, 4, 8, 0x17] {
            assert!(
                parse(&synth(16, 4, false)[..n]).is_err(),
                "cut at {n} must be refused"
            );
        }
    }

    #[test]
    fn an_align_size_smaller_than_the_header_is_refused() {
        let mut d = synth(64, 4, false);
        d[0x14..0x18].copy_from_slice(&4u32.to_le_bytes());
        assert!(parse(&d).is_err());
    }

    #[test]
    fn a_high_entropy_payload_is_reported_as_encrypted() {
        let img = describe(&synth(65536, 4, true)).unwrap();
        assert!(img.is_encrypted(), "entropy was {:.3}", img.payload_entropy);
        let text = to_text(&img, "dt.img");
        assert!(text.contains("ENCRYPTED"), "{text}");
    }

    #[test]
    fn a_low_entropy_payload_is_not_called_encrypted() {
        let img = describe(&synth(65536, 4, false)).unwrap();
        assert!(
            !img.is_encrypted(),
            "entropy was {:.3}",
            img.payload_entropy
        );
    }

    #[test]
    fn the_real_device_tree_is_recognised_and_reported_encrypted() {
        // Read-only, skipped when the firmware is not present.
        let p = "/Users/vaibhavtomar/Downloads/STB-JHSD200-5.7.1/dt.img";
        if !std::path::Path::new(p).exists() {
            return;
        }
        let img = describe_file(std::path::Path::new(p)).unwrap();
        assert_eq!(img.header.align_size, 512);
        assert_eq!(img.file_len, 80896);
        assert!(img.is_encrypted(), "this device encrypts its dt payload");
    }
}
