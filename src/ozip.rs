//! Oppo/Realme `.ozip` decryption.
//!
//! An ozip is an AES-128-ECB encrypted ZIP. The format carries no key material: each device
//! model has a published AES key, and the right one is identified by decrypting a 16-byte probe
//! and checking that the plaintext starts with a known magic. Layout:
//!
//! ```
//! 0x0000  magic "OPPOENCRYPT!" (12 bytes)
//! 0x0010  16 bytes of ASCII decimal: the decompressed size
//! 0x0050  16 bytes of AES-128-ECB ciphertext (the key probe)
//! 0x1050  the encrypted payload, in 0x4000-byte ECB blocks
//! ```
//!
//! Format and key table follow B. Kerler's `oppo_ozip_decrypt` (MIT).
use aes::cipher::{BlockCipherDecrypt, KeyInit};
use aes::{Aes128, Block};
use anyhow::{Context, Result, bail, ensure};
use std::io::Read;
use std::path::Path;

const MAGIC: &[u8; 12] = b"OPPOENCRYPT!";
/// The 16-byte key probe sits here.
const PROBE_OFF: usize = 0x50;
/// The encrypted payload starts here.
const PAYLOAD_OFF: usize = 0x1050;
/// Payload is encrypted in 16-byte AES blocks; the format chunks these in pages of
/// this size when it writes the file.
#[allow(dead_code)]
const BLOCK: usize = 0x4000;

/// What a correct key produces when the probe is decrypted.
const MAGIC_ZIP: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const MAGIC_AVB: [u8; 4] = [0x41, 0x56, 0x42, 0x30];
const MAGIC_ANDR: [u8; 4] = [0x41, 0x4E, 0x44, 0x52];

/// The parsed fixed header.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    /// Length of the plaintext once decrypted.
    pub size: u64,
}

/// Parse and sanity-check the header.
pub fn parse_header(bytes: &[u8]) -> Result<Header> {
    ensure!(
        bytes.len() >= PAYLOAD_OFF,
        "ozip is too short: {} bytes, need at least {PAYLOAD_OFF}",
        bytes.len()
    );
    ensure!(&bytes[..12] == MAGIC, "not an ozip: bad magic");
    // A NUL-padded ASCII decimal field.
    let raw: Vec<u8> = bytes[0x10..0x20]
        .iter()
        .copied()
        .filter(|b| *b != 0)
        .collect();
    let text = std::str::from_utf8(&raw).context("ozip size field is not ASCII")?;
    let size: u64 = text
        .trim()
        .parse()
        .with_context(|| format!("ozip size field {text:?} is not a number"))?;
    Ok(Header { size })
}

/// Published device keys, as (model, 32 hex chars).
///
/// From B. Kerler's `oppo_ozip_decrypt` (MIT). An ozip from a model absent here cannot be
/// decrypted: the format does not carry the key.
const DEVICE_KEYS: &[(&str, &str)] = &[
    ("mnkey", "D6EECF0AE5ACD4E0E9FE522DE7CE381E"),
    ("mkey", "D6ECCF0AE5ACD4E0E92E522DE7C1381E"),
    (
        "R9s CPH1607 / RMX1921 / RMX1851EX",
        "D6DCCF0AD5ACD4E0292E522DB7C1381E",
    ),
    ("testkey", "D7DCCE1AD4AFDCE2393E5161CBDC4321"),
    ("utilkey", "D7DBCE2AD4ADDCE1393E5521CBDC4321"),
    ("R11s CPH1719 / Plus", "D7DBCE1AD4AFDCE1393E5121CBDC4321"),
    ("FindX CPH1871", "D4D2CD61D4AFDCE13B5E01221BD14D20"),
    ("FindX", "261CC7131D7C1481294E532DB752381E"),
    ("Realme 2 pro", "1CA21E12271335AE33AB81B2A7B14622"),
    ("K1 SDM660/MSM8976", "D4D2CE11D4AFDCE13B3E0121CBD14D20"),
    (
        "Realme 3 Pro / X / 5 Pro / Q",
        "1C4C1EA3A12531AE491B21BB31613C11",
    ),
    (
        "Reno 10x zoom / CPH1921EX",
        "1C4C1EA3A12531AE4A1B21BB31C13C21",
    ),
    ("Reno 2 PCKM00", "1C4A11A3A12513AE441B23BB31513121"),
    ("Realme X2", "1C4A11A3A12589AE441A23BB31517733"),
    ("Realme 5 SDM665", "1C4A11A3A22513AE541B53BB31513121"),
    ("R17 Pro SDM710", "2442CE821A4F352E33AE81B22BC1462E"),
    ("CPH1803 OppoA3s", "14C2CD6214CFDC2733AE81B22BC1462C"),
    ("A77 CPH1715", "2D23CCBBA1563519CE23C1C4AA1E3412"),
    ("Realme 1 MTK P60", "172B3E14E46F3CE13E2B5121CBDC4321"),
    ("Realme U1 RMX1831", "ACAA1E12A71431CE4A1B21BBA1C1C6A2"),
    ("Realme 3 RMX1825EX", "ACAC1E13A72531AE4A1B22BB31C1CC22"),
    ("A1k CPH1923", "1C4411A3A12533AE441B21BB31613C11"),
    (
        "Reno 3 PCRM00 / CPH2059 / CPH2067",
        "1C4416A8A42717AE441523B336513121",
    ),
    ("RenoAce SDM855Plus", "55EEAA33112133AE441B23BB31513121"),
    ("Reno / K3", "ACAC1E13A12531AE4A1B22BB31C13C21"),
    ("A9", "ACAC1E13A72431AE4A1B22BBA1C1C6A2"),
    ("A1 / A83t", "12CAC11211AAC3AEA2658690122C1E81"),
    ("CPH1909 OppoA5s", "1CA21E12271435AE331B81BBA7C14612"),
    ("Realme 1 (reserved)", "D1DACF24351CE428A9CE32ED87323216"),
];

/// How many keys are carried.
pub fn key_count() -> usize {
    DEVICE_KEYS.len()
}

/// Decrypt one 16-byte block with `key`.
/// Decrypt one 16-byte block in place.
///
/// `Block::from_mut_slice` is the simplest correct conversion here; the `TryFrom` spelling
/// needs a fully-qualified type that adds nothing at this size, so the lint is allowed for
/// this function only rather than across the crate.
#[allow(deprecated)]
fn decrypt_block(cipher: &Aes128, block: &mut [u8; 16]) {
    cipher.decrypt_block(Block::from_mut_slice(block));
}

/// The model whose key decrypts the probe to a known magic, and that key.
pub fn find_key(probe: &[u8]) -> Option<(&'static str, [u8; 16])> {
    ensure16(probe).ok()?;
    for (model, hex) in DEVICE_KEYS {
        let key = match decode_hex16(hex) {
            Some(k) => k,
            None => continue,
        };
        let cipher = Aes128::new_from_slice(&key).ok()?;
        let mut block = [0u8; 16];
        block.copy_from_slice(&probe[..16]);
        decrypt_block(&cipher, &mut block);
        if block[..4] == MAGIC_ZIP || block[..4] == MAGIC_AVB || block[..4] == MAGIC_ANDR {
            return Some((model, key));
        }
    }
    None
}

fn ensure16(p: &[u8]) -> Result<()> {
    ensure!(p.len() == 16, "probe must be 16 bytes");
    Ok(())
}

fn decode_hex16(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = (b[2 * i] as char).to_digit(16)?;
        let lo = (b[2 * i + 1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Decrypt an ozip into `out`, returning the plaintext length written.
///
/// `input` must yield the whole file: the header and probe live before the payload.
pub fn decrypt(input: &mut impl Read, out: &Path) -> Result<u64> {
    use std::io::Write;
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes)?;
    let header = parse_header(&bytes)?;
    let probe = &bytes[PROBE_OFF..PROBE_OFF + 16];
    let Some((_model, key)) = find_key(probe) else {
        bail!(
            "no known key decrypts this ozip ({} keys tried); the device may not be in the table",
            key_count()
        );
    };
    let cipher = Aes128::new_from_slice(&key)?;
    let payload = &bytes[PAYLOAD_OFF..];
    let tmp = out.with_extension("part");
    let mut f =
        std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    // The payload is a whole number of 16-byte blocks; the last plaintext block is truncated
    // to the declared size.
    let mut written: u64 = 0;
    for unit in payload.chunks_exact(16) {
        let mut block: [u8; 16] = [0; 16];
        block.copy_from_slice(unit);
        decrypt_block(&cipher, &mut block);
        let remaining = header.size.saturating_sub(written) as usize;
        if remaining == 0 {
            break;
        }
        let take = block.len().min(remaining);
        f.write_all(&block[..take])?;
        written += take as u64;
    }
    drop(f);
    ensure!(
        written == header.size,
        "ozip plaintext is {written} bytes but the header claims {}",
        header.size
    );
    std::fs::rename(&tmp, out)?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockCipherEncrypt;

    const TEST_KEY_HEX: &str = "D6DCCF0AD5ACD4E0292E522DB7C1381E";

    fn test_key() -> [u8; 16] {
        decode_hex16(TEST_KEY_HEX).unwrap()
    }

    /// Encrypt 16-byte blocks the way the format does, so we can build a fixture.
    #[allow(deprecated)]
    fn encrypt(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let cipher = Aes128::new_from_slice(key).unwrap();
        let mut out = Vec::with_capacity(data.len());
        let mut carry: Vec<u8> = Vec::new();
        carry.extend_from_slice(data);
        while !carry.len().is_multiple_of(16) {
            carry.push(0);
        }
        for unit in carry.chunks(16) {
            let mut owned = [0u8; 16];
            owned.copy_from_slice(unit);
            let block = Block::from_mut_slice(&mut owned);
            cipher.encrypt_block(block);
            out.extend_from_slice(block);
        }
        out
    }

    /// A synthetic ozip: real header, a probe that identifies the key, and a ZIP payload.
    fn build_ozip(plaintext: &[u8], key: &[u8; 16]) -> Vec<u8> {
        let mut probe = [0u8; 16];
        probe[..4].copy_from_slice(&MAGIC_ZIP);
        probe[4..].copy_from_slice(b"PK-probe-000");
        let encrypted_probe = encrypt(key, &probe);

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        while out.len() < 0x10 {
            out.push(0);
        }
        let mut size_field = [0u8; 16];
        let text = plaintext.len().to_string();
        size_field[..text.len()].copy_from_slice(text.as_bytes());
        out.extend_from_slice(&size_field);
        while out.len() < PROBE_OFF {
            out.push(0);
        }
        out.extend_from_slice(&encrypted_probe);
        while out.len() < PAYLOAD_OFF {
            out.push(0);
        }
        let payload = encrypt(key, plaintext);
        out.extend_from_slice(&payload);
        out
    }

    #[test]
    fn a_header_parses_and_reads_its_size() {
        let o = build_ozip(b"hello world payload", &test_key());
        assert_eq!(parse_header(&o).unwrap().size, 19);
    }

    #[test]
    fn a_wrong_magic_is_refused() {
        let mut o = build_ozip(b"x", &test_key());
        o[0] = b'X';
        assert!(parse_header(&o).is_err());
    }

    #[test]
    fn a_short_or_non_numeric_header_is_an_error_not_a_panic() {
        assert!(parse_header(&[]).is_err());
        assert!(parse_header(&[0u8; 64]).is_err());
        let mut o = build_ozip(b"x", &test_key());
        for b in &mut o[0x10..0x20] {
            *b = b'Z';
        }
        assert!(parse_header(&o).is_err());
    }

    #[test]
    fn the_probe_identifies_the_right_key() {
        let o = build_ozip(b"payload", &test_key());
        let (model, _) = find_key(&o[PROBE_OFF..PROBE_OFF + 16]).expect("key must be found");
        assert!(!model.is_empty());
    }

    #[test]
    fn an_unknown_key_is_not_guessed() {
        // A key that is in no table entry.
        let bogus = [0x5Au8; 16];
        let o = build_ozip(b"payload", &bogus);
        assert!(find_key(&o[PROBE_OFF..PROBE_OFF + 16]).is_none());
    }

    #[test]
    fn a_synthetic_ozip_round_trips_to_its_zip_bytes() {
        let d = crate::testutil::Scratch::new("ozip-rt");
        let plaintext = b"PK\x03\x04 pretend this is a zip archive body";
        let src = d.join("SUPER.ozip");
        std::fs::write(&src, build_ozip(plaintext, &test_key())).unwrap();
        let out = d.join("SUPER.zip");
        crate::ozip::decrypt(&mut std::fs::File::open(&src).unwrap(), &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), plaintext);
    }

    #[test]
    fn an_undecryptable_ozip_writes_nothing() {
        let d = crate::testutil::Scratch::new("ozip-bad");
        let src = d.join("SUPER.ozip");
        std::fs::write(&src, build_ozip(b"payload", &[0x5Au8; 16])).unwrap();
        let out = d.join("SUPER.zip");
        let e = crate::ozip::decrypt(&mut std::fs::File::open(&src).unwrap(), &out)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no known key"), "{e}");
        assert!(!out.exists(), "no undecrypted output may be left behind");
    }

    #[test]
    fn the_key_table_is_populated() {
        assert!(key_count() >= 20, "expected the published device keys");
    }
}
