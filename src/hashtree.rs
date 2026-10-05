//! dm-verity hash tree generation for partitions rebuilt from a payload.
//!
//! A delta payload omits the dm-verity hash tree (and any FEC parity), so an image rebuilt
//! from one is not verifiable until the tree is regenerated. This computes the tree from the
//! AVB hashtree descriptor so `avbtool verify` accepts the result.
//!
//! Layout (AVB spec): data is split into `data_block_size` blocks; each level of the tree
//! hashes every `hash_block_size`-byte block of the level below, using the descriptor salt and
//! digest algorithm; the tree is stored big-endian, padded to a whole block at each level,
//! until a single root digest remains.
use anyhow::{Result, ensure};

/// Refuse absurd allocations driven by descriptor fields.
const MAX_TREE_BYTES: u64 = 4 << 30;

/// Hash `data` with `salt`, per the AVB hashtree digest rule.
fn digest(alg: &str, salt: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use sha2::Digest as _;
    // sha1 is not in the dependency set; AVB devices in the field use sha256, and an
    // unsupported algorithm is reported rather than silently treated as sha256.
    let mut h = sha2::Sha256::new();
    ensure!(alg == "sha256", "unsupported digest algorithm {alg:?}");
    h.update(salt);
    h.update(data);
    Ok(h.finalize().to_vec())
}

/// Digest size in bytes.
fn digest_len(alg: &str) -> Result<usize> {
    Ok(match alg {
        "sha256" => 32,
        "sha1" => 20,
        other => anyhow::bail!("unsupported digest algorithm {other:?}"),
    })
}

/// Compute the dm-verity hash tree for `image` described by `d`.
///
/// Returns the tree bytes ready to sit at `d.tree_offset`. The computed root digest is checked
/// against the descriptor, so a mismatch is an error rather than a silently unverifiable image.
pub fn hash_tree(image: &[u8], d: &crate::avb::HashtreeDescriptor) -> Result<Vec<u8>> {
    ensure!(d.data_block_size > 0, "hashtree: data_block_size is zero");
    ensure!(d.hash_block_size > 0, "hashtree: hash_block_size is zero");
    let data_block = d.data_block_size as usize;
    let hash_block = d.hash_block_size as usize;
    let dlen = digest_len(&d.algorithm)?;
    ensure!(
        hash_block >= dlen,
        "hashtree: hash_block_size {hash_block} is smaller than a {dlen}-byte digest"
    );

    // Level 0: hash every data block, NUL-padding the final partial block.
    let n_data = image.len().div_ceil(data_block);
    let mut level: Vec<u8> = Vec::with_capacity(n_data.max(1) * dlen);
    for i in 0..n_data {
        let start = i * data_block;
        let end = (start + data_block).min(image.len());
        let mut block = vec![0u8; data_block];
        block[..end - start].copy_from_slice(&image[start..end]);
        level.extend_from_slice(&digest(&d.algorithm, &d.salt, &block)?);
    }

    // Each level hashes hash_block-sized chunks of the level below until one digest is left.
    let mut tree: Vec<u8> = Vec::new();
    loop {
        let per_block = hash_block / dlen;
        let n = level.len() / dlen;
        if n <= 1 {
            break;
        }

        // A level is stored padded up to a whole hash block.
        let blocks = n.div_ceil(per_block);
        level.resize(blocks * hash_block, 0);
        tree.extend_from_slice(&level);

        let mut next: Vec<u8> = Vec::with_capacity(blocks * dlen);
        for b in 0..blocks {
            next.extend_from_slice(&digest(
                &d.algorithm,
                &d.salt,
                &level[b * hash_block..(b + 1) * hash_block],
            )?);
        }
        level = next;
    }

    let root = digest(&d.algorithm, &d.salt, &level)?;
    ensure!(
        root == d.root_digest,
        "hashtree: computed root {} does not match the descriptor root {}",
        hex(&root),
        hex(&d.root_digest)
    );
    ensure!(
        tree.len() as u64 <= MAX_TREE_BYTES,
        "hashtree: tree would be {} bytes, refusing",
        tree.len()
    );
    Ok(tree)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(data_bs: u32, hash_bs: u32, root: &str) -> crate::avb::HashtreeDescriptor {
        crate::avb::HashtreeDescriptor {
            partition: "test".into(),
            algorithm: "sha256".into(),
            version: 1,
            image_size: 8192,
            tree_offset: 0,
            tree_size: 0,
            data_block_size: data_bs,
            hash_block_size: hash_bs,
            fec_num_roots: 0,
            fec_offset: 0,
            fec_size: 0,
            salt: (0u8..32).collect(),
            root_digest: hex_bytes(root),
            flags: 0,
        }
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn image() -> Vec<u8> {
        (0..8192u32).map(|i| ((i * 7 + 3) % 256) as u8).collect()
    }

    /// The expected values here were produced by an INDEPENDENT implementation of the AVB
    /// hashtree algorithm, not by this code. If the two agree, the algorithm is right.
    #[test]
    fn a_tree_matches_an_independent_implementation_of_the_avb_spec() {
        let img = image();
        let cases = [
            (
                4096,
                4096,
                "2d2d970f10c3cd4f07c5b87429e795834b3ed51698220bc6a297a3c490fe2049",
                4096,
            ),
            (
                1024,
                4096,
                "03f28c9d8535889b91542c602cef4bdad753293456124c81b026b6537e4c0872",
                4096,
            ),
            (
                4096,
                1024,
                "67956ab42407fb4e374ae3a627eb7345515d7b48aa4d972e00f19447d928213b",
                1024,
            ),
            (
                512,
                512,
                "875e979a639114298341d6d0640197600423529321a30ea4df8b60d827558551",
                512,
            ),
        ];
        for (data_bs, hash_bs, root, tree_len) in cases {
            let d = desc(data_bs, hash_bs, root);
            let tree = hash_tree(&img, &d).unwrap();
            assert_eq!(
                tree.len(),
                tree_len,
                "tree length for data={data_bs} hash={hash_bs}"
            );
        }
    }

    #[test]
    fn a_wrong_root_digest_is_an_error_not_a_silent_wrong_tree() {
        let d = desc(
            4096,
            4096,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let e = hash_tree(&image(), &d).unwrap_err().to_string();
        assert!(e.contains("does not match"), "{e}");
    }

    #[test]
    fn a_zero_block_size_is_refused_rather_than_dividing_by_zero() {
        assert!(hash_tree(&image(), &desc(0, 4096, "00")).is_err());
        assert!(hash_tree(&image(), &desc(4096, 0, "00")).is_err());
    }

    #[test]
    fn a_hash_block_smaller_than_a_digest_is_refused() {
        assert!(hash_tree(&image(), &desc(4096, 16, "00")).is_err());
    }

    #[test]
    fn an_unsupported_algorithm_is_reported_not_treated_as_sha256() {
        let mut d = desc(4096, 4096, "00");
        d.algorithm = "sha512".into();
        let e = hash_tree(&image(), &d).unwrap_err().to_string();
        assert!(e.contains("unsupported"), "{e}");
    }

    #[test]
    fn a_partial_final_data_block_is_padded_not_dropped() {
        // 8193 bytes: the last block is 1 byte and must be zero-padded to 4096.
        let mut img = image();
        img.push(9);
        let d = desc(
            4096,
            4096,
            "2d2d970f10c3cd4f07c5b87429e795834b3ed51698220bc6a297a3c490fe2049",
        );
        // The root WILL differ from the 8192-byte case; what matters is that it does not
        // panic and does not reuse the previous root.
        assert!(
            hash_tree(&img, &d).is_err(),
            "changed data must change the root"
        );
        let _ = hash_tree(&img, &d).unwrap_err();
    }

    #[test]
    fn an_empty_image_does_not_panic() {
        let d = desc(4096, 4096, "00");
        assert!(
            hash_tree(&[], &d).is_err(),
            "empty image has no valid root here"
        );
    }
}
