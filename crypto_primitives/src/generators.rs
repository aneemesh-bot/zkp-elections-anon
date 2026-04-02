///! Generator vectors for Bulletproofs.
///!
///! Produces deterministic, independent generators for the secp256k1 group by
///! hashing domain-separated labels through hash-to-curve. This avoids any
///! trusted-setup requirement — the generators are derived transparently.

use k256::ProjectivePoint;
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use sha2::Sha256;

/// Domain separation tag used for hash-to-curve generator derivation.
const DST: &[u8] = b"BULLETPROOFS_GENERATORS_secp256k1_XMD:SHA-256_SSWU_RO_";

/// Public parameters: vectors of independent group generators plus a blinding
/// generator `h`.
#[derive(Clone, Debug)]
pub struct BulletproofGens {
    /// Generator vector **g** of length `n`.
    pub g_vec: Vec<ProjectivePoint>,
    /// Generator vector **h** of length `n`.
    pub h_vec: Vec<ProjectivePoint>,
    /// Blinding generator used for Pedersen commitments.
    pub h: ProjectivePoint,
    /// Alternative base generator (the standard secp256k1 generator).
    pub g: ProjectivePoint,
}

impl BulletproofGens {
    /// Create a new set of generators supporting vectors of length `n`.
    ///
    /// All generators are derived deterministically via hash-to-curve so that
    /// no trusted setup is required.
    pub fn new(n: usize) -> Self {
        let g = ProjectivePoint::GENERATOR;

        // Derive the blinding generator h from a fixed label.
        let h = hash_to_point(b"h_blind", 0);

        let g_vec: Vec<ProjectivePoint> = (0..n)
            .map(|i| hash_to_point(b"g_vec", i as u64))
            .collect();

        let h_vec: Vec<ProjectivePoint> = (0..n)
            .map(|i| hash_to_point(b"h_vec", i as u64))
            .collect();

        BulletproofGens { g_vec, h_vec, h, g }
    }

    /// Doubles the capacity by extending the generator vectors to length `new_n`.
    pub fn extend_to(&mut self, new_n: usize) {
        let old_n = self.g_vec.len();
        if new_n <= old_n {
            return;
        }
        for i in old_n..new_n {
            self.g_vec.push(hash_to_point(b"g_vec", i as u64));
            self.h_vec.push(hash_to_point(b"h_vec", i as u64));
        }
    }
}

/// Deterministically map `(label, index)` to a secp256k1 group element using
/// hash-to-curve (RFC 9380).
fn hash_to_point(label: &[u8], index: u64) -> ProjectivePoint {
    let mut msg = Vec::with_capacity(label.len() + 8);
    msg.extend_from_slice(label);
    msg.extend_from_slice(&index.to_le_bytes());

    k256::Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[&msg], &[DST])
        .expect("hash_to_curve should not fail for valid inputs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ProjectivePoint;

    #[test]
    fn generators_are_distinct() {
        let gens = BulletproofGens::new(8);
        // All generators in g_vec must be distinct
        for i in 0..gens.g_vec.len() {
            for j in (i + 1)..gens.g_vec.len() {
                assert_ne!(gens.g_vec[i], gens.g_vec[j]);
            }
        }
        // All generators in h_vec must be distinct
        for i in 0..gens.h_vec.len() {
            for j in (i + 1)..gens.h_vec.len() {
                assert_ne!(gens.h_vec[i], gens.h_vec[j]);
            }
        }
        // g_vec and h_vec generators must be cross-distinct
        for gi in &gens.g_vec {
            for hj in &gens.h_vec {
                assert_ne!(gi, hj);
            }
        }
        // h must differ from all others
        assert_ne!(gens.h, ProjectivePoint::GENERATOR);
        for gi in &gens.g_vec {
            assert_ne!(&gens.h, gi);
        }
    }

    #[test]
    fn deterministic_generators() {
        let a = BulletproofGens::new(4);
        let b = BulletproofGens::new(4);
        assert_eq!(a.g_vec, b.g_vec);
        assert_eq!(a.h_vec, b.h_vec);
        assert_eq!(a.h, b.h);
    }

    #[test]
    fn extend_preserves_existing() {
        let mut gens = BulletproofGens::new(4);
        let g4 = gens.g_vec.clone();
        gens.extend_to(8);
        assert_eq!(&gens.g_vec[..4], &g4[..]);
        assert_eq!(gens.g_vec.len(), 8);
    }
}
