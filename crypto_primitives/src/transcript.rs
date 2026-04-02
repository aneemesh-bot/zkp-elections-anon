///! Fiat-Shamir proof transcript.
///!
///! Replaces interactive verifier challenges with deterministic hashes of the
///! proof transcript accumulated so far. Uses SHA-256 as the hash function.

use k256::{AffinePoint, ProjectivePoint, Scalar};
use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::ops::Reduce;
use sha2::{Sha256, Digest};

/// Running transcript that accumulates messages and produces challenge scalars
/// via the Fiat-Shamir transform.
#[derive(Clone, Debug)]
pub struct ProofTranscript {
    hasher: Sha256,
}

impl ProofTranscript {
    /// Start a new transcript with a domain-separation label.
    pub fn new(label: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"Bulletproofs_Transcript_");
        hasher.update(label);
        ProofTranscript { hasher }
    }

    /// Append a domain-separated byte message.
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.hasher.update(label);
        self.hasher.update((message.len() as u64).to_le_bytes());
        self.hasher.update(message);
    }

    /// Append a scalar to the transcript.
    pub fn append_scalar(&mut self, label: &[u8], scalar: &Scalar) {
        let bytes = scalar.to_bytes();
        self.append_message(label, &bytes);
    }

    /// Append a group point (compressed SEC1 encoding) to the transcript.
    pub fn append_point(&mut self, label: &[u8], point: &ProjectivePoint) {
        let affine: AffinePoint = (*point).into();
        let encoded = affine.to_encoded_point(true);
        self.append_message(label, encoded.as_bytes());
    }

    /// Produce a challenge scalar by finalising the current hash state.
    ///
    /// The transcript is then re-seeded with the challenge so that
    /// subsequent challenges depend on the full history.
    pub fn challenge_scalar(&mut self, label: &[u8]) -> Scalar {
        self.hasher.update(b"challenge_");
        self.hasher.update(label);

        let hash = self.hasher.finalize_reset();
        // Re-seed with the challenge
        self.hasher.update(&hash);

        // Reduce the 256-bit hash modulo the group order.
        scalar_from_hash(&hash)
    }
}

/// Reduce a 32-byte hash output to a secp256k1 scalar (mod n).
fn scalar_from_hash(hash: &[u8]) -> Scalar {
    let mut wide = [0u8; 32];
    wide.copy_from_slice(&hash[..32]);
    <Scalar as Reduce<k256::U256>>::reduce_bytes(&wide.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ProjectivePoint;

    #[test]
    fn transcript_deterministic() {
        let mut t1 = ProofTranscript::new(b"test");
        let mut t2 = ProofTranscript::new(b"test");

        t1.append_message(b"msg", b"hello");
        t2.append_message(b"msg", b"hello");

        let c1 = t1.challenge_scalar(b"c");
        let c2 = t2.challenge_scalar(b"c");
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_labels_different_challenges() {
        let mut t1 = ProofTranscript::new(b"alpha");
        let mut t2 = ProofTranscript::new(b"beta");

        let c1 = t1.challenge_scalar(b"c");
        let c2 = t2.challenge_scalar(b"c");
        assert_ne!(c1, c2);
    }

    #[test]
    fn different_messages_different_challenges() {
        let mut t1 = ProofTranscript::new(b"test");
        let mut t2 = ProofTranscript::new(b"test");

        t1.append_message(b"m", b"aaa");
        t2.append_message(b"m", b"bbb");

        let c1 = t1.challenge_scalar(b"c");
        let c2 = t2.challenge_scalar(b"c");
        assert_ne!(c1, c2);
    }

    #[test]
    fn challenge_depends_on_point() {
        let mut t1 = ProofTranscript::new(b"test");
        let mut t2 = ProofTranscript::new(b"test");

        t1.append_point(b"P", &ProjectivePoint::GENERATOR);
        t2.append_point(b"P", &ProjectivePoint::IDENTITY);

        let c1 = t1.challenge_scalar(b"c");
        let c2 = t2.challenge_scalar(b"c");
        assert_ne!(c1, c2);
    }

    #[test]
    fn sequential_challenges_differ() {
        let mut t = ProofTranscript::new(b"test");
        let c1 = t.challenge_scalar(b"first");
        let c2 = t.challenge_scalar(b"second");
        assert_ne!(c1, c2);
    }
}
