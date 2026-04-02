///! Inner Product Argument for Bulletproofs.
///!
///! Implements the recursive logarithmic-size inner-product proof as described
///! in the Bulletproofs paper (Bünz et al., 2018 §3).
///!
///! Given commitment P = ⟨a, G⟩ + ⟨b, H⟩ + ⟨a, b⟩ · U,
///! the protocol recursively halves the vectors until they reach length 1,
///! producing a proof of size O(log n).

use crypto_primitives::transcript::ProofTranscript;
use k256::{ProjectivePoint, Scalar};
use elliptic_curve::Field;
use serde::{Serialize, Deserialize};

use crate::util::inner_product_scalar;

/// The inner product proof: a sequence of L/R curve points plus the final
/// scalars a and b.
#[derive(Clone, Debug)]
pub struct InnerProductProof {
    /// Left-fold points, one per round.
    pub l_vec: Vec<ProjectivePoint>,
    /// Right-fold points, one per round.
    pub r_vec: Vec<ProjectivePoint>,
    /// Final scalar a (after all folding rounds).
    pub a: Scalar,
    /// Final scalar b (after all folding rounds).
    pub b: Scalar,
}

/// Compute ⟨a, b⟩.
pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    inner_product_scalar(a, b)
}

/// Multi-scalar multiplication Σ s_i · P_i.
fn msm(points: &[ProjectivePoint], scalars: &[Scalar]) -> ProjectivePoint {
    assert_eq!(points.len(), scalars.len());
    let mut acc = ProjectivePoint::IDENTITY;
    for (p, s) in points.iter().zip(scalars.iter()) {
        acc += *p * s;
    }
    acc
}

/// Create an inner-product proof.
///
/// # Arguments
/// * `transcript` – Fiat-Shamir transcript (mutated in-place).
/// * `g_vec` – Generator vector **G** of length `n` (must be a power of 2).
/// * `h_vec` – Generator vector **H** of length `n`.
/// * `u` – The "inner-product base" point.
/// * `a_vec` – Witness vector **a** of length `n`.
/// * `b_vec` – Witness vector **b** of length `n`.
pub fn prove_inner_product(
    transcript: &mut ProofTranscript,
    g_vec: &[ProjectivePoint],
    h_vec: &[ProjectivePoint],
    u: &ProjectivePoint,
    a_vec: &[Scalar],
    b_vec: &[Scalar],
) -> InnerProductProof {
    let mut n = a_vec.len();
    assert!(n.is_power_of_two(), "vector length must be a power of 2");
    assert_eq!(g_vec.len(), n);
    assert_eq!(h_vec.len(), n);
    assert_eq!(b_vec.len(), n);

    let lg_n = n.trailing_zeros() as usize;

    let mut g = g_vec.to_vec();
    let mut h = h_vec.to_vec();
    let mut a = a_vec.to_vec();
    let mut b = b_vec.to_vec();

    let mut l_vec = Vec::with_capacity(lg_n);
    let mut r_vec = Vec::with_capacity(lg_n);

    while n > 1 {
        let half = n / 2;

        let (a_lo, a_hi) = a.split_at(half);
        let (b_lo, b_hi) = b.split_at(half);
        let (g_lo, g_hi) = g.split_at(half);
        let (h_lo, h_hi) = h.split_at(half);

        // L = ⟨a_lo, G_hi⟩ + ⟨b_hi, H_lo⟩ + ⟨a_lo, b_hi⟩ · U
        let c_l = inner_product_scalar(a_lo, b_hi);
        let l_point = msm(g_hi, a_lo) + msm(h_lo, b_hi) + *u * c_l;

        // R = ⟨a_hi, G_lo⟩ + ⟨b_lo, H_hi⟩ + ⟨a_hi, b_lo⟩ · U
        let c_r = inner_product_scalar(a_hi, b_lo);
        let r_point = msm(g_lo, a_hi) + msm(h_hi, b_lo) + *u * c_r;

        l_vec.push(l_point);
        r_vec.push(r_point);

        transcript.append_point(b"L", &l_point);
        transcript.append_point(b"R", &r_point);
        let x = transcript.challenge_scalar(b"x");
        let x_inv = x.invert().unwrap();

        // Fold generators: G' = x_inv · G_lo + x · G_hi
        let g_new: Vec<ProjectivePoint> = g_lo
            .iter()
            .zip(g_hi.iter())
            .map(|(lo, hi)| *lo * x_inv + *hi * x)
            .collect();

        // H' = x · H_lo + x_inv · H_hi
        let h_new: Vec<ProjectivePoint> = h_lo
            .iter()
            .zip(h_hi.iter())
            .map(|(lo, hi)| *lo * x + *hi * x_inv)
            .collect();

        // Fold witness: a' = x · a_lo + x_inv · a_hi
        let a_new: Vec<Scalar> = a_lo
            .iter()
            .zip(a_hi.iter())
            .map(|(lo, hi)| *lo * x + *hi * x_inv)
            .collect();

        // b' = x_inv · b_lo + x · b_hi
        let b_new: Vec<Scalar> = b_lo
            .iter()
            .zip(b_hi.iter())
            .map(|(lo, hi)| *lo * x_inv + *hi * x)
            .collect();

        g = g_new;
        h = h_new;
        a = a_new;
        b = b_new;
        n = half;
    }

    InnerProductProof {
        l_vec,
        r_vec,
        a: a[0],
        b: b[0],
    }
}

/// Verify an inner-product proof.
///
/// Re-derives the challenges via the same Fiat-Shamir transcript and checks
/// that the final equation holds.
pub fn verify_inner_product(
    transcript: &mut ProofTranscript,
    g_vec: &[ProjectivePoint],
    h_vec: &[ProjectivePoint],
    u: &ProjectivePoint,
    p: &ProjectivePoint,
    proof: &InnerProductProof,
) -> bool {
    let n = g_vec.len();
    assert!(n.is_power_of_two());
    let lg_n = proof.l_vec.len();
    assert_eq!(lg_n, n.trailing_zeros() as usize);

    // Recompute challenges
    let mut challenges = Vec::with_capacity(lg_n);
    for i in 0..lg_n {
        transcript.append_point(b"L", &proof.l_vec[i]);
        transcript.append_point(b"R", &proof.r_vec[i]);
        let x = transcript.challenge_scalar(b"x");
        challenges.push(x);
    }

    // Compute scalars s_i for the folded generators
    // s_i = Π_{j where bit j of i is 1} x_j · Π_{j where bit j of i is 0} x_j^{-1}
    let mut s = vec![Scalar::ONE; n];
    for i in 0..n {
        for (j, xj) in challenges.iter().enumerate() {
            let bit = (i >> (lg_n - 1 - j)) & 1;
            if bit == 1 {
                s[i] *= xj;
            } else {
                s[i] *= xj.invert().unwrap();
            }
        }
    }

    // Verification equation:
    // P_final = a·b·U + Σ (a·s_i)·G_i + Σ (b·s_i^{-1})·H_i
    // P = P_final - Σ x_j^2·L_j - Σ x_j^{-2}·R_j
    let ab = proof.a * proof.b;

    let mut expected = *u * ab;
    for i in 0..n {
        expected += g_vec[i] * (proof.a * s[i]);
        expected += h_vec[i] * (proof.b * s[i].invert().unwrap());
    }
    for j in 0..lg_n {
        let xj_sq = challenges[j] * challenges[j];
        let xj_inv_sq = xj_sq.invert().unwrap();
        expected -= proof.l_vec[j] * xj_sq;
        expected -= proof.r_vec[j] * xj_inv_sq;
    }

    expected == *p
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_primitives::generators::BulletproofGens;
    use crypto_primitives::transcript::ProofTranscript;
    use rand::rngs::OsRng;
    use elliptic_curve::Field;

    fn random_scalars(n: usize) -> Vec<Scalar> {
        (0..n).map(|_| Scalar::random(&mut OsRng)).collect()
    }

    #[test]
    fn inner_product_proof_verify_n4() {
        let n = 4;
        let gens = BulletproofGens::new(n);
        let u = ProjectivePoint::GENERATOR; // arbitrary point for inner-product base

        let a = random_scalars(n);
        let b = random_scalars(n);

        // P = ⟨a, G⟩ + ⟨b, H⟩ + ⟨a, b⟩ · U
        let ip = inner_product(&a, &b);
        let p = msm(&gens.g_vec, &a) + msm(&gens.h_vec, &b) + u * ip;

        let mut pt = ProofTranscript::new(b"ipp_test");
        let proof = prove_inner_product(&mut pt, &gens.g_vec, &gens.h_vec, &u, &a, &b);

        let mut vt = ProofTranscript::new(b"ipp_test");
        assert!(verify_inner_product(&mut vt, &gens.g_vec, &gens.h_vec, &u, &p, &proof));
    }

    #[test]
    fn inner_product_proof_verify_n16() {
        let n = 16;
        let gens = BulletproofGens::new(n);
        let u = ProjectivePoint::GENERATOR;

        let a = random_scalars(n);
        let b = random_scalars(n);

        let ip = inner_product(&a, &b);
        let p = msm(&gens.g_vec, &a) + msm(&gens.h_vec, &b) + u * ip;

        let mut pt = ProofTranscript::new(b"ipp_test");
        let proof = prove_inner_product(&mut pt, &gens.g_vec, &gens.h_vec, &u, &a, &b);

        let mut vt = ProofTranscript::new(b"ipp_test");
        assert!(verify_inner_product(&mut vt, &gens.g_vec, &gens.h_vec, &u, &p, &proof));
    }

    #[test]
    fn inner_product_proof_rejects_bad_witness() {
        let n = 4;
        let gens = BulletproofGens::new(n);
        let u = ProjectivePoint::GENERATOR;

        let a = random_scalars(n);
        let b = random_scalars(n);

        // Correct commitment
        let ip = inner_product(&a, &b);
        let p = msm(&gens.g_vec, &a) + msm(&gens.h_vec, &b) + u * ip;

        // Use wrong witness for proving
        let bad_a = random_scalars(n);
        let mut pt = ProofTranscript::new(b"ipp_test");
        let proof = prove_inner_product(&mut pt, &gens.g_vec, &gens.h_vec, &u, &bad_a, &b);

        let mut vt = ProofTranscript::new(b"ipp_test");
        assert!(!verify_inner_product(&mut vt, &gens.g_vec, &gens.h_vec, &u, &p, &proof));
    }

    #[test]
    fn proof_size_is_logarithmic() {
        let n = 64;
        let gens = BulletproofGens::new(n);
        let u = ProjectivePoint::GENERATOR;
        let a = random_scalars(n);
        let b = random_scalars(n);

        let mut pt = ProofTranscript::new(b"size_test");
        let proof = prove_inner_product(&mut pt, &gens.g_vec, &gens.h_vec, &u, &a, &b);

        // log2(64) = 6 rounds
        assert_eq!(proof.l_vec.len(), 6);
        assert_eq!(proof.r_vec.len(), 6);
    }
}
