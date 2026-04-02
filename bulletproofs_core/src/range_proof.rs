///! Bulletproof Range Proofs.
///!
///! Proves that a committed value v lies in [0, 2^n) without revealing v.
///! The proof size is 2·log₂(n) + 9 group/field elements (as stated in the
///! Bulletproofs paper).
///!
///! Protocol outline (Bünz et al., 2018 §4.2):
///!   1. Prover decomposes v into bits a_L ∈ {0,1}^n.
///!   2. Constructs a_R = a_L − **1**^n and commits A, S.
///!   3. Verifier challenges y, z.
///!   4. Prover computes polynomial coefficients t_1, t_2and commits T_1, T_2.
///!   5. Verifier challenges x.
///!   6. Prover opens evaluations t_hat, tau_x, mu and provides the inner-product
///!      proof on the resulting vectors.

use crypto_primitives::generators::BulletproofGens;
use crypto_primitives::pedersen::PedersenCommitment;
use crypto_primitives::transcript::ProofTranscript;
use k256::{ProjectivePoint, Scalar};
use elliptic_curve::Field;
use rand::rngs::OsRng;

use crate::inner_product::{prove_inner_product, verify_inner_product, InnerProductProof};
use crate::util::*;

/// A single Bulletproof range proof for value v in [0, 2^n).
#[derive(Clone, Debug)]
pub struct RangeProof {
    /// Commitment to the bit-decomposition vector.
    pub a_commit: ProjectivePoint,
    /// Commitment to the blinding polynomial vector.
    pub s_commit: ProjectivePoint,
    /// Commitment to polynomial coefficient t_1.
    pub t1_commit: ProjectivePoint,
    /// Commitment to polynomial coefficient t_2.
    pub t2_commit: ProjectivePoint,
    /// Evaluated inner product t_hat = ⟨l(x), r(x)⟩.
    pub t_hat: Scalar,
    /// Blinding factor for the t_hat opening.
    pub tau_x: Scalar,
    /// Blinding factor mu = alpha + rho · x.
    pub mu: Scalar,
    /// The logarithmic-size inner-product proof.
    pub ipp_proof: InnerProductProof,
    /// Number of bits in the range.
    pub n: usize,
}

/// Generate a Bulletproof range proof that `value` lies in [0, 2^n).
///
/// Returns `(commitment, proof)` where `commitment` is the Pedersen commitment
/// to `value` and `proof` is the non-interactive range proof.
pub fn prove_range(
    gens: &BulletproofGens,
    value: u64,
    n: usize,
) -> (PedersenCommitment, RangeProof) {
    assert!(n.is_power_of_two(), "n must be a power of 2");
    assert!(n >= 8, "minimum bit-length is 8");
    assert!(
        value < (1u64 << n),
        "value must be in range [0, 2^n)"
    );

    let gamma = Scalar::random(&mut OsRng); // blinding for value commitment
    let v_scalar = Scalar::from(value);

    // Value commitment: V = g^v · h^gamma
    let v_commit = gens.g * v_scalar + gens.h * gamma;

    // Step 1: Bit decomposition
    let a_l = bit_decompose(value, n);
    let one_n = ones(n);
    let a_r = vec_sub(&a_l, &one_n); // a_R = a_L - 1^n

    // Step 2: Commit A = h^alpha · g_vec^{a_L} · h_vec^{a_R}
    let alpha = Scalar::random(&mut OsRng);
    let a_commit = gens.h * alpha
        + msm_points(&gens.g_vec[..n], &a_l)
        + msm_points(&gens.h_vec[..n], &a_r);

    // Blinding vectors s_l, s_r
    let s_l: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
    let s_r: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();

    let rho = Scalar::random(&mut OsRng);
    let s_commit = gens.h * rho
        + msm_points(&gens.g_vec[..n], &s_l)
        + msm_points(&gens.h_vec[..n], &s_r);

    // Fiat-Shamir: derive y and z
    let mut transcript = ProofTranscript::new(b"range_proof");
    transcript.append_point(b"V", &v_commit);
    transcript.append_point(b"A", &a_commit);
    transcript.append_point(b"S", &s_commit);

    let y = transcript.challenge_scalar(b"y");
    let z = transcript.challenge_scalar(b"z");

    let y_n = powers_of(&y, n);
    let two_n = twos(n);
    let z_sq = z * z;

    // l(X) = (a_L - z·1^n) + s_L · X
    // r(X) = y^n ∘ (a_R + z·1^n + s_R · X) + z^2 · 2^n
    let l_0 = vec_sub(&a_l, &scalar_vec_mul(&z, &one_n));
    let l_1 = s_l.clone();

    let r_0 = vec_add(
        &hadamard(&y_n, &vec_add(&a_r, &scalar_vec_mul(&z, &one_n))),
        &scalar_vec_mul(&z_sq, &two_n),
    );
    let r_1 = hadamard(&y_n, &s_r);

    // t(X) = ⟨l(X), r(X)⟩ = t_0 + t_1·X + t_2·X^2
    let t_0 = inner_product_scalar(&l_0, &r_0);
    let t_1 = inner_product_scalar(&l_0, &r_1) + inner_product_scalar(&l_1, &r_0);
    let t_2 = inner_product_scalar(&l_1, &r_1);

    // Commit to t_1, t_2
    let tau_1 = Scalar::random(&mut OsRng);
    let tau_2 = Scalar::random(&mut OsRng);

    let t1_commit = gens.g * t_1 + gens.h * tau_1;
    let t2_commit = gens.g * t_2 + gens.h * tau_2;

    // Challenge x
    transcript.append_point(b"T1", &t1_commit);
    transcript.append_point(b"T2", &t2_commit);
    let x = transcript.challenge_scalar(b"x");

    // Evaluate l, r at x
    let l_x = vec_add(&l_0, &scalar_vec_mul(&x, &l_1));
    let r_x = vec_add(&r_0, &scalar_vec_mul(&x, &r_1));

    let t_hat = inner_product_scalar(&l_x, &r_x);

    // Blinding scalars
    let tau_x = tau_1 * x + tau_2 * x * x + z_sq * gamma;
    let mu = alpha + rho * x;

    // Append evaluations for inner-product argument
    transcript.append_scalar(b"t_hat", &t_hat);
    transcript.append_scalar(b"tau_x", &tau_x);
    transcript.append_scalar(b"mu", &mu);

    // Derive inner-product base u' = w · u_base
    let w = transcript.challenge_scalar(b"w");
    let u_point = gens.g * w;

    // Fold h generators: h'_i = h_i^{y^{-i}}
    let y_inv = y.invert().unwrap();
    let y_inv_n = powers_of(&y_inv, n);
    let h_prime: Vec<ProjectivePoint> = gens.h_vec[..n]
        .iter()
        .zip(y_inv_n.iter())
        .map(|(hi, yi)| *hi * yi)
        .collect();

    let ipp_proof = prove_inner_product(
        &mut transcript,
        &gens.g_vec[..n],
        &h_prime,
        &u_point,
        &l_x,
        &r_x,
    );

    let commitment = PedersenCommitment { point: v_commit };
    let proof = RangeProof {
        a_commit,
        s_commit,
        t1_commit,
        t2_commit,
        t_hat,
        tau_x,
        mu,
        ipp_proof,
        n,
    };

    (commitment, proof)
}

/// Verify a Bulletproof range proof.
///
/// Returns true if the proof is valid: the committed value lies in [0, 2^n).
pub fn verify_range(
    gens: &BulletproofGens,
    commitment: &PedersenCommitment,
    proof: &RangeProof,
) -> bool {
    let n = proof.n;

    let mut transcript = ProofTranscript::new(b"range_proof");
    transcript.append_point(b"V", &commitment.point);
    transcript.append_point(b"A", &proof.a_commit);
    transcript.append_point(b"S", &proof.s_commit);

    let y = transcript.challenge_scalar(b"y");
    let z = transcript.challenge_scalar(b"z");

    transcript.append_point(b"T1", &proof.t1_commit);
    transcript.append_point(b"T2", &proof.t2_commit);
    let x = transcript.challenge_scalar(b"x");

    transcript.append_scalar(b"t_hat", &proof.t_hat);
    transcript.append_scalar(b"tau_x", &proof.tau_x);
    transcript.append_scalar(b"mu", &proof.mu);

    let w = transcript.challenge_scalar(b"w");

    let one_n = ones(n);
    let y_n = powers_of(&y, n);
    let two_n = twos(n);
    let z_sq = z * z;

    // Check 1: t_hat =? z^2 · v + delta(y, z)
    // delta(y,z) = (z - z^2)·⟨1^n, y^n⟩ - z^3·⟨1^n, 2^n⟩
    let ip_1_y = scalar_sum(&y_n);
    let ip_1_2 = scalar_sum(&two_n);
    let delta = (z - z_sq) * ip_1_y - z * z_sq * ip_1_2;

    // Verify: g^{t_hat} · h^{tau_x} == V^{z^2} · g^delta · T_1^x · T_2^{x^2}
    let lhs = gens.g * proof.t_hat + gens.h * proof.tau_x;
    let rhs = commitment.point * z_sq + gens.g * delta + proof.t1_commit * x + proof.t2_commit * (x * x);

    if lhs != rhs {
        return false;
    }

    // Reconstruct P for the inner-product argument
    // P = A · S^x · g_vec^{-z} · (h_vec')^{z · y^n + z^2 · 2^n} · h^{-mu}
    let neg_z = -z;
    let neg_z_vec: Vec<Scalar> = vec![neg_z; n];

    let z_y_plus_z2_2: Vec<Scalar> = y_n
        .iter()
        .zip(two_n.iter())
        .map(|(yi, twoi)| z * yi + z_sq * twoi)
        .collect();

    let y_inv = y.invert().unwrap();
    let y_inv_n = powers_of(&y_inv, n);
    let h_prime: Vec<ProjectivePoint> = gens.h_vec[..n]
        .iter()
        .zip(y_inv_n.iter())
        .map(|(hi, yi)| *hi * yi)
        .collect();

    let p = proof.a_commit
        + proof.s_commit * x
        + msm_points(&gens.g_vec[..n], &neg_z_vec)
        + msm_points(&h_prime, &z_y_plus_z2_2)
        - gens.h * proof.mu;

    // Add the t_hat · U term
    let u_point = gens.g * w;
    let p_with_ip = p + u_point * proof.t_hat;

    verify_inner_product(
        &mut transcript,
        &gens.g_vec[..n],
        &h_prime,
        &u_point,
        &p_with_ip,
        &proof.ipp_proof,
    )
}

/// Multi-scalar multiplication helper.
fn msm_points(points: &[ProjectivePoint], scalars: &[Scalar]) -> ProjectivePoint {
    assert_eq!(points.len(), scalars.len());
    let mut acc = ProjectivePoint::IDENTITY;
    for (p, s) in points.iter().zip(scalars.iter()) {
        acc += *p * s;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_primitives::generators::BulletproofGens;

    #[test]
    fn range_proof_valid_value() {
        let n = 8; // [0, 256)
        let gens = BulletproofGens::new(n);

        let (commitment, proof) = prove_range(&gens, 42, n);
        assert!(verify_range(&gens, &commitment, &proof));
    }

    #[test]
    fn range_proof_zero() {
        let n = 8;
        let gens = BulletproofGens::new(n);

        let (commitment, proof) = prove_range(&gens, 0, n);
        assert!(verify_range(&gens, &commitment, &proof));
    }

    #[test]
    fn range_proof_max_value() {
        let n = 8;
        let gens = BulletproofGens::new(n);

        let (commitment, proof) = prove_range(&gens, 255, n);
        assert!(verify_range(&gens, &commitment, &proof));
    }

    #[test]
    fn range_proof_boolean_vote() {
        // Voting use-case: prove that a vote v ∈ {0, 1} ⊂ [0, 2^8)
        let n = 8;
        let gens = BulletproofGens::new(n);

        let (c0, p0) = prove_range(&gens, 0, n);
        assert!(verify_range(&gens, &c0, &p0));

        let (c1, p1) = prove_range(&gens, 1, n);
        assert!(verify_range(&gens, &c1, &p1));
    }

    #[test]
    #[should_panic(expected = "value must be in range")]
    fn range_proof_out_of_range() {
        let n = 8;
        let gens = BulletproofGens::new(n);
        prove_range(&gens, 256, n); // 256 >= 2^8 → must panic
    }

    #[test]
    fn range_proof_16bit() {
        let n = 16;
        let gens = BulletproofGens::new(n);

        let (commitment, proof) = prove_range(&gens, 12345, n);
        assert!(verify_range(&gens, &commitment, &proof));
    }

    #[test]
    fn range_proof_tampered_commitment_fails() {
        let n = 8;
        let gens = BulletproofGens::new(n);

        let (_, proof) = prove_range(&gens, 42, n);
        // Use a different commitment
        let fake_commit = PedersenCommitment {
            point: ProjectivePoint::GENERATOR,
        };
        assert!(!verify_range(&gens, &fake_commit, &proof));
    }
}
