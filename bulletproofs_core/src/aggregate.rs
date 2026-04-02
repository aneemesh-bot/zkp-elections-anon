///! Aggregate Bulletproof Range Proofs.
///!
///! Proves that m committed values all lie in [0, 2^n) with a single proof
///! whose size grows only by O(log(m)) over the single-value case.
///!
///! This is used for ballots with multiple candidates — each candidate's
///! committed score is proven valid in one aggregate proof.

use crypto_primitives::generators::BulletproofGens;
use crypto_primitives::pedersen::PedersenCommitment;
use crypto_primitives::transcript::ProofTranscript;
use k256::{ProjectivePoint, Scalar};
use elliptic_curve::Field;
use rand::rngs::OsRng;

use crate::inner_product::{prove_inner_product, verify_inner_product, InnerProductProof};
use crate::util::*;

/// Aggregate range proof for m values, each in [0, 2^n).
#[derive(Clone, Debug)]
pub struct AggregateRangeProof {
    pub a_commit: ProjectivePoint,
    pub s_commit: ProjectivePoint,
    pub t1_commit: ProjectivePoint,
    pub t2_commit: ProjectivePoint,
    pub t_hat: Scalar,
    pub tau_x: Scalar,
    pub mu: Scalar,
    pub ipp_proof: InnerProductProof,
    /// Bit-length of each value's range.
    pub n: usize,
    /// Number of values aggregated.
    pub m: usize,
}

/// Generate an aggregate range proof for `values`, each in [0, 2^n).
///
/// Returns `(commitments, proof)`.
pub fn prove_aggregate_range(
    gens: &BulletproofGens,
    values: &[u64],
    n: usize,
) -> (Vec<PedersenCommitment>, AggregateRangeProof) {
    let m = values.len();
    assert!(m > 0, "need at least one value");
    assert!(n.is_power_of_two(), "n must be power of 2");
    assert!(n >= 8);
    let nm = n * m;
    let nm_padded = nm.next_power_of_two();
    assert!(
        gens.g_vec.len() >= nm_padded,
        "generators too short; need {}",
        nm_padded
    );

    // Blinding factors and commitments for each value
    let gammas: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut OsRng)).collect();
    let v_scalars: Vec<Scalar> = values.iter().map(|&v| {
        assert!(v < (1u64 << n), "value out of range");
        Scalar::from(v)
    }).collect();

    let v_commits: Vec<ProjectivePoint> = v_scalars
        .iter()
        .zip(gammas.iter())
        .map(|(v, g)| gens.g * *v + gens.h * *g)
        .collect();

    // Concatenated bit decompositions
    let mut a_l = Vec::with_capacity(nm);
    let mut a_r = Vec::with_capacity(nm);
    for &val in values {
        let bits = bit_decompose(val, n);
        let one_n = ones(n);
        let ar = vec_sub(&bits, &one_n);
        a_l.extend_from_slice(&bits);
        a_r.extend_from_slice(&ar);
    }

    // Commit A
    let alpha = Scalar::random(&mut OsRng);
    let a_commit = gens.h * alpha
        + msm_points(&gens.g_vec[..nm], &a_l)
        + msm_points(&gens.h_vec[..nm], &a_r);

    // Blinding vectors
    let s_l: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut OsRng)).collect();
    let s_r: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut OsRng)).collect();

    let rho = Scalar::random(&mut OsRng);
    let s_commit = gens.h * rho
        + msm_points(&gens.g_vec[..nm], &s_l)
        + msm_points(&gens.h_vec[..nm], &s_r);

    // Fiat-Shamir
    let mut transcript = ProofTranscript::new(b"agg_range_proof");
    for vc in &v_commits {
        transcript.append_point(b"V", vc);
    }
    transcript.append_point(b"A", &a_commit);
    transcript.append_point(b"S", &s_commit);

    let y = transcript.challenge_scalar(b"y");
    let z = transcript.challenge_scalar(b"z");

    let y_nm = powers_of(&y, nm);
    let two_n = twos(n);

    // Build z-vectors for aggregation:
    // z_vec_j = z^{j+2} · 2^n  (concatenated for j = 0..m-1)
    let mut z_aggr = Vec::with_capacity(nm);
    let mut z_pow = z * z; // z^2
    for _ in 0..m {
        for twoi in &two_n {
            z_aggr.push(z_pow * twoi);
        }
        z_pow *= z;
    }

    let one_nm = ones(nm);

    // l(X) = (a_L - z · 1^{nm}) + s_L · X
    let l_0 = vec_sub(&a_l, &scalar_vec_mul(&z, &one_nm));
    let l_1 = s_l.clone();

    // r(X) = y^{nm} ∘ (a_R + z · 1^{nm} + s_R · X) + Σ_j z^{j+2} · 2^n
    let r_0 = vec_add(
        &hadamard(&y_nm, &vec_add(&a_r, &scalar_vec_mul(&z, &one_nm))),
        &z_aggr,
    );
    let r_1 = hadamard(&y_nm, &s_r);

    let t_0 = inner_product_scalar(&l_0, &r_0);
    let t_1 = inner_product_scalar(&l_0, &r_1) + inner_product_scalar(&l_1, &r_0);
    let t_2 = inner_product_scalar(&l_1, &r_1);

    let tau_1 = Scalar::random(&mut OsRng);
    let tau_2 = Scalar::random(&mut OsRng);

    let t1_commit = gens.g * t_1 + gens.h * tau_1;
    let t2_commit = gens.g * t_2 + gens.h * tau_2;

    transcript.append_point(b"T1", &t1_commit);
    transcript.append_point(b"T2", &t2_commit);
    let x = transcript.challenge_scalar(b"x");

    let l_x = vec_add(&l_0, &scalar_vec_mul(&x, &l_1));
    let r_x = vec_add(&r_0, &scalar_vec_mul(&x, &r_1));
    let t_hat = inner_product_scalar(&l_x, &r_x);

    // tau_x = Σ_j z^{j+2} · gamma_j + tau_1 · x + tau_2 · x^2
    let mut tau_x = tau_1 * x + tau_2 * x * x;
    let mut zpow = z * z;
    for gj in &gammas {
        tau_x += zpow * gj;
        zpow *= z;
    }

    let mu = alpha + rho * x;

    transcript.append_scalar(b"t_hat", &t_hat);
    transcript.append_scalar(b"tau_x", &tau_x);
    transcript.append_scalar(b"mu", &mu);

    let w = transcript.challenge_scalar(b"w");
    let u_point = gens.g * w;

    let y_inv = y.invert().unwrap();
    let y_inv_padded = powers_of(&y_inv, nm_padded);
    let h_prime: Vec<ProjectivePoint> = gens.h_vec[..nm_padded]
        .iter()
        .zip(y_inv_padded.iter())
        .map(|(hi, yi)| *hi * yi)
        .collect();

    // Pad l_x and r_x with zeros to next power of 2 for IPP.
    // Zero-padding preserves the inner product (t_hat) and commitment (P).
    let mut l_x = l_x;
    let mut r_x = r_x;
    l_x.resize(nm_padded, Scalar::ZERO);
    r_x.resize(nm_padded, Scalar::ZERO);

    let ipp_proof = prove_inner_product(
        &mut transcript,
        &gens.g_vec[..nm_padded],
        &h_prime,
        &u_point,
        &l_x,
        &r_x,
    );

    let commitments: Vec<PedersenCommitment> = v_commits
        .into_iter()
        .map(|pt| PedersenCommitment { point: pt })
        .collect();

    let proof = AggregateRangeProof {
        a_commit,
        s_commit,
        t1_commit,
        t2_commit,
        t_hat,
        tau_x,
        mu,
        ipp_proof,
        n,
        m,
    };

    (commitments, proof)
}

/// Verify an aggregate range proof.
pub fn verify_aggregate_range(
    gens: &BulletproofGens,
    commitments: &[PedersenCommitment],
    proof: &AggregateRangeProof,
) -> bool {
    let n = proof.n;
    let m = proof.m;
    let nm = n * m;
    let nm_padded = nm.next_power_of_two();

    assert_eq!(commitments.len(), m);

    let mut transcript = ProofTranscript::new(b"agg_range_proof");
    for c in commitments {
        transcript.append_point(b"V", &c.point);
    }
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

    let y_nm = powers_of(&y, nm);
    let two_n = twos(n);
    let one_nm = ones(nm);

    // delta(y,z) = (z - z^2)·⟨1^{nm}, y^{nm}⟩ - Σ_{j=0}^{m-1} z^{j+3}·⟨1^n, 2^n⟩
    let ip_1_y = scalar_sum(&y_nm);
    let ip_1_2 = scalar_sum(&two_n);
    let z_sq = z * z;

    let mut delta = (z - z_sq) * ip_1_y;
    let mut zpow = z * z_sq; // z^3
    for _ in 0..m {
        delta -= zpow * ip_1_2;
        zpow *= z;
    }

    // Check: g^{t_hat} · h^{tau_x} == Σ V_j^{z^{j+2}} · g^delta · T_1^x · T_2^{x^2}
    let lhs = gens.g * proof.t_hat + gens.h * proof.tau_x;
    let mut rhs = gens.g * delta + proof.t1_commit * x + proof.t2_commit * (x * x);
    let mut zpow2 = z_sq;
    for c in commitments {
        rhs += c.point * zpow2;
        zpow2 *= z;
    }

    if lhs != rhs {
        return false;
    }

    // Build z_aggr for the inner-product check
    let mut z_aggr = Vec::with_capacity(nm);
    let mut zp = z_sq;
    for _ in 0..m {
        for twoi in &two_n {
            z_aggr.push(zp * twoi);
        }
        zp *= z;
    }

    let neg_z = -z;
    let neg_z_vec: Vec<Scalar> = vec![neg_z; nm];

    let z_y_plus_zaggr: Vec<Scalar> = y_nm
        .iter()
        .zip(z_aggr.iter())
        .map(|(yi, zagg)| z * yi + zagg)
        .collect();

    let y_inv = y.invert().unwrap();
    let y_inv_padded = powers_of(&y_inv, nm_padded);
    let h_prime: Vec<ProjectivePoint> = gens.h_vec[..nm_padded]
        .iter()
        .zip(y_inv_padded.iter())
        .map(|(hi, yi)| *hi * yi)
        .collect();

    // P is computed with nm generators; zero-padded entries contribute identity
    let p = proof.a_commit
        + proof.s_commit * x
        + msm_points(&gens.g_vec[..nm], &neg_z_vec)
        + msm_points(&h_prime[..nm], &z_y_plus_zaggr)
        - gens.h * proof.mu;

    let u_point = gens.g * w;
    let p_with_ip = p + u_point * proof.t_hat;

    verify_inner_product(
        &mut transcript,
        &gens.g_vec[..nm_padded],
        &h_prime,
        &u_point,
        &p_with_ip,
        &proof.ipp_proof,
    )
}

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
    fn aggregate_range_two_values() {
        let n = 8;
        let m = 2;
        let mut gens = BulletproofGens::new(n * m);

        let values = vec![10u64, 200u64];
        let (commitments, proof) = prove_aggregate_range(&gens, &values, n);
        assert!(verify_aggregate_range(&gens, &commitments, &proof));
    }

    #[test]
    fn aggregate_range_four_values() {
        let n = 8;
        let m = 4;
        let gens = BulletproofGens::new(n * m);

        let values = vec![0, 1, 127, 255];
        let (commitments, proof) = prove_aggregate_range(&gens, &values, n);
        assert!(verify_aggregate_range(&gens, &commitments, &proof));
    }

    #[test]
    fn aggregate_proof_size_grows_logarithmically() {
        // m=2: nm=16 → log2(16) = 4 rounds
        let gens2 = BulletproofGens::new(16);
        let (_, p2) = prove_aggregate_range(&gens2, &[1, 2], 8);

        // m=4: nm=32 → log2(32) = 5 rounds
        let gens4 = BulletproofGens::new(32);
        let (_, p4) = prove_aggregate_range(&gens4, &[1, 2, 3, 4], 8);

        // Only 1 more round for doubling m
        assert_eq!(p4.ipp_proof.l_vec.len() - p2.ipp_proof.l_vec.len(), 1);
    }

    #[test]
    fn aggregate_range_boolean_votes() {
        // Voting scenario: 4 candidates, each vote is {0, 1}
        let n = 8;
        let m = 4;
        let gens = BulletproofGens::new(n * m);

        let votes = vec![1, 0, 1, 0]; // voter selects candidates 0 and 2
        let (commitments, proof) = prove_aggregate_range(&gens, &votes, n);
        assert!(verify_aggregate_range(&gens, &commitments, &proof));
    }

    #[test]
    fn aggregate_tampered_commitment_fails() {
        let n = 8;
        let gens = BulletproofGens::new(16);

        let (mut commitments, proof) = prove_aggregate_range(&gens, &[10, 20], n);
        // Tamper with one commitment
        commitments[0] = PedersenCommitment {
            point: ProjectivePoint::GENERATOR,
        };
        assert!(!verify_aggregate_range(&gens, &commitments, &proof));
    }
}
