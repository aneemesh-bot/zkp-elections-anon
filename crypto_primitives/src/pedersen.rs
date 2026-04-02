///! Pedersen commitments over secp256k1.
///!
///! A Pedersen commitment to value `x` with blinding factor `r` is:
///!     Com(x; r) = g^x · h^r
///!
///! For vector commitments with value vector **v** = (v_1, …, v_n) and
///! blinding factor `r`:
///!     Com(**v**; r) = h^r · Π g_i^{v_i}

use k256::{ProjectivePoint, Scalar};

/// A Pedersen commitment: a curve point that perfectly hides the committed
/// value and is computationally binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenCommitment {
    pub point: ProjectivePoint,
}

/// Compute a scalar Pedersen commitment:  Com(x; r) = g^x · h^r
pub fn commit(g: &ProjectivePoint, h: &ProjectivePoint, x: &Scalar, r: &Scalar) -> PedersenCommitment {
    let point = *g * x + *h * r;
    PedersenCommitment { point }
}

/// Compute a vector Pedersen commitment:
///   Com(**v**; r) = h^r · Π g_i^{v_i}
///
/// Panics if `g_vec.len() < values.len()`.
pub fn vector_commit(
    g_vec: &[ProjectivePoint],
    h: &ProjectivePoint,
    values: &[Scalar],
    r: &Scalar,
) -> PedersenCommitment {
    assert!(
        g_vec.len() >= values.len(),
        "generator vector too short for values"
    );

    let mut point = *h * r;
    for (gi, vi) in g_vec.iter().zip(values.iter()) {
        point += *gi * vi;
    }
    PedersenCommitment { point }
}

/// Multi-scalar multiplication:  Σ p_i · s_i
///
/// Used as a building block for batch verification and the inner-product
/// argument.
pub fn multiscalar_mul(points: &[ProjectivePoint], scalars: &[Scalar]) -> ProjectivePoint {
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
    use crate::generators::BulletproofGens;
    use k256::Scalar;
    use rand::rngs::OsRng;
    use elliptic_curve::Field;

    #[test]
    fn commitment_hiding() {
        let gens = BulletproofGens::new(1);
        let x = Scalar::ONE;
        let r1 = Scalar::random(&mut OsRng);
        let r2 = Scalar::random(&mut OsRng);

        let c1 = commit(&gens.g, &gens.h, &x, &r1);
        let c2 = commit(&gens.g, &gens.h, &x, &r2);
        // Different blinding factors → different commitments (hides value)
        assert_ne!(c1, c2);
    }

    #[test]
    fn commitment_binding() {
        let gens = BulletproofGens::new(1);
        let r = Scalar::random(&mut OsRng);
        let x1 = Scalar::ONE;
        let x2 = Scalar::from(2u64);

        let c1 = commit(&gens.g, &gens.h, &x1, &r);
        let c2 = commit(&gens.g, &gens.h, &x2, &r);
        // Same blinding, different values → different commitments (binding)
        assert_ne!(c1, c2);
    }

    #[test]
    fn commitment_homomorphic() {
        let gens = BulletproofGens::new(1);
        let r1 = Scalar::random(&mut OsRng);
        let r2 = Scalar::random(&mut OsRng);
        let x1 = Scalar::from(3u64);
        let x2 = Scalar::from(5u64);

        let c1 = commit(&gens.g, &gens.h, &x1, &r1);
        let c2 = commit(&gens.g, &gens.h, &x2, &r2);
        let c_sum = commit(&gens.g, &gens.h, &(x1 + x2), &(r1 + r2));

        // Homomorphic property: Com(x1;r1) + Com(x2;r2) = Com(x1+x2; r1+r2)
        assert_eq!(c1.point + c2.point, c_sum.point);
    }

    #[test]
    fn vector_commitment_matches_scalar() {
        let gens = BulletproofGens::new(1);
        let x = Scalar::from(7u64);
        let r = Scalar::random(&mut OsRng);

        let scalar_com = commit(&gens.g_vec[0], &gens.h, &x, &r);
        let vec_com = vector_commit(&gens.g_vec, &gens.h, &[x], &r);
        assert_eq!(scalar_com, vec_com);
    }

    #[test]
    fn multiscalar_mul_identity() {
        let gens = BulletproofGens::new(4);
        let zeros = vec![Scalar::ZERO; 4];
        let result = multiscalar_mul(&gens.g_vec, &zeros);
        assert_eq!(result, ProjectivePoint::IDENTITY);
    }
}
