///! Utility helpers for scalar / vector arithmetic.

use k256::Scalar;
use elliptic_curve::Field;

/// Compute the inner product ⟨a, b⟩ = Σ a_i · b_i.
pub fn inner_product_scalar(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .fold(Scalar::ZERO, |acc, (ai, bi)| acc + *ai * *bi)
}

/// Hadamard (element-wise) product of two scalar vectors.
pub fn hadamard(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(ai, bi)| *ai * *bi).collect()
}

/// Scalar-vector multiplication: s · **v**.
pub fn scalar_vec_mul(s: &Scalar, v: &[Scalar]) -> Vec<Scalar> {
    v.iter().map(|vi| *s * *vi).collect()
}

/// Element-wise addition of two scalar vectors.
pub fn vec_add(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(ai, bi)| *ai + *bi).collect()
}

/// Element-wise subtraction: a - b.
pub fn vec_sub(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(ai, bi)| *ai - *bi).collect()
}

/// Create a vector of powers: (1, s, s^2, …, s^{n-1}).
pub fn powers_of(s: &Scalar, n: usize) -> Vec<Scalar> {
    let mut v = Vec::with_capacity(n);
    let mut cur = Scalar::ONE;
    for _ in 0..n {
        v.push(cur);
        cur *= s;
    }
    v
}

/// Sum of elements in a scalar vector.
pub fn scalar_sum(v: &[Scalar]) -> Scalar {
    v.iter().fold(Scalar::ZERO, |acc, x| acc + x)
}

/// Decompose `value` into `n` bits (little-endian) as scalars (0 or 1).
pub fn bit_decompose(value: u64, n: usize) -> Vec<Scalar> {
    (0..n)
        .map(|i| {
            if (value >> i) & 1 == 1 {
                Scalar::ONE
            } else {
                Scalar::ZERO
            }
        })
        .collect()
}

/// Build a vector of all ones of length `n`.
pub fn ones(n: usize) -> Vec<Scalar> {
    vec![Scalar::ONE; n]
}

/// Build a vector of all twos powers: (1, 2, 4, …, 2^{n-1}).
pub fn twos(n: usize) -> Vec<Scalar> {
    powers_of(&Scalar::from(2u64), n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inner_product() {
        let a = vec![Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(4u64), Scalar::from(5u64)];
        // 2*4 + 3*5 = 23
        assert_eq!(inner_product_scalar(&a, &b), Scalar::from(23u64));
    }

    #[test]
    fn test_bit_decompose() {
        let bits = bit_decompose(5, 4); // 5 = 0b0101
        assert_eq!(bits[0], Scalar::ONE);
        assert_eq!(bits[1], Scalar::ZERO);
        assert_eq!(bits[2], Scalar::ONE);
        assert_eq!(bits[3], Scalar::ZERO);
    }

    #[test]
    fn test_powers_of() {
        let s = Scalar::from(3u64);
        let p = powers_of(&s, 4);
        assert_eq!(p[0], Scalar::ONE);
        assert_eq!(p[1], Scalar::from(3u64));
        assert_eq!(p[2], Scalar::from(9u64));
        assert_eq!(p[3], Scalar::from(27u64));
    }

    #[test]
    fn test_hadamard() {
        let a = vec![Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(4u64), Scalar::from(5u64)];
        let h = hadamard(&a, &b);
        assert_eq!(h[0], Scalar::from(8u64));
        assert_eq!(h[1], Scalar::from(15u64));
    }
}
