///! End-to-End Integration Tests.
///!
///! These tests validate the full pipeline:
///!   1. Generate votes with range proofs.
///!   2. Submit them to the consumer service.
///!   3. Batch-verify all proofs.
///!   4. Execute a verifiable shuffle on the commitments.

#[cfg(test)]
mod tests {
    use crypto_primitives::generators::BulletproofGens;
    use crypto_primitives::pedersen::{PedersenCommitment, commit};
    use crypto_primitives::transcript::ProofTranscript;
    use bulletproofs_core::range_proof::{prove_range, verify_range, RangeProof};
    use bulletproofs_core::aggregate::{prove_aggregate_range, verify_aggregate_range};
    use bulletproofs_core::batch::batch_verify_range_proofs;
    use bulletproofs_core::shuffle::{prove_shuffle, verify_shuffle};
    use k256::{ProjectivePoint, Scalar};
    use elliptic_curve::Field;
    use rand::rngs::OsRng;

    /// Simulate N voters casting boolean votes and batch-verify all proofs.
    #[test]
    fn election_with_multiple_voters() {
        let n = 8; // bit-length
        let num_voters = 10;
        let gens = BulletproofGens::new(n);

        // Each voter casts a boolean vote (0 or 1)
        let votes: Vec<u64> = (0..num_voters)
            .map(|i| if i % 3 == 0 { 1 } else { 0 })
            .collect();

        let proofs: Vec<(PedersenCommitment, RangeProof)> = votes
            .iter()
            .map(|&v| prove_range(&gens, v, n))
            .collect();

        // Individual verification
        for (c, p) in &proofs {
            assert!(verify_range(&gens, c, p), "individual verification failed");
        }

        // Batch verification
        assert!(batch_verify_range_proofs(&gens, &proofs), "batch verification failed");
    }

    /// Test that invalid votes are rejected by verifier.
    #[test]
    fn reject_invalid_vote() {
        let n = 8;
        let gens = BulletproofGens::new(n);

        // Valid proof for value 42
        let (commitment, proof) = prove_range(&gens, 42, n);
        assert!(verify_range(&gens, &commitment, &proof));

        // Tamper: use a different commitment
        let fake = PedersenCommitment {
            point: ProjectivePoint::GENERATOR,
        };
        assert!(!verify_range(&gens, &fake, &proof));
    }

    /// End-to-end: generate votes, verify, shuffle, verify shuffle.
    #[test]
    fn full_election_pipeline() {
        let n = 8;
        let num_voters = 5;
        let gens = BulletproofGens::new(n);

        // Step 1: Voters generate proofs
        let votes: Vec<u64> = vec![1, 0, 1, 1, 0];
        let proofs: Vec<(PedersenCommitment, RangeProof)> = votes
            .iter()
            .map(|&v| prove_range(&gens, v, n))
            .collect();

        // Step 2: Consumer verifies all proofs in batch
        assert!(batch_verify_range_proofs(&gens, &proofs));

        // Step 3: Shuffle the commitments
        // For the shuffle, we need the underlying values and blinding factors.
        // In a real system, the shuffle would be done on committed values by a
        // mixing authority. Here we simulate with known values.
        let values: Vec<Scalar> = votes.iter().map(|&v| Scalar::from(v)).collect();
        let blindings: Vec<Scalar> = (0..num_voters)
            .map(|_| Scalar::random(&mut OsRng))
            .collect();

        // Shuffled order
        let shuffled_values = vec![
            values[4].clone(),
            values[2].clone(),
            values[0].clone(),
            values[3].clone(),
            values[1].clone(),
        ];
        let shuffled_blindings: Vec<Scalar> = (0..num_voters)
            .map(|_| Scalar::random(&mut OsRng))
            .collect();

        let (in_c, out_c, shuffle_proof) = prove_shuffle(
            &gens,
            &values,
            &blindings,
            &shuffled_values,
            &shuffled_blindings,
        );

        // Step 4: Verify the shuffle
        assert!(verify_shuffle(&gens, &in_c, &out_c, &shuffle_proof));
    }

    /// Test aggregate range proof for multi-candidate ballots.
    #[test]
    fn multi_candidate_ballot() {
        // 3 candidates, each vote ∈ [0, 256)
        let n: usize = 8;
        let m: usize = 3;
        let gens = BulletproofGens::new((n * m).next_power_of_two());

        // Voter selects candidates 0 and 2
        let ballot = vec![1u64, 0, 1];
        let (commitments, proof) = prove_aggregate_range(&gens, &ballot, n);

        assert!(verify_aggregate_range(&gens, &commitments, &proof));
    }

    /// Test that the homomorphic property of commitments enables tallying.
    #[test]
    fn homomorphic_tally() {
        let gens = BulletproofGens::new(8);

        // Three voters: votes are 1, 0, 1
        let votes = vec![1u64, 0, 1];
        let blindings: Vec<Scalar> = (0..3)
            .map(|_| Scalar::random(&mut OsRng))
            .collect();

        let commitments: Vec<PedersenCommitment> = votes
            .iter()
            .zip(blindings.iter())
            .map(|(&v, r)| commit(&gens.g, &gens.h, &Scalar::from(v), r))
            .collect();

        // Homomorphic sum of commitments
        let sum_point: ProjectivePoint = commitments
            .iter()
            .map(|c| c.point)
            .fold(ProjectivePoint::IDENTITY, |acc, p| acc + p);

        // Expected: commitment to sum(votes)=2 with sum(blindings)
        let sum_vote: Scalar = votes.iter().map(|&v| Scalar::from(v)).sum();
        let sum_blind: Scalar = blindings.iter().copied().sum();
        let expected = commit(&gens.g, &gens.h, &sum_vote, &sum_blind);

        assert_eq!(sum_point, expected.point);
    }

    /// Stress test: larger election with batch verification.
    #[test]
    fn stress_batch_verify_20_votes() {
        let n = 8;
        let gens = BulletproofGens::new(n);

        let proofs: Vec<(PedersenCommitment, RangeProof)> = (0..20)
            .map(|i| prove_range(&gens, i % 2, n))
            .collect();

        assert!(batch_verify_range_proofs(&gens, &proofs));
    }

    /// Test that the system handles edge cases properly.
    #[test]
    fn edge_case_all_zeros() {
        let n = 8;
        let num_voters = 5;
        let gens = BulletproofGens::new(n);

        let proofs: Vec<(PedersenCommitment, RangeProof)> = (0..num_voters)
            .map(|_| prove_range(&gens, 0, n))
            .collect();

        assert!(batch_verify_range_proofs(&gens, &proofs));
    }

    #[test]
    fn edge_case_all_ones() {
        let n = 8;
        let num_voters = 5;
        let gens = BulletproofGens::new(n);

        let proofs: Vec<(PedersenCommitment, RangeProof)> = (0..num_voters)
            .map(|_| prove_range(&gens, 1, n))
            .collect();

        assert!(batch_verify_range_proofs(&gens, &proofs));
    }
}
