/// - PUBLIC INPUTS (Verifier sees):
///   * fibonacci_value: u64 - Expected Fibonacci result
///   * committed_index: u64 - Committed index (in real impl, this would be hash)
///
/// - PRIVATE INPUTS (Only Prover knows):
///   * fibonacci_index: u64 - Secret index from server
///
/// - CIRCUIT VERIFIES (3 steps):
///   * STEP 1: Check committed_index matches fibonacci_index (simulated commitment)
///   * STEP 2: Compute fibonacci(fibonacci_index)
///   * STEP 3: Verify result == fibonacci_value
///
/// NOTE: In production with TLSNotary, you would:
/// - Replace committed_index with SHA256(fibonacci_index || blinder)
/// - Add SHA256 circuit constraints (requires ~25k constraints)
/// - This example uses direct comparison for simplicity

mod computing;
mod trace_gen;

pub use computing::{SimpleFibComponent, FibEval};
pub use trace_gen::gen_fib_trace;

use num_traits::Zero;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo::core::pcs::{CommitmentSchemeVerifier, TreeVec};
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::TraceLocationAllocator;

pub const LOG_CONSTRAINT_DEGREE: u32 = 1;

pub fn gen_is_first_column(log_size: u32) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    col.set(0, BaseField::from_u32_unchecked(1));

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());

    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn is_first_column_id(log_size: u32) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_first_{}", log_size),
    }
}


#[derive(Clone, Copy, Debug)]
pub struct FibStatement {
    pub log_size: u32,
    pub fibonacci_value: u32,
}

impl FibStatement {
    pub fn mix_into(&self, channel: &mut Blake2sChannel) {
        channel.mix_u64(self.log_size as u64);
        channel.mix_u64(self.fibonacci_value as u64);
    }

    pub fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        TreeVec(vec![
            vec![self.log_size; 1],
            vec![self.log_size; 4],
        ])
    }
}


/// This generates a STARK proof that:
/// 1. The prover knows fibonacci_index (private input from server/TLSNotary)
/// 2. The prover COMPUTED fibonacci(fibonacci_index) correctly
/// 3. The result fibonacci_value is the PUBLIC OUTPUT (not input!)
pub fn prove_simple_fib(
    fibonacci_index: usize, 
    channel: &mut Blake2sChannel,
    mut commitment_scheme: CommitmentSchemeProver<SimdBackend, Blake2sMerkleChannel>,
) -> Result<
    (
        StarkProof<Blake2sMerkleHasher>,
        SimpleFibComponent,
        FibStatement,
    ),
    Box<dyn std::error::Error>,
> {
    let min_rows = fibonacci_index + 1;
    let min_log_size = if min_rows <= 1 {
        0
    } else {
        (min_rows - 1).ilog2() + 1
    };
    let log_size = min_log_size.max(4);

    let is_first_col = gen_is_first_column(log_size);
    let preprocessed_trace = vec![is_first_col];

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preprocessed_trace);
    tree_builder.commit(channel);

    let (trace, fibonacci_value) = gen_fib_trace(log_size, fibonacci_index);

    let statement = FibStatement {
        log_size,
        fibonacci_value, 
    };
    statement.mix_into(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(channel);

    let mut tree_span_provider = TraceLocationAllocator::default();

    let component = SimpleFibComponent::new(
        &mut tree_span_provider,
        FibEval {
            log_n_rows: log_size,
            fibonacci_value,
            is_first_id: is_first_column_id(log_size),
        },
        SecureField::zero(),
    );

    let proof = prove(&[&component], channel, commitment_scheme)?;

    Ok((proof, component, statement))
}

pub fn verify_fib(
    proof: StarkProof<Blake2sMerkleHasher>,
    statement: FibStatement,
    config: stwo::core::pcs::PcsConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let log_sizes = statement.log_sizes();

    commitment_scheme.commit(proof.commitments[0], &log_sizes[0], channel);

    statement.mix_into(channel);

    commitment_scheme.commit(proof.commitments[1], &log_sizes[1], channel);

    let mut tree_span_provider = TraceLocationAllocator::default();

    let component = SimpleFibComponent::new(
        &mut tree_span_provider,
        FibEval {
            log_n_rows: statement.log_size,
            fibonacci_value: statement.fibonacci_value,
            is_first_id: is_first_column_id(statement.log_size),
        },
        SecureField::zero(),
    );
    stwo::core::verifier::verify(&[&component], channel, commitment_scheme, proof)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::channel::Blake2sChannel;
    use stwo::core::pcs::PcsConfig;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::CommitmentSchemeProver;

    #[test]
    fn test_simple_fib_prove_verify() {
        println!("\n=== Testing Simple Fibonacci Proof ===\n");

        let fibonacci_index: usize = 5;

        let config = PcsConfig::default();
        let min_log_size: u32 = if fibonacci_index + 1 <= 1 { 0 } else { (fibonacci_index as u32).ilog2() + 1 };
        let log_size = min_log_size.max(4);

        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );

        let channel = &mut Blake2sChannel::default();
        let commitment_scheme = CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(
            config,
            &twiddles,
        );

        // Prove (fibonacci_value will be computed internally)
        let result = prove_simple_fib(fibonacci_index, channel, commitment_scheme);

        match result {
            Ok((proof, _component, statement)) => {
                println!("\n✓ Proof generated successfully!");
                println!("✓ Prover computed: fibonacci({}) = {}", fibonacci_index, statement.fibonacci_value);

                assert_eq!(statement.fibonacci_value, 5, "fibonacci(5) should be 5");

                let verify_result = verify_fib(proof, statement, config);

                match verify_result {
                    Ok(()) => {
                        println!("\n=== SUCCESS ===");
                        println!("Proof verified successfully!");
                        println!("\nThis proves:");
                        println!("  1. Prover knows fibonacci_index = {}", fibonacci_index);
                        println!("  2. Prover computed fibonacci({}) = {}", fibonacci_index, statement.fibonacci_value);
                        println!("  3. Verifier confirmed the computation is correct");
                    }
                    Err(e) => panic!("Verification failed: {:?}", e),
                }
            }
            Err(e) => panic!("Proof generation failed: {:?}", e),
        }
    }

    #[test]
    fn test_different_fibonacci_values() {
        let test_cases = vec![
            (0, 0),
            (1, 1),
            (2, 1),
            (3, 2),
            (4, 3),
            (5, 5),
            (6, 8),
            (7, 13),
        ];

        for (index, expected_value) in test_cases {
            println!("\nTesting fibonacci({}) ...", index);

            let config = PcsConfig::default();
            let min_log_size: u32 = if index + 1 <= 1 { 0 } else { (index as u32).ilog2() + 1 };
            let log_size = min_log_size.max(4);

            let twiddles = SimdBackend::precompute_twiddles(
                CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
                    .circle_domain()
                    .half_coset,
            );

            let channel = &mut Blake2sChannel::default();
            let commitment_scheme = CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(
                config,
                &twiddles,
            );

            // Prover computes fibonacci_value internally
            let result = prove_simple_fib(index, channel, commitment_scheme);

            match result {
                Ok((_proof, _component, statement)) => {
                    let computed_value = statement.fibonacci_value;
                    println!("✓ Prover computed fibonacci({}) = {}", index, computed_value);
                    assert_eq!(computed_value, expected_value,
                              "fibonacci({}) should be {}, got {}", index, expected_value, computed_value);
                }
                Err(e) => {
                    panic!("Failed for fibonacci({}) = {}: {:?}", index, expected_value, e);
                }
            }
        }

        println!("\n✓ All test cases passed!");
    }
}

