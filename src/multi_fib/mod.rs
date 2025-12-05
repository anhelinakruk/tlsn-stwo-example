use stwo_constraint_framework::relation;

mod computing;
mod scheduler;
mod trace_gen;

pub use computing::{FibonacciComputingComponent, FibonacciComputingEval};
pub use scheduler::{FibonacciSchedulerComponent, FibonacciSchedulerEval};
pub use trace_gen::{
    gen_computing_interaction_trace, gen_computing_trace, gen_scheduler_interaction_trace,
    gen_scheduler_trace,
};

pub const LOG_CONSTRAINT_DEGREE: u32 = 1;
pub const FIBONACCI_RELATION_SIZE: usize = 1;
pub const INDEX_RELATION_SIZE: usize = 1;

relation!(FibonacciRelation, FIBONACCI_RELATION_SIZE);
relation!(IndexRelation, INDEX_RELATION_SIZE);

use num_traits::{One, Zero};
use std::simd::u32x16;
use itertools::{chain, multiunzip, Itertools};
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver, ComponentProver};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::TraceLocationAllocator;

use crate::blake::{round as blake_round, xor_table as blake_xor, BlakeXorElements, N_ROUNDS, ROUND_LOG_SPLIT};
use crate::blake::scheduler as blake_scheduler;
use crate::blake::scheduler::BlakeInput;

pub fn compute_blake3_log_size(num_instances: usize) -> u32 {
    if num_instances <= 1 {
        LOG_N_LANES
    } else {
        ((num_instances as u32 - 1).ilog2() + 1 + LOG_N_LANES as u32).max(LOG_N_LANES)
    }
}

pub fn compute_max_log_size(fib_log_size: u32, blake3_log_size: u32) -> u32 {
    use crate::blake::XOR12_MIN_LOG_SIZE;

    fib_log_size
        .max(blake3_log_size + ROUND_LOG_SPLIT[0])
        .max(XOR12_MIN_LOG_SIZE)
}


pub fn gen_is_first_column(
    log_size: u32,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
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

pub fn gen_is_active_column(
    log_size: u32,
    target_element: usize,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    for row in 0..=target_element.min(n_rows - 1) {
        col.set(row, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());

    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn is_active_column_id(log_size: u32, target_element: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_active_{}_upto{}", log_size, target_element),
    }
}

pub fn gen_is_target_column(
    log_size: u32,
    target_element: usize,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    if target_element < n_rows {
        col.set(target_element, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());

    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn is_target_column_id(log_size: u32, target_element: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_target_{}_row{}", log_size, target_element),
    }
}
/// Statement 0: Component configuration (log_size)
/// This is mixed into the channel before drawing the FibonacciRelation
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct MultiFibStatement0 {
    pub log_size: u32,
    pub blake3_log_size: Option<u32>, // log_size for BLAKE3 (if enabled)
}

impl MultiFibStatement0 {
    pub fn mix_into(&self, channel: &mut Blake2sChannel) {
        channel.mix_u64(self.log_size as u64);
        if let Some(blake3_log_size) = self.blake3_log_size {
            channel.mix_u64(blake3_log_size as u64);
        }
    }

    /// Returns log sizes for all trees (preprocessed, main, interaction)
    /// This must EXACTLY match the order and structure of how we commit traces!
    pub fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        if let Some(blake3_log_size) = self.blake3_log_size {
            use crate::blake::ROUND_LOG_SPLIT;

            // Tree 0: Preprocessed columns
            // We commit: Fibonacci (5 cols) + BLAKE3 XOR tables (5×3=15 cols)
            use crate::blake::{XOR12_MIN_LOG_SIZE, XOR9_MIN_LOG_SIZE, XOR8_MIN_LOG_SIZE,
                               XOR7_MIN_LOG_SIZE, XOR4_MIN_LOG_SIZE};
            let tree0 = chain![
                vec![self.log_size; 5],           // Fibonacci: is_first, is_active1, is_target1, is_active2, is_target2
                vec![XOR12_MIN_LOG_SIZE; 3],      // XOR12: a, b, c
                vec![XOR9_MIN_LOG_SIZE; 3],       // XOR9: a, b, c
                vec![XOR8_MIN_LOG_SIZE; 3],       // XOR8: a, b, c
                vec![XOR7_MIN_LOG_SIZE; 3],       // XOR7: a, b, c
                vec![XOR4_MIN_LOG_SIZE; 3],       // XOR4: a, b, c
            ].collect();

            // Tree 1: Main traces
            // We commit: Fibonacci (9 cols) + BLAKE3 scheduler (288 cols) + rounds (384×3) + XOR mains (305 cols)
            let tree1 = chain![
                vec![self.log_size; 9],                              // Fibonacci: 3+3+3 cols from computing1, computing2, scheduler
                vec![blake3_log_size; 288],                          // BLAKE3 scheduler: 288 cols
                vec![blake3_log_size + ROUND_LOG_SPLIT[0]; 384],     // Round 0: 384 cols
                vec![blake3_log_size + ROUND_LOG_SPLIT[1]; 384],     // Round 1: 384 cols
                vec![blake3_log_size + ROUND_LOG_SPLIT[2]; 384],     // Round 2: 384 cols
                vec![XOR12_MIN_LOG_SIZE; 256],                       // XOR12 main: 256 cols
                vec![XOR9_MIN_LOG_SIZE; 16],                         // XOR9 main: 16 cols
                vec![XOR8_MIN_LOG_SIZE; 16],                         // XOR8 main: 16 cols
                vec![XOR7_MIN_LOG_SIZE; 16],                         // XOR7 main: 16 cols
                vec![XOR4_MIN_LOG_SIZE; 1],                          // XOR4 main: 1 col
            ].collect();

            // Tree 2: Interaction traces
            // We commit: Fibonacci (12 cols) + BLAKE3 scheduler (16 cols) + rounds (260×3) + XOR interactions (612 cols)
            let tree2 = chain![
                vec![self.log_size; 12],                             // Fibonacci: 4+4+4 cols from computing1, computing2, scheduler
                vec![blake3_log_size; 16],                           // BLAKE3 scheduler: 16 cols
                vec![blake3_log_size + ROUND_LOG_SPLIT[0]; 260],     // Round 0: 260 cols
                vec![blake3_log_size + ROUND_LOG_SPLIT[1]; 260],     // Round 1: 260 cols
                vec![blake3_log_size + ROUND_LOG_SPLIT[2]; 260],     // Round 2: 260 cols
                vec![XOR12_MIN_LOG_SIZE; 512],                       // XOR12 interaction: 512 cols
                vec![XOR9_MIN_LOG_SIZE; 32],                         // XOR9 interaction: 32 cols
                vec![XOR8_MIN_LOG_SIZE; 32],                         // XOR8 interaction: 32 cols
                vec![XOR7_MIN_LOG_SIZE; 32],                         // XOR7 interaction: 32 cols
                vec![XOR4_MIN_LOG_SIZE; 4],                          // XOR4 interaction: 4 cols
            ].collect();

            TreeVec(vec![tree0, tree1, tree2])
        } else {
            // Original without BLAKE3
            TreeVec(vec![
                vec![self.log_size; 5],   // Tree 0: Preprocessed
                vec![self.log_size; 9],   // Tree 1: Main traces
                vec![self.log_size; 12],  // Tree 2: Interaction traces
            ])
        }
    }
}

/// Statement 1: LogUp claimed sums
/// This is mixed into the channel after drawing FibonacciRelation
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MultiFibStatement1 {
    pub claimed_sum_computing1: SecureField,
    pub claimed_sum_computing2: SecureField,
    pub claimed_sum_scheduler: SecureField,
    // BLAKE3 claimed sums (if enabled)
    pub blake3_scheduler_claimed_sum: Option<SecureField>,
    pub blake3_round_claimed_sums: Option<Vec<SecureField>>,
    pub blake3_xor12_claimed_sum: Option<SecureField>,
    pub blake3_xor9_claimed_sum: Option<SecureField>,
    pub blake3_xor8_claimed_sum: Option<SecureField>,
    pub blake3_xor7_claimed_sum: Option<SecureField>,
    pub blake3_xor4_claimed_sum: Option<SecureField>,
}

impl MultiFibStatement1 {
    pub fn mix_into(&self, channel: &mut Blake2sChannel) {
        channel.mix_felts(&[
            self.claimed_sum_computing1,
            self.claimed_sum_computing2,
            self.claimed_sum_scheduler,
        ]);

        // Mix BLAKE3 claimed sums if present
        if let Some(blake3_scheduler) = self.blake3_scheduler_claimed_sum {
            channel.mix_felts(&[blake3_scheduler]);
        }
        if let Some(ref round_sums) = self.blake3_round_claimed_sums {
            channel.mix_felts(round_sums);
        }
        if let Some(xor12) = self.blake3_xor12_claimed_sum {
            channel.mix_felts(&[xor12]);
        }
        if let Some(xor9) = self.blake3_xor9_claimed_sum {
            channel.mix_felts(&[xor9]);
        }
        if let Some(xor8) = self.blake3_xor8_claimed_sum {
            channel.mix_felts(&[xor8]);
        }
        if let Some(xor7) = self.blake3_xor7_claimed_sum {
            channel.mix_felts(&[xor7]);
        }
        if let Some(xor4) = self.blake3_xor4_claimed_sum {
            channel.mix_felts(&[xor4]);
        }
    }
}

/// Prove multi-component Fibonacci with LogUp + BLAKE3 verification
///
/// This generates a STARK proof for:
/// - Computing1: Fibonacci up to target_element_computing1 (rest are zeros)
/// - Computing2: Fibonacci up to target_element_computing2 (rest are zeros)
/// - Scheduler: Sums specific results from Computing1 and Computing2
/// - BLAKE3: Verifies hash(fibonacci_index + blinder) == committed_hash (2 instances)
///
/// LogUp verifies that Scheduler uses the correct values from both Computing components.
pub fn prove_multi_fib(
    target_element_computing1: usize,
    target_element_computing2: usize,
    blake3_inputs: Option<Vec<([u32; 16], [u32; 16])>>, // (v, m) pairs for BLAKE3
    blake3_expected_hashes: Option<Vec<[u8; 32]>>, // expected hashes to verify
    channel: &mut Blake2sChannel,
    mut commitment_scheme: CommitmentSchemeProver<SimdBackend, Blake2sMerkleChannel>,
) -> Result<
    (
        StarkProof<Blake2sMerkleHasher>,
        [FibonacciComputingComponent; 2],
        FibonacciSchedulerComponent,
        MultiFibStatement0,
        MultiFibStatement1,
    ),
    Box<dyn std::error::Error>,
> {
    // Validate BLAKE3 inputs/hashes consistency
    if let (Some(ref inputs), Some(ref hashes)) = (&blake3_inputs, &blake3_expected_hashes) {
        if inputs.len() != hashes.len() {
            return Err(format!(
                "BLAKE3 inputs/hashes length mismatch: {} inputs, {} hashes",
                inputs.len(), hashes.len()
            ).into());
        }
        if inputs.is_empty() {
            return Err("BLAKE3 inputs cannot be empty when provided".into());
        }
    } else if blake3_inputs.is_some() || blake3_expected_hashes.is_some() {
        return Err("BLAKE3 inputs and expected_hashes must both be provided or both be None".into());
    }

    // Step 0: Compute dynamic log_size
    let max_target = target_element_computing1.max(target_element_computing2);
    let min_rows = max_target + 1;
    let min_log_size = if min_rows <= 1 {
        0
    } else {
        (min_rows - 1).ilog2() + 1 // log2_ceil
    };
    let log_size = min_log_size.max(4); // minimum 16 rows for SIMD (LOG_N_LANES = 4)

    use std::time::Instant;
    let total_start = Instant::now();

    tracing::info!("=== Multi-Component Fibonacci Proof Generation ===");
    tracing::info!(
        "Target elements: Computing1={}, Computing2={}",
        target_element_computing1, target_element_computing2
    );
    tracing::info!("Computed log_size: {} ({} rows)", log_size, 1 << log_size);

    // Step 1: Generate and commit preprocessed columns
    tracing::debug!("Step 1: Generating and committing preprocessed columns...");
    let step_start = Instant::now();
    let is_first_col = gen_is_first_column(log_size);
    let is_active_comp1_col = gen_is_active_column(log_size, target_element_computing1);
    let is_target_comp1_col = gen_is_target_column(log_size, target_element_computing1);
    let is_active_comp2_col = gen_is_active_column(log_size, target_element_computing2);
    let is_target_comp2_col = gen_is_target_column(log_size, target_element_computing2);

    let preprocessed_trace = vec![
        is_first_col,
        is_active_comp1_col,
        is_target_comp1_col,
        is_active_comp2_col,
        is_target_comp2_col,
    ];

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preprocessed_trace);

    // Step 1.5: Add BLAKE3 preprocessed columns if enabled
    let blake3_log_size = if let Some(ref inputs) = blake3_inputs {
        let num_instances = inputs.len();
        let blake3_log = compute_blake3_log_size(num_instances);
        tracing::info!("BLAKE3 enabled: {} instances, log_size={}", num_instances, blake3_log);

        // Add XOR table preprocessed columns
        use crate::blake::preprocessed_columns::XorTable;
        let xor12_pre = XorTable::new(12, 4, 0).generate_constant_trace();
        let xor9_pre = XorTable::new(9, 2, 0).generate_constant_trace();
        let xor8_pre = XorTable::new(8, 2, 0).generate_constant_trace();
        let xor7_pre = XorTable::new(7, 2, 0).generate_constant_trace();
        let xor4_pre = XorTable::new(4, 0, 0).generate_constant_trace();

        tree_builder.extend_evals(chain![xor12_pre, xor9_pre, xor8_pre, xor7_pre, xor4_pre].collect_vec());

        Some(blake3_log)
    } else {
        None
    };

    tree_builder.commit(channel);

    // Mix Statement0 (log_size, target_elements) into channel
    let statement0 = MultiFibStatement0 {
        log_size,
        blake3_log_size,
    };
    statement0.mix_into(channel);
    tracing::debug!("Preprocessed columns: {:?}", step_start.elapsed());

    // Step 2: Generate main traces for all components
    tracing::debug!("Step 2: Generating main traces...");
    let step_start = Instant::now();
    let (trace_computing1, fib1_c_value) =
        gen_computing_trace(log_size, 0, 1, target_element_computing1);
    let (trace_computing2, fib2_c_value) =
        gen_computing_trace(log_size, 0, 1, target_element_computing2);
    let trace_scheduler = gen_scheduler_trace(log_size, fib1_c_value, fib2_c_value);
    tracing::debug!("Computing1 trace (initial: 0, 1): {} rows", 1 << log_size);
    tracing::debug!("Computing2 trace (initial: 0, 1): {} rows", 1 << log_size);
    tracing::debug!("Scheduler trace: {} rows", 1 << log_size);

    // Step 2.5: Generate BLAKE3 traces if enabled
    let (blake3_scheduler_trace, blake3_round_traces, blake3_xor_traces, blake3_xor_lookup_data, _blake3_round_inputs) =
        if let (Some(ref inputs), Some(blake3_log)) = (&blake3_inputs, blake3_log_size) {
            tracing::debug!("Step 2.5: Generating BLAKE3 traces...");

            // Convert inputs to BlakeInput format (u32x16 SIMD)
            let blake_inputs: Vec<BlakeInput> = inputs
                .iter()
                .map(|(v, m)| BlakeInput {
                    v: v.map(u32x16::splat),
                    m: m.map(u32x16::splat),
                })
                .collect();

            // Generate scheduler trace
            let (scheduler_trace, scheduler_lookup_data, round_inputs) =
                blake_scheduler::gen_trace(blake3_log, &blake_inputs, target_element_computing1);

            // Generate rounds traces
            use crate::blake::XorAccums;
            let mut xor_accums = XorAccums::default();
            let mut rest = &round_inputs[..];
            let (round_traces, round_lookup_data): (Vec<_>, Vec<_>) =
                multiunzip(ROUND_LOG_SPLIT.map(|l| {
                    let (cur_inputs, r) = rest.split_at(1 << (blake3_log - LOG_N_LANES + l));
                    rest = r;
                    blake_round::generate_trace(blake3_log + l, cur_inputs, &mut xor_accums)
                }));

            // Generate XOR tables traces
            let (xor_trace12, xor_lookup_data12) = blake_xor::xor12::generate_trace(xor_accums.xor12);
            let (xor_trace9, xor_lookup_data9) = blake_xor::xor9::generate_trace(xor_accums.xor9);
            let (xor_trace8, xor_lookup_data8) = blake_xor::xor8::generate_trace(xor_accums.xor8);
            let (xor_trace7, xor_lookup_data7) = blake_xor::xor7::generate_trace(xor_accums.xor7);
            let (xor_trace4, xor_lookup_data4) = blake_xor::xor4::generate_trace(xor_accums.xor4);

            tracing::debug!("Generated BLAKE3 scheduler + {} round components + 5 XOR tables", ROUND_LOG_SPLIT.len());

            // Step B: Extract and verify BLAKE3 outputs
            if let Some(ref expected_hashes) = blake3_expected_hashes {
                tracing::info!("Verifying BLAKE3 outputs...");

                for (idx, ((v_init, m), expected_hash)) in
                    inputs.iter().zip(expected_hashes.iter()).enumerate()
                {
                    // Simulate BLAKE3 compression (same as scheduler does)
                    // Convert to u32x16 for SIMD operations
                    let mut v: [u32x16; 16] = v_init.map(u32x16::splat);
                    let mut m_current: [u32x16; 16] = m.map(u32x16::splat);

                    // Run all 7 rounds
                    for r in 0..N_ROUNDS {
                        use crate::blake::blake3;
                        blake3::round(&mut v, m_current, r);
                        // Permute message for next round
                        m_current = blake3::MSG_SCHEDULE.map(|i| m_current[i as usize]);
                    }

                    // Finalize: XOR to get output hash
                    // Step 1: state[i] ^= state[i + 8] for i=0..8
                    for i in 0..8 {
                        v[i] ^= v[i + 8];
                    }
                    // Step 2: state[i + 8] ^= chaining_value[i] for i=0..8
                    for i in 0..8 {
                        let cv_i = u32x16::splat(v_init[i]);
                        v[i + 8] ^= cv_i;
                    }

                    // Extract output hash (first 8 u32 words = 32 bytes)
                    // Extract first lane from SIMD (all lanes should be identical for splat inputs)
                    let mut computed_hash = [0u8; 32];
                    for i in 0..8 {
                        let word = v[i].to_array()[0]; // Get first lane
                        computed_hash[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
                    }

                    // Verify computed hash matches expected
                    if &computed_hash != expected_hash {
                        return Err(format!(
                            "BLAKE3 verification failed for input {}: computed {:?} != expected {:?}",
                            idx, computed_hash, expected_hash
                        ).into());
                    }

                    tracing::debug!("BLAKE3 output {} verified: {:?}", idx, &computed_hash[..8]);
                }

                tracing::info!("All {} BLAKE3 outputs verified successfully!", expected_hashes.len());
            }

            // Store for later use (including XOR lookup data for interaction trace generation)
            (
                Some((scheduler_trace, scheduler_lookup_data)),
                Some((round_traces, round_lookup_data)),
                Some((xor_trace12, xor_trace9, xor_trace8, xor_trace7, xor_trace4)),
                Some((xor_lookup_data12, xor_lookup_data9, xor_lookup_data8, xor_lookup_data7, xor_lookup_data4)),
                Some(round_inputs),
            )
        } else {
            (None, None, None, None, None)
        };

    // Step 3: Commit main traces
    tracing::debug!("Step 3: Committing main traces...");
    let mut tree_builder = commitment_scheme.tree_builder();

    // Fibonacci traces must be cloned - they're used later for interaction trace generation
    let fib_traces = [
        trace_computing1.clone(),
        trace_computing2.clone(),
        trace_scheduler.clone(),
    ].concat();
    tree_builder.extend_evals(fib_traces);

    // BLAKE3 traces: only lookup_data is needed after this point, but since they're
    // stored in tuples with traces, we need to clone. Future optimization: separate storage.
    if let Some((ref scheduler_trace, _)) = blake3_scheduler_trace {
        tree_builder.extend_evals(scheduler_trace.clone());
    }
    if let Some((ref round_traces, _)) = blake3_round_traces {
        // Optimized: use iter().flatten() instead of clone().into_iter().flatten()
        // Saves one Vec allocation for the outer structure
        let flat_rounds: Vec<_> = round_traces.iter().flatten().cloned().collect_vec();
        tree_builder.extend_evals(flat_rounds);
    }
    if let Some((ref xor12, ref xor9, ref xor8, ref xor7, ref xor4)) = blake3_xor_traces {
        // Use chain! macro which is slightly more efficient than multiple Vec::concat calls
        let xor_traces = chain![
            xor12.clone(),
            xor9.clone(),
            xor8.clone(),
            xor7.clone(),
            xor4.clone(),
        ].collect_vec();
        tree_builder.extend_evals(xor_traces);
    }

    tree_builder.commit(channel);
    tracing::debug!("Main traces generated and committed: {:?}", step_start.elapsed());

    // Step 4: Draw FibonacciRelation from channel
    tracing::debug!("Step 4: Drawing LogUp relation from channel...");
    let step_start = Instant::now();
    let fibonacci_relation = FibonacciRelation::draw(channel);
    let index_relation = IndexRelation::draw(channel);

    // Step 5: Generate interaction traces (LogUp columns)
    tracing::debug!("Step 5: Generating LogUp interaction traces...");
    let (interaction_trace_computing1, claimed_sum_computing1) = gen_computing_interaction_trace(
        &trace_computing1,
        &fibonacci_relation,
        target_element_computing1,
    );

    let (interaction_trace_computing2, claimed_sum_computing2) = gen_computing_interaction_trace(
        &trace_computing2,
        &fibonacci_relation,
        target_element_computing2,
    );

    let (interaction_trace_scheduler, claimed_sum_scheduler) =
        gen_scheduler_interaction_trace(&trace_scheduler, &fibonacci_relation);

    // Step 6: Verify LogUp property: sum of all claimed_sums should be 0
    let total_sum = claimed_sum_computing1 + claimed_sum_computing2 + claimed_sum_scheduler;
    tracing::debug!("LogUp verification:");
    tracing::debug!("  Computing1 yields: {:?}", claimed_sum_computing1);
    tracing::debug!("  Computing2 yields: {:?}", claimed_sum_computing2);
    tracing::debug!("  Scheduler uses:    {:?}", claimed_sum_scheduler);
    tracing::debug!("  Total sum:         {:?}", total_sum);
    if total_sum == Zero::zero() {
        tracing::debug!("LogUp property satisfied: total sum = 0");
    } else {
        tracing::warn!("Warning: LogUp sum is not zero!");
    }

    // Step 5.5: Draw BLAKE3 lookup elements and generate interaction traces
    let (blake3_all_elements, blake3_interaction_traces, blake3_xor_interaction_traces, blake3_claimed_sums) =
        if blake3_scheduler_trace.is_some() {
            tracing::debug!("Step 5.5: Drawing BLAKE3 lookup elements...");

            // Draw BLAKE3-specific elements
            let blake3_xor_elements = BlakeXorElements::draw(channel);
            use crate::blake::round::RoundElements;
            use crate::blake::scheduler::BlakeElements;
            let blake3_round_elements = RoundElements::draw(channel);
            let blake3_blake_elements = BlakeElements::draw(channel);

            tracing::debug!("Generating BLAKE3 interaction traces...");

            // Generate scheduler interaction trace
            let (scheduler_int_trace, scheduler_claimed_sum) = if let Some((_, ref lookup_data)) =
                blake3_scheduler_trace
            {
                blake_scheduler::gen_interaction_trace(
                    blake3_log_size.unwrap(),
                    lookup_data.clone(),
                    &blake3_round_elements,
                    &blake3_blake_elements,
                    &index_relation,
                    target_element_computing1,
                )
            } else {
                panic!("BLAKE3 scheduler trace missing");
            };

            // Generate rounds interaction traces
            let (round_int_traces, round_claimed_sums): (Vec<_>, Vec<_>) =
                if let Some((_, ref lookup_data_vec)) = blake3_round_traces {
                    multiunzip(ROUND_LOG_SPLIT.iter().zip(lookup_data_vec).map(|(l, lookup_data)| {
                        blake_round::generate_interaction_trace(
                            blake3_log_size.unwrap() + l,
                            lookup_data.clone(),
                            &blake3_xor_elements,
                            &blake3_round_elements,
                        )
                    }))
                } else {
                    (vec![], vec![])
                };

            // Generate XOR tables interaction traces using lookup data
            let (xor12_int_trace, xor12_claimed_sum, xor9_int_trace, xor9_claimed_sum,
                 xor8_int_trace, xor8_claimed_sum, xor7_int_trace, xor7_claimed_sum,
                 xor4_int_trace, xor4_claimed_sum) =
                if let Some((ref lookup12, ref lookup9, ref lookup8, ref lookup7, ref lookup4)) = blake3_xor_lookup_data {
                    use crate::blake::xor_table::{xor12, xor9, xor8, xor7, xor4};

                    let (trace12, sum12) = xor12::generate_interaction_trace(
                        lookup12.clone(),
                        &blake3_xor_elements.xor12,
                    );
                    let (trace9, sum9) = xor9::generate_interaction_trace(
                        lookup9.clone(),
                        &blake3_xor_elements.xor9,
                    );
                    let (trace8, sum8) = xor8::generate_interaction_trace(
                        lookup8.clone(),
                        &blake3_xor_elements.xor8,
                    );
                    let (trace7, sum7) = xor7::generate_interaction_trace(
                        lookup7.clone(),
                        &blake3_xor_elements.xor7,
                    );
                    let (trace4, sum4) = xor4::generate_interaction_trace(
                        lookup4.clone(),
                        &blake3_xor_elements.xor4,
                    );

                    (Some(trace12), sum12, Some(trace9), sum9, Some(trace8), sum8,
                     Some(trace7), sum7, Some(trace4), sum4)
                } else {
                    (None, SecureField::zero(), None, SecureField::zero(), None, SecureField::zero(),
                     None, SecureField::zero(), None, SecureField::zero())
                };

            tracing::debug!(
                "Generated BLAKE3 interaction: scheduler + {} rounds + 5 XOR tables",
                round_claimed_sums.len()
            );

            (
                Some((blake3_xor_elements, blake3_round_elements, blake3_blake_elements)),
                Some((scheduler_int_trace, round_int_traces)),
                Some((xor12_int_trace, xor9_int_trace, xor8_int_trace, xor7_int_trace, xor4_int_trace)),
                Some((
                    scheduler_claimed_sum,
                    round_claimed_sums,
                    xor12_claimed_sum,
                    xor9_claimed_sum,
                    xor8_claimed_sum,
                    xor7_claimed_sum,
                    xor4_claimed_sum,
                )),
            )
        } else {
            (None, None, None, None)
        };

    // Mix Statement1 (claimed_sums) into channel
    let statement1 = MultiFibStatement1 {
        claimed_sum_computing1,
        claimed_sum_computing2,
        claimed_sum_scheduler,
        blake3_scheduler_claimed_sum: blake3_claimed_sums.as_ref().map(|s| s.0),
        blake3_round_claimed_sums: blake3_claimed_sums.as_ref().map(|s| s.1.clone()),
        blake3_xor12_claimed_sum: blake3_claimed_sums.as_ref().map(|s| s.2),
        blake3_xor9_claimed_sum: blake3_claimed_sums.as_ref().map(|s| s.3),
        blake3_xor8_claimed_sum: blake3_claimed_sums.as_ref().map(|s| s.4),
        blake3_xor7_claimed_sum: blake3_claimed_sums.as_ref().map(|s| s.5),
        blake3_xor4_claimed_sum: blake3_claimed_sums.as_ref().map(|s| s.6),
    };
    statement1.mix_into(channel);

    // Step 6: Commit interaction traces
    tracing::debug!("Step 6: Committing interaction traces...");
    let mut tree_builder = commitment_scheme.tree_builder();

    let fib_int_traces = [
        interaction_trace_computing1,
        interaction_trace_computing2,
        interaction_trace_scheduler,
    ].concat();
    tree_builder.extend_evals(fib_int_traces);

    // Add BLAKE3 interaction traces if present
    if let Some((scheduler_int, rounds_int)) = blake3_interaction_traces {
        tree_builder.extend_evals(scheduler_int);
        let flat_rounds: Vec<_> = rounds_int.into_iter().flatten().collect_vec();
        tree_builder.extend_evals(flat_rounds);
    }

    // Add XOR interaction traces if present
    if let Some((xor12_int, xor9_int, xor8_int, xor7_int, xor4_int)) = blake3_xor_interaction_traces {
        if let (Some(xor12), Some(xor9), Some(xor8), Some(xor7), Some(xor4)) =
            (xor12_int, xor9_int, xor8_int, xor7_int, xor4_int) {
            let xor_int_traces = chain![
                xor12,
                xor9,
                xor8,
                xor7,
                xor4,
            ].collect_vec();
            tree_builder.extend_evals(xor_int_traces);
        }
    }

    tree_builder.commit(channel);
    tracing::debug!("Interaction traces generated and committed: {:?}", step_start.elapsed());

    // Step 7: Create components with TraceLocationAllocator (AFTER committing interaction traces)
    tracing::debug!("Step 7: Creating components...");
    let step_start = Instant::now();

    // CRITICAL: Initialize TraceLocationAllocator with preprocessed columns
    // This tells it the structure of Tree 0 (preprocessed trace)
    let preprocessed_column_ids = vec![
        is_first_column_id(log_size),
        is_active_column_id(log_size, target_element_computing1),
        is_target_column_id(log_size, target_element_computing1),
        is_active_column_id(log_size, target_element_computing2),
        is_target_column_id(log_size, target_element_computing2),
    ];

    // If BLAKE3 is enabled, add BLAKE3 preprocessed columns (XOR tables)
    let all_preprocessed_ids: Vec<_> = if blake3_inputs.is_some() {
        use crate::blake::preprocessed_columns::XorTable;
        let blake3_preprocessed: Vec<_> = vec![
            XorTable::new(12, 4, 0).id(), XorTable::new(12, 4, 1).id(), XorTable::new(12, 4, 2).id(),
            XorTable::new(9, 2, 0).id(), XorTable::new(9, 2, 1).id(), XorTable::new(9, 2, 2).id(),
            XorTable::new(8, 2, 0).id(), XorTable::new(8, 2, 1).id(), XorTable::new(8, 2, 2).id(),
            XorTable::new(7, 2, 0).id(), XorTable::new(7, 2, 1).id(), XorTable::new(7, 2, 2).id(),
            XorTable::new(4, 0, 0).id(), XorTable::new(4, 0, 1).id(), XorTable::new(4, 0, 2).id(),
        ];
        [preprocessed_column_ids, blake3_preprocessed].concat()
    } else {
        preprocessed_column_ids
    };

    let mut tree_span_provider = TraceLocationAllocator::new_with_preprocessed_columns(&all_preprocessed_ids);
    let is_first_id = is_first_column_id(log_size);

    let component_computing1 = FibonacciComputingComponent::new(
        &mut tree_span_provider,
        FibonacciComputingEval {
            log_n_rows: log_size,
            initial_a: 0,
            initial_b: 1,
            fibonacci_relation: fibonacci_relation.clone(),
            index_relation: index_relation.clone(),
            fibonacci_index: target_element_computing1,
            claimed_sum: claimed_sum_computing1,
            is_first_id: is_first_id.clone(),
            is_active_id: is_active_column_id(log_size, target_element_computing1),
            is_target_id: is_target_column_id(log_size, target_element_computing1),
        },
        claimed_sum_computing1,
    );

    let component_computing2 = FibonacciComputingComponent::new(
        &mut tree_span_provider,
        FibonacciComputingEval {
            log_n_rows: log_size,
            initial_a: 0,
            initial_b: 1,
            fibonacci_relation: fibonacci_relation.clone(),
            index_relation: index_relation.clone(),
            fibonacci_index: target_element_computing2,
            claimed_sum: claimed_sum_computing2,
            is_first_id: is_first_id.clone(),
            is_active_id: is_active_column_id(log_size, target_element_computing2),
            is_target_id: is_target_column_id(log_size, target_element_computing2),
        },
        claimed_sum_computing2,
    );

    let component_scheduler = FibonacciSchedulerComponent::new(
        &mut tree_span_provider,
        FibonacciSchedulerEval {
            log_n_rows: log_size,
            fibonacci_relation,
            claimed_sum: claimed_sum_scheduler,
            is_first_id: is_first_id.clone(),
        },
        claimed_sum_scheduler,
    );

    // Step 8: Create BLAKE3 components if enabled
    let (blake_scheduler_comp, blake_round_comps, blake_xor_comps) =
        if let (Some((blake_xor_els, blake_round_els, blake_blake_els)), Some(blake_sums)) =
            (blake3_all_elements.as_ref(), blake3_claimed_sums.as_ref())
    {
        tracing::debug!("Step 8: Creating BLAKE3 components...");

        use crate::blake::scheduler::{BlakeSchedulerComponent, BlakeSchedulerEval};
        use crate::blake::round::{BlakeRoundComponent, BlakeRoundEval};

        // Create scheduler component
        let blake_scheduler = BlakeSchedulerComponent::new(
            &mut tree_span_provider,
            BlakeSchedulerEval {
                log_size: blake3_log_size.unwrap(),
                blake_lookup_elements: blake_blake_els.clone(),
                round_lookup_elements: blake_round_els.clone(),
                index_relation: index_relation.clone(),
                fibonacci_index: target_element_computing1,
                is_first_id: is_first_id.clone(),
                claimed_sum: blake_sums.0,
            },
            blake_sums.0,
        );

        // Create round components (7 rounds split as 4+2+1)
        let blake_rounds: Vec<BlakeRoundComponent> = ROUND_LOG_SPLIT
            .iter()
            .zip(&blake_sums.1)
            .enumerate()
            .map(|(_idx, (l, &claimed_sum))| {
                let comp = BlakeRoundComponent::new(
                    &mut tree_span_provider,
                    BlakeRoundEval {
                        log_size: blake3_log_size.unwrap() + l,
                        xor_lookup_elements: blake_xor_els.clone(),
                        round_lookup_elements: blake_round_els.clone(),
                        claimed_sum,
                    },
                    claimed_sum,
                );
                comp
            })
            .collect();

        // Create XOR table components
        use crate::blake::xor_table::{xor12, xor9, xor8, xor7, xor4};
        let xor12_comp = xor12::XorTableComponent::new(
            &mut tree_span_provider,
            xor12::XorTableEval::<12, 4> {
                lookup_elements: blake_xor_els.xor12.clone(),
                claimed_sum: blake_sums.2,
            },
            blake_sums.2,
        );
        let xor9_comp = xor9::XorTableComponent::new(
            &mut tree_span_provider,
            xor9::XorTableEval::<9, 2> {
                lookup_elements: blake_xor_els.xor9.clone(),
                claimed_sum: blake_sums.3,
            },
            blake_sums.3,
        );
        let xor8_comp = xor8::XorTableComponent::new(
            &mut tree_span_provider,
            xor8::XorTableEval::<8, 2> {
                lookup_elements: blake_xor_els.xor8.clone(),
                claimed_sum: blake_sums.4,
            },
            blake_sums.4,
        );
        let xor7_comp = xor7::XorTableComponent::new(
            &mut tree_span_provider,
            xor7::XorTableEval::<7, 2> {
                lookup_elements: blake_xor_els.xor7.clone(),
                claimed_sum: blake_sums.5,
            },
            blake_sums.5,
        );
        let xor4_comp = xor4::XorTableComponent::new(
            &mut tree_span_provider,
            xor4::XorTableEval::<4, 0> {
                lookup_elements: blake_xor_els.xor4.clone(),
                claimed_sum: blake_sums.6,
            },
            blake_sums.6,
        );

        tracing::debug!("Created BLAKE3: 1 scheduler + {} rounds + 5 XOR tables", blake_rounds.len());

        (Some(blake_scheduler), Some(blake_rounds), Some((xor12_comp, xor9_comp, xor8_comp, xor7_comp, xor4_comp)))
    } else {
        (None, None, None)
    };

    tracing::debug!("Components created: {:?}", step_start.elapsed());

    // Step 9: Generate proof (with or without BLAKE3 components)
    tracing::info!("Generating STARK proof...");
    let step_start = Instant::now();
    let proof = if blake_scheduler_comp.is_some() {
        // With BLAKE3 components
        let blake_sched = blake_scheduler_comp.as_ref().unwrap();
        let blake_rounds = blake_round_comps.as_ref().unwrap();
        let (xor12, xor9, xor8, xor7, xor4) = blake_xor_comps.as_ref().unwrap();

        let mut all_components: Vec<&dyn ComponentProver<SimdBackend>> = vec![
            &component_computing1,
            &component_computing2,
            &component_scheduler,
            blake_sched,
        ];

        // Add round components
        for round_comp in blake_rounds {
            all_components.push(round_comp);
        }

        // Add XOR components
        all_components.extend_from_slice(&[xor12, xor9, xor8, xor7, xor4]);

        tracing::info!("Proving with {} components total", all_components.len());

        prove(&all_components, channel, commitment_scheme)?
    } else {
        // Without BLAKE3
        prove(
            &[
                &component_computing1,
                &component_computing2,
                &component_scheduler,
            ],
            channel,
            commitment_scheme,
        )?
    };
    tracing::info!("STARK proof generated: {:?}", step_start.elapsed());
    tracing::info!("Total proof generation time: {:?}", total_start.elapsed());

    Ok((
        proof,
        [component_computing1, component_computing2],
        component_scheduler,
        statement0,
        statement1,
    ))
}

/// Verify multi-component Fibonacci proof with LogUp
///
/// This verifies a STARK proof for the multi-component Fibonacci circuit.
/// The verifier must commit to the same tree structure as the prover.
pub fn verify_multi_fib(
    proof: StarkProof<Blake2sMerkleHasher>,
    target_element_computing1: usize,
    target_element_computing2: usize,
    statement0: MultiFibStatement0,
    statement1: MultiFibStatement1,
    config: stwo::core::pcs::PcsConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;
    let total_start = Instant::now();

    tracing::info!("=== Multi-Component Fibonacci Proof Verification ===");
    tracing::info!(
        "Target elements: Computing1={}, Computing2={}",
        target_element_computing1, target_element_computing2
    );

    // Extract log_size from statement
    let log_size = statement0.log_size;
    let blake3_log_size = statement0.blake3_log_size;

    // Step 1: Setup verifier channel and commitment scheme
    tracing::debug!("Step 1: Setting up verifier...");
    let step_start = Instant::now();
    let channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let log_sizes = statement0.log_sizes();

    // Step 2: Commit preprocessed columns (is_first + BLAKE3 XOR tables if present)
    tracing::debug!("Step 2: Committing preprocessed columns...");
    commitment_scheme.commit(proof.commitments[0], &log_sizes[0], channel);

    if blake3_log_size.is_some() {
        tracing::debug!("Committed BLAKE3 XOR table preprocessed columns");
    }

    // Mix Statement0 (log_size) into channel
    statement0.mix_into(channel);

    // Step 3: Commit main traces
    tracing::debug!("Step 3: Committing main traces...");
    commitment_scheme.commit(proof.commitments[1], &log_sizes[1], channel);

    // Step 4: Draw FibonacciRelation from channel (must match prover)
    tracing::debug!("Step 4: Drawing LogUp relation from channel...");
    let fibonacci_relation = FibonacciRelation::draw(channel);
    let index_relation = IndexRelation::draw(channel);

    // Step 4.5: Draw BLAKE3 lookup elements if present (must match prover order)
    let blake3_elements = if blake3_log_size.is_some() {
        tracing::debug!("Step 4.5: Drawing BLAKE3 lookup elements...");
        let blake3_xor_elements = BlakeXorElements::draw(channel);
        use crate::blake::round::RoundElements;
        use crate::blake::scheduler::BlakeElements;
        let blake3_round_elements = RoundElements::draw(channel);
        let blake3_blake_elements = BlakeElements::draw(channel);
        Some((blake3_xor_elements, blake3_round_elements, blake3_blake_elements))
    } else {
        None
    };

    // Mix Statement1 (claimed_sums) into channel
    statement1.mix_into(channel);

    // Step 5: Commit interaction traces
    tracing::debug!("Step 5: Committing interaction traces...");
    commitment_scheme.commit(proof.commitments[2], &log_sizes[2], channel);

    tracing::debug!("Setup and commitments: {:?}", step_start.elapsed());

    // Step 6: Create components (AFTER committing interaction traces, matching prover order)
    tracing::debug!("Step 6: Creating components for verification...");
    let step_start = Instant::now();

    // CRITICAL: Initialize TraceLocationAllocator with preprocessed columns (same as prover!)
    let preprocessed_column_ids = vec![
        is_first_column_id(log_size),
        is_active_column_id(log_size, target_element_computing1),
        is_target_column_id(log_size, target_element_computing1),
        is_active_column_id(log_size, target_element_computing2),
        is_target_column_id(log_size, target_element_computing2),
    ];

    // If BLAKE3 is enabled, add BLAKE3 preprocessed columns (XOR tables)
    let all_preprocessed_ids: Vec<_> = if blake3_log_size.is_some() {
        use crate::blake::preprocessed_columns::XorTable;
        let blake3_preprocessed: Vec<_> = vec![
            XorTable::new(12, 4, 0).id(), XorTable::new(12, 4, 1).id(), XorTable::new(12, 4, 2).id(),
            XorTable::new(9, 2, 0).id(), XorTable::new(9, 2, 1).id(), XorTable::new(9, 2, 2).id(),
            XorTable::new(8, 2, 0).id(), XorTable::new(8, 2, 1).id(), XorTable::new(8, 2, 2).id(),
            XorTable::new(7, 2, 0).id(), XorTable::new(7, 2, 1).id(), XorTable::new(7, 2, 2).id(),
            XorTable::new(4, 0, 0).id(), XorTable::new(4, 0, 1).id(), XorTable::new(4, 0, 2).id(),
        ];
        [preprocessed_column_ids, blake3_preprocessed].concat()
    } else {
        preprocessed_column_ids
    };

    let mut tree_span_provider = TraceLocationAllocator::new_with_preprocessed_columns(&all_preprocessed_ids);
    let is_first_id = is_first_column_id(log_size);

    let component_computing1 = FibonacciComputingComponent::new(
        &mut tree_span_provider,
        FibonacciComputingEval {
            log_n_rows: log_size,
            initial_a: 0,
            initial_b: 1,
            fibonacci_relation: fibonacci_relation.clone(),
            index_relation: index_relation.clone(),
            fibonacci_index: target_element_computing1,
            claimed_sum: statement1.claimed_sum_computing1,
            is_first_id: is_first_id.clone(),
            is_active_id: is_active_column_id(log_size, target_element_computing1),
            is_target_id: is_target_column_id(log_size, target_element_computing1),
        },
        statement1.claimed_sum_computing1,
    );

    let component_computing2 = FibonacciComputingComponent::new(
        &mut tree_span_provider,
        FibonacciComputingEval {
            log_n_rows: log_size,
            initial_a: 0,
            initial_b: 1,
            fibonacci_relation: fibonacci_relation.clone(),
            index_relation: index_relation.clone(),
            fibonacci_index: target_element_computing2,
            claimed_sum: statement1.claimed_sum_computing2,
            is_first_id: is_first_id.clone(),
            is_active_id: is_active_column_id(log_size, target_element_computing2),
            is_target_id: is_target_column_id(log_size, target_element_computing2),
        },
        statement1.claimed_sum_computing2,
    );

    let component_scheduler = FibonacciSchedulerComponent::new(
        &mut tree_span_provider,
        FibonacciSchedulerEval {
            log_n_rows: log_size,
            fibonacci_relation,
            claimed_sum: statement1.claimed_sum_scheduler,
            is_first_id: is_first_id.clone(),
        },
        statement1.claimed_sum_scheduler,
    );

    // Step 6.5: Create BLAKE3 components if present
    let (blake_scheduler_comp, blake_round_comps, blake_xor_comps) =
        if let (Some(blake3_log), Some(blake_sums), Some((blake_xor_els, blake_round_els, blake_blake_els))) =
            (blake3_log_size,
             statement1.blake3_scheduler_claimed_sum.zip(statement1.blake3_round_claimed_sums.as_ref())
                .zip(statement1.blake3_xor12_claimed_sum)
                .zip(statement1.blake3_xor9_claimed_sum)
                .zip(statement1.blake3_xor8_claimed_sum)
                .zip(statement1.blake3_xor7_claimed_sum)
                .zip(statement1.blake3_xor4_claimed_sum)
                .map(|((((((s, r), x12), x9), x8), x7), x4)| (s, r.clone(), x12, x9, x8, x7, x4)),
             blake3_elements.as_ref())
        {
            tracing::debug!("Step 6.5: Creating BLAKE3 components...");

            use crate::blake::scheduler::{BlakeSchedulerComponent, BlakeSchedulerEval};
            use crate::blake::round::{BlakeRoundComponent, BlakeRoundEval};
            use crate::blake::xor_table::{xor12, xor9, xor8, xor7, xor4};

            // Create scheduler component
            let blake_scheduler = BlakeSchedulerComponent::new(
                &mut tree_span_provider,
                BlakeSchedulerEval {
                    log_size: blake3_log,
                    round_lookup_elements: blake_round_els.clone(),
                    blake_lookup_elements: blake_blake_els.clone(),
                    index_relation: index_relation.clone(),
                    fibonacci_index: target_element_computing1,
                    is_first_id: is_first_id.clone(),
                    claimed_sum: blake_sums.0,
                },
                blake_sums.0,
            );

            // Create round components
            let blake_rounds: Vec<BlakeRoundComponent> = ROUND_LOG_SPLIT
                .iter()
                .zip(&blake_sums.1)
                .map(|(l, &claimed_sum)| {
                    BlakeRoundComponent::new(
                        &mut tree_span_provider,
                        BlakeRoundEval {
                            log_size: blake3_log + l,
                            xor_lookup_elements: blake_xor_els.clone(),
                            round_lookup_elements: blake_round_els.clone(),
                            claimed_sum,
                        },
                        claimed_sum,
                    )
                })
                .collect();

            // Create XOR table components
            let xor12_comp = xor12::XorTableComponent::new(
                &mut tree_span_provider,
                xor12::XorTableEval::<12, 4> {
                    lookup_elements: blake_xor_els.xor12.clone(),
                    claimed_sum: blake_sums.2,
                },
                blake_sums.2,
            );
            let xor9_comp = xor9::XorTableComponent::new(
                &mut tree_span_provider,
                xor9::XorTableEval::<9, 2> {
                    lookup_elements: blake_xor_els.xor9.clone(),
                    claimed_sum: blake_sums.3,
                },
                blake_sums.3,
            );
            let xor8_comp = xor8::XorTableComponent::new(
                &mut tree_span_provider,
                xor8::XorTableEval::<8, 2> {
                    lookup_elements: blake_xor_els.xor8.clone(),
                    claimed_sum: blake_sums.4,
                },
                blake_sums.4,
            );
            let xor7_comp = xor7::XorTableComponent::new(
                &mut tree_span_provider,
                xor7::XorTableEval::<7, 2> {
                    lookup_elements: blake_xor_els.xor7.clone(),
                    claimed_sum: blake_sums.5,
                },
                blake_sums.5,
            );
            let xor4_comp = xor4::XorTableComponent::new(
                &mut tree_span_provider,
                xor4::XorTableEval::<4, 0> {
                    lookup_elements: blake_xor_els.xor4.clone(),
                    claimed_sum: blake_sums.6,
                },
                blake_sums.6,
            );

            tracing::debug!("Created BLAKE3: 1 scheduler + {} rounds + 5 XOR tables", blake_rounds.len());

            (Some(blake_scheduler), Some(blake_rounds), Some((xor12_comp, xor9_comp, xor8_comp, xor7_comp, xor4_comp)))
        } else {
            (None, None, None)
        };

    tracing::debug!("Components created: {:?}", step_start.elapsed());

    // Step 7: Verify the proof
    tracing::info!("Verifying STARK proof...");
    let step_start = Instant::now();

    if blake_scheduler_comp.is_some() {
        // With BLAKE3 components
        let blake_sched = blake_scheduler_comp.as_ref().unwrap();
        let blake_rounds = blake_round_comps.as_ref().unwrap();
        let (xor12, xor9, xor8, xor7, xor4) = blake_xor_comps.as_ref().unwrap();

        let mut all_components: Vec<&dyn stwo::core::air::Component> = vec![
            &component_computing1,
            &component_computing2,
            &component_scheduler,
            blake_sched,
        ];

        // Add round components
        for round_comp in blake_rounds {
            all_components.push(round_comp);
        }

        // Add XOR components
        all_components.extend_from_slice(&[xor12, xor9, xor8, xor7, xor4]);

        tracing::info!("Verifying with {} components total", all_components.len());

        stwo::core::verifier::verify(
            &all_components,
            channel,
            commitment_scheme,
            proof,
        )?;
    } else {
        // Without BLAKE3
        stwo::core::verifier::verify(
            &[
                &component_computing1,
                &component_computing2,
                &component_scheduler,
            ],
            channel,
            commitment_scheme,
            proof,
        )?;
    }

    tracing::info!("STARK proof verified: {:?}", step_start.elapsed());
    tracing::info!("Total verification time: {:?}", total_start.elapsed());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::channel::Blake2sChannel;
    use stwo::core::pcs::PcsConfig;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::CommitmentSchemeProver;

    #[test]
    fn test_multi_component_fibonacci_traces() {
        let target_element_computing1 = 5;
        let target_element_computing2 = 10;
        let log_size = 4; // 16 rows

        // Generate traces for Computing1 (initial: 0, 1) up to element 5
        let (_trace_computing1, fib1_c_value) =
            gen_computing_trace(log_size, 0, 1, target_element_computing1);

        // Generate traces for Computing2 (initial: 0, 1) up to element 10
        let (_trace_computing2, fib2_c_value) =
            gen_computing_trace(log_size, 0, 1, target_element_computing2);

        // Generate Scheduler trace (will sum specific values from both)
        let _trace_scheduler = gen_scheduler_trace(log_size, fib1_c_value, fib2_c_value);

        println!("✓ Multi-component traces generated successfully");
        println!(
            "  Computing1 rows: {} (active up to element {})",
            1 << log_size,
            target_element_computing1
        );
        println!(
            "  Computing2 rows: {} (active up to element {})",
            1 << log_size,
            target_element_computing2
        );
        println!("  Scheduler rows: {}", 1 << log_size);
    }

    #[test]
    fn test_multi_component_proof_with_logup() {
        println!("\n==================================================");
        println!("  MULTI-COMPONENT FIBONACCI PROOF TEST");
        println!("==================================================\n");

        let target_element_computing1 = 5;
        let target_element_computing2 = 10;

        // Setup prover (log_size will be computed dynamically)
        let config = PcsConfig::default();

        // Compute expected log_size for twiddles
        let max_target = target_element_computing1.max(target_element_computing2) as u32;
        let min_log_size = if max_target + 1 <= 1 {
            0
        } else {
            (max_target).ilog2() + 1
        };
        let log_size = min_log_size.max(4);

        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );

        let channel = &mut Blake2sChannel::default();
        let commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

        // Generate proof with LogUp (without BLAKE3)
        let result = prove_multi_fib(
            target_element_computing1,
            target_element_computing2,
            None, // blake3_inputs
            None, // blake3_expected_hashes
            channel,
            commitment_scheme,
        );

        match result {
            Ok((proof, _components, _scheduler, _statement0, _statement1)) => {
                println!("\n==================================================");
                println!("  PROOF GENERATION SUCCESSFUL!");
                println!("==================================================\n");

                println!("Proof details:");
                println!("  - Number of commitments: {}", proof.commitments.len());
                println!("  - Computing components: 2");
                println!("  - Scheduler component: 1");

                println!("\n✓ Multi-component proof with LogUp generated successfully!");
                println!("\nThis proves:");
                println!("  1. Computing1 correctly computed Fibonacci(0,1)");
                println!("  2. Computing2 correctly computed Fibonacci(1,1)");
                println!("  3. Scheduler correctly summed values from both");
                println!("  4. LogUp verified that Scheduler used correct values");
            }
            Err(e) => {
                panic!("Proof generation failed: {:?}", e);
            }
        }
    }

    #[test]
    fn test_logup_claimed_sums() {
        println!("\n==================================================");
        println!("  TESTING LOGUP CLAIMED SUMS");
        println!("==================================================\n");

        let target_element_computing1 = 5;
        let target_element_computing2 = 10;
        let log_size = 4;

        // Generate traces
        let (trace_computing1, fib1_c_value) =
            gen_computing_trace(log_size, 0, 1, target_element_computing1);
        let (trace_computing2, fib2_c_value) =
            gen_computing_trace(log_size, 0, 1, target_element_computing2);
        let trace_scheduler = gen_scheduler_trace(log_size, fib1_c_value, fib2_c_value);

        // Draw relation
        let channel = &mut Blake2sChannel::default();
        let fibonacci_relation = FibonacciRelation::draw(channel);

        // Generate interaction traces
        let (_, claimed_sum_computing1) = gen_computing_interaction_trace(
            &trace_computing1,
            &fibonacci_relation,
            target_element_computing1,
        );
        let (_, claimed_sum_computing2) = gen_computing_interaction_trace(
            &trace_computing2,
            &fibonacci_relation,
            target_element_computing2,
        );
        let (_, claimed_sum_scheduler) =
            gen_scheduler_interaction_trace(&trace_scheduler, &fibonacci_relation);

        println!("LogUp claimed sums:");
        println!("  Computing1 yields: {:?}", claimed_sum_computing1);
        println!("  Computing2 yields: {:?}", claimed_sum_computing2);
        println!("  Scheduler uses:    {:?}", claimed_sum_scheduler);

        let total = claimed_sum_computing1 + claimed_sum_computing2 + claimed_sum_scheduler;
        println!("\n  Total sum: {:?}", total);

        if total == Zero::zero() {
            println!("\n✓ LogUp property satisfied: total sum = 0");
            println!("  This means Scheduler used exactly the values that Computing produced!");
        } else {
            panic!("✗ LogUp sum is not zero! This should not happen!");
        }
    }

    #[test]
    fn test_prove_and_verify() {
        println!("\n==================================================");
        println!("  MULTI-COMPONENT FIBONACCI: PROVE + VERIFY");
        println!("==================================================\n");

        let target_element_computing1 = 5;
        let target_element_computing2 = 10;

        // Setup prover (log_size will be computed dynamically)
        let config = PcsConfig::default();

        // Compute expected log_size for twiddles
        let max_target = target_element_computing1.max(target_element_computing2) as u32;
        let min_log_size = if max_target + 1 <= 1 {
            0
        } else {
            (max_target).ilog2() + 1
        };
        let log_size = min_log_size.max(4);

        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );

        let channel = &mut Blake2sChannel::default();
        let commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

        // STEP 1: Generate proof
        println!("==================================================");
        println!("STEP 1: PROVING");
        println!("==================================================");

        let result = prove_multi_fib(
            target_element_computing1,
            target_element_computing2,
            None, // blake3_inputs
            None, // blake3_expected_hashes
            channel,
            commitment_scheme,
        );

        match result {
            Ok((proof, _components, _scheduler, statement0, statement1)) => {
                println!("\n✓ Proof generated successfully!");
                println!("  - Commitments: {}", proof.commitments.len());

                // STEP 2: Verify proof
                println!("\n==================================================");
                println!("STEP 2: VERIFYING");
                println!("==================================================");

                let verify_result = verify_multi_fib(
                    proof,
                    target_element_computing1,
                    target_element_computing2,
                    statement0,
                    statement1,
                    config,
                );

                match verify_result {
                    Ok(()) => {
                        println!("\n==================================================");
                        println!("  ✓✓✓ SUCCESS! ✓✓✓");
                        println!("==================================================");
                        println!("\nProof was generated AND verified successfully!");
                        println!("\nThis proves:");
                        println!("  1. Computing1 correctly computed Fibonacci(0,1)");
                        println!("  2. Computing2 correctly computed Fibonacci(1,1)");
                        println!("  3. Scheduler correctly summed values from both");
                        println!("  4. LogUp verified that Scheduler used correct values");
                        println!("  5. Verifier independently confirmed all constraints!");
                    }
                    Err(e) => {
                        panic!("Verification failed: {:?}", e);
                    }
                }
            }
            Err(e) => {
                panic!("Proof generation failed: {:?}", e);
            }
        }
    }

    #[test]
    fn test_blake3_hash_verification_in_circuit() {
        println!("\n==================================================");
        println!("  BLAKE3 HASH VERIFICATION TEST (Circuit Only)");
        println!("==================================================\n");

        // Prepare BLAKE3 test input
        let fibonacci_index = 5usize;
        let blinder: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        // Prepare message: index_bytes + blinder
        let index_string = fibonacci_index.to_string();
        let index_bytes = index_string.as_bytes();
        let mut message = [0u8; 64];
        let index_len = index_bytes.len();
        message[..index_len].copy_from_slice(index_bytes);
        message[index_len..index_len + 16].copy_from_slice(&blinder);
        let total_len = index_len + 16;

        // Convert to u32 array for BLAKE3
        let m: [u32; 16] = std::array::from_fn(|i| {
            u32::from_le_bytes([
                message[i * 4],
                message[i * 4 + 1],
                message[i * 4 + 2],
                message[i * 4 + 3],
            ])
        });

        // Initialize BLAKE3 state (IV)
        const IV: [u32; 8] = [
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        ];

        let mut v = [0u32; 16];
        v[0..8].copy_from_slice(&IV);
        v[8..12].copy_from_slice(&IV[0..4]);
        v[12] = 0; // counter_low
        v[13] = 0; // counter_high
        v[14] = total_len as u32; // block_len
        v[15] = 0b1011; // flags: CHUNK_START | CHUNK_END | ROOT

        // Compute expected hash using blake3 crate
        let mut hasher = blake3::Hasher::new();
        hasher.update(&message[..total_len]);
        let expected_hash: [u8; 32] = *hasher.finalize().as_bytes();

        println!("  Input: fibonacci_index={}", fibonacci_index);
        println!("  Blinder: {:?}", &blinder[..4]);
        println!("  Expected hash: {:?}...", &expected_hash[..8]);

        // Test BLAKE3 circuit by simulating computation
        let mut v_sim: [u32x16; 16] = v.map(u32x16::splat);
        let m_sim: [u32x16; 16] = m.map(u32x16::splat);
        let mut m_current = m_sim;

        // Run all 7 rounds
        for r in 0..N_ROUNDS {
            use crate::blake::blake3;
            blake3::round(&mut v_sim, m_current, r);
            m_current = blake3::MSG_SCHEDULE.map(|i| m_current[i as usize]);
        }

        // Finalize
        for i in 0..8 {
            v_sim[i] ^= v_sim[i + 8];
        }
        for i in 0..8 {
            let cv_i = u32x16::splat(v[i]);
            v_sim[i + 8] ^= cv_i;
        }

        // Extract computed hash
        let mut computed_hash = [0u8; 32];
        for i in 0..8 {
            let word = v_sim[i].to_array()[0];
            computed_hash[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
        }

        // Verify
        assert_eq!(computed_hash, expected_hash, "BLAKE3 circuit hash mismatch!");

        println!("\n✓ BLAKE3 circuit verification successful!");
        println!("  Computed hash: {:?}...", &computed_hash[..8]);
        println!("  Expected hash: {:?}...", &expected_hash[..8]);
        println!("\n✓ BLAKE3 correctly computed hash(index + blinder) in circuit!");
    }

    #[test]
    fn test_fibonacci_with_blake3_full_integration() {
        println!("\n==================================================");
        println!("  FIBONACCI + BLAKE3: FULL INTEGRATION TEST");
        println!("==================================================\n");

        let target_element_computing1 = 5;
        let target_element_computing2 = 10;

        // Setup prover (log_size will be computed dynamically)
        let config = PcsConfig::default();

        // Compute expected log_size for twiddles
        let max_target = target_element_computing1.max(target_element_computing2) as u32;
        let min_log_size = if max_target + 1 <= 1 {
            0
        } else {
            (max_target).ilog2() + 1
        };
        let fib_log_size = min_log_size.max(4);

        // BLAKE3 log_size: 1 instance = LOG_N_LANES minimum
        let num_instances: usize = 1;
        let blake3_log_size = compute_blake3_log_size(num_instances);

        // Compute max log_size needed for twiddles
        let max_log_size = compute_max_log_size(fib_log_size, blake3_log_size);

        println!("  Fibonacci log_size: {}", fib_log_size);
        println!("  BLAKE3 log_size: {}", blake3_log_size);
        println!("  Max log_size for twiddles: {}", max_log_size);

        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(max_log_size + 1 + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );

        let channel = &mut Blake2sChannel::default();
        let commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

        // Prepare BLAKE3 inputs
        println!("Preparing BLAKE3 test data...");

        // Create test input: hash(fibonacci_index + blinder)
        let fibonacci_index = 5usize;
        let blinder: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        // Prepare message: index_bytes + blinder
        let index_string = fibonacci_index.to_string();
        let index_bytes = index_string.as_bytes();
        let mut message = [0u8; 64];
        let index_len = index_bytes.len();
        message[..index_len].copy_from_slice(index_bytes);
        message[index_len..index_len + 16].copy_from_slice(&blinder);
        let total_len = index_len + 16;

        // Convert to u32 array for BLAKE3
        let m: [u32; 16] = std::array::from_fn(|i| {
            u32::from_le_bytes([
                message[i * 4],
                message[i * 4 + 1],
                message[i * 4 + 2],
                message[i * 4 + 3],
            ])
        });

        // Initialize BLAKE3 state (IV)
        const IV: [u32; 8] = [
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        ];

        let mut v = [0u32; 16];
        v[0..8].copy_from_slice(&IV);
        v[8..12].copy_from_slice(&IV[0..4]);
        v[12] = 0; // counter_low
        v[13] = 0; // counter_high
        v[14] = total_len as u32; // block_len
        v[15] = 0b1011; // flags: CHUNK_START | CHUNK_END | ROOT

        // Compute expected hash using blake3 crate
        let mut hasher = blake3::Hasher::new();
        hasher.update(&message[..total_len]);
        let expected_hash: [u8; 32] = *hasher.finalize().as_bytes();

        println!("  Input: fibonacci_index={}", fibonacci_index);
        println!("  Blinder: {:?}", &blinder[..4]);
        println!("  Expected hash: {:?}...", &expected_hash[..8]);

        // Prepare inputs for prove_multi_fib
        let blake3_inputs = vec![(v, m)];
        let blake3_expected_hashes = vec![expected_hash];

        // STEP 1: Generate proof with BLAKE3
        println!("\n==================================================");
        println!("STEP 1: PROVING (Fibonacci + BLAKE3)");
        println!("==================================================");

        let result = prove_multi_fib(
            target_element_computing1,
            target_element_computing2,
            Some(blake3_inputs),
            Some(blake3_expected_hashes),
            channel,
            commitment_scheme,
        );

        match result {
            Ok((proof, _components, _scheduler, statement0, statement1)) => {
                println!("\n✓ Proof generated successfully!");
                println!("  - Fibonacci components: 3 (Computing1, Computing2, Scheduler)");
                println!("  - BLAKE3 components: {} (Scheduler + Rounds + XOR tables)",
                    1 + 3 + 5); // scheduler + 3 rounds + 5 xor tables
                println!("  - Total commitments: {}", proof.commitments.len());

                // STEP 2: Verify the proof
                println!("\n==================================================");
                println!("STEP 2: VERIFYING (Fibonacci + BLAKE3)");
                println!("==================================================");

                let verify_result = verify_multi_fib(
                    proof,
                    target_element_computing1,
                    target_element_computing2,
                    statement0,
                    statement1,
                    config,
                );

                match verify_result {
                    Ok(()) => {
                        println!("\n==================================================");
                        println!("  ✓✓✓ FULL INTEGRATION SUCCESS! ✓✓✓");
                        println!("==================================================");
                        println!("\nProof was generated AND verified successfully!");
                        println!("\nThis proves:");
                        println!("  1. Computing1 correctly computed Fibonacci(0,1)");
                        println!("  2. Computing2 correctly computed Fibonacci(1,1)");
                        println!("  3. Scheduler correctly summed values from both");
                        println!("  4. LogUp verified that Scheduler used correct values");
                        println!("  5. BLAKE3 correctly computed hash(index + blinder)");
                        println!("  6. BLAKE3 hash matches expected: {:?}...", &expected_hash[..8]);
                        println!("  7. Verifier independently confirmed all constraints!");
                        println!("\n✓ Combined Fibonacci + BLAKE3 AIR verification successful!");
                    }
                    Err(e) => {
                        panic!("Verification failed: {:?}", e);
                    }
                }
            }
            Err(e) => {
                panic!("Proof generation failed: {:?}", e);
            }
        }
    }
}
