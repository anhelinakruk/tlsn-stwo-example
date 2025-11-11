use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;

pub fn gen_fib_trace(
    log_size: u32,
    fibonacci_index: usize,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    u32,
) {
    let n_rows = 1 << log_size;

    let mut col_a = Col::<SimdBackend, BaseField>::zeros(n_rows);
    let mut col_b = Col::<SimdBackend, BaseField>::zeros(n_rows);
    let mut col_c = Col::<SimdBackend, BaseField>::zeros(n_rows);
    let mut col_is_target = Col::<SimdBackend, BaseField>::zeros(n_rows);

    let mut a = BaseField::zero();
    let mut b = BaseField::from_u32_unchecked(1);

    let mut target_value = 0u32;

    for row in 0..n_rows {
        let c = a + b;

        col_a.set(row, a);
        col_b.set(row, b);
        col_c.set(row, c);

        if row == fibonacci_index {
            col_is_target.set(row, BaseField::one());
            target_value = a.0;
        }

        a = b;
        b = c;
    }

    bit_reverse_coset_to_circle_domain_order(col_a.as_mut_slice());
    bit_reverse_coset_to_circle_domain_order(col_b.as_mut_slice());
    bit_reverse_coset_to_circle_domain_order(col_c.as_mut_slice());
    bit_reverse_coset_to_circle_domain_order(col_is_target.as_mut_slice());

    let domain = CanonicCoset::new(log_size).circle_domain();

    (
        vec![
            CircleEvaluation::new(domain, col_a),
            CircleEvaluation::new(domain, col_b),
            CircleEvaluation::new(domain, col_c),
            CircleEvaluation::new(domain, col_is_target),
        ],
        target_value,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fibonacci_trace_generation() {
        let log_size = 4; // 16 rows
        let fibonacci_index = 7;

        let (trace, value) = gen_fib_trace(log_size, fibonacci_index);

        println!("Generated trace with {} columns", trace.len());
        println!("fibonacci({}) = {}", fibonacci_index, value);

        // Verify we have 4 columns (a, b, c, is_target)
        assert_eq!(trace.len(), 4);

        // Verify fibonacci(7) = 13
        assert_eq!(value, 13);
    }

    #[test]
    fn test_fibonacci_values() {
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

        for (index, expected) in test_cases {
            let log_size = 4;
            let (_, value) = gen_fib_trace(log_size, index);
            assert_eq!(
                value, expected,
                "fibonacci({}) should be {}, got {}",
                index, expected, value
            );
        }
    }
}
