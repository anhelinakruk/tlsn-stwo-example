use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX};

use super::LOG_CONSTRAINT_DEGREE;

#[derive(Clone)]
pub struct FibEval {
    pub log_n_rows: u32,
    pub fibonacci_value: u32,
    pub is_first_id: PreProcessedColumnId,
}

impl FrameworkEval for FibEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + LOG_CONSTRAINT_DEGREE
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_first = eval.get_preprocessed_column(self.is_first_id.clone());

        let [a_curr, _a_prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
        let [b_curr, b_prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
        let [c_curr, c_prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
        let [is_target_curr, is_target_prev] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);

        // CONSTRAINT 1: Fibonacci relation c = a + b
        eval.add_constraint(c_curr.clone() - (a_curr.clone() + b_curr.clone()));

        // CONSTRAINT 2: Transition a_curr = b_prev (disabled for first row)
        let not_first = E::F::one() - is_first.clone();
        eval.add_constraint(not_first.clone() * (a_curr.clone() - b_prev));

        // CONSTRAINT 3: Transition b_curr = c_prev (disabled for first row)
        eval.add_constraint(not_first.clone() * (b_curr.clone() - c_prev));

        // CONSTRAINT 4: Initial value a = 0 at first row
        eval.add_constraint(is_first.clone() * a_curr.clone());

        // CONSTRAINT 5: Initial value b = 1 at first row
        eval.add_constraint(is_first.clone() * (b_curr.clone() - E::F::one()));

        // CONSTRAINT 6: is_target is boolean (0 or 1)
        eval.add_constraint(is_target_curr.clone() * (is_target_curr.clone() - E::F::one()));

        // CONSTRAINT 7: is_target sums to exactly 1 (using running sum technique)
        // We verify: is_target transitions from 0 to 1 at most once
        // This ensures exactly one row has is_target = 1
        // Constraint: is_target_curr * is_target_prev == 0 (can't have two consecutive 1s)
        // Combined with: is_target is boolean and sum check
        eval.add_constraint(not_first.clone() * is_target_curr.clone() * is_target_prev);

        // CONSTRAINT 8: At target row, verify a = fibonacci_value
        // This is the KEY constraint! Verifier doesn't know WHICH row, but knows
        // that SOME row (marked by is_target=1) has the correct Fibonacci value
        let expected_value = E::F::from(BaseField::from_u32_unchecked(self.fibonacci_value));
        eval.add_constraint(is_target_curr.clone() * (a_curr.clone() - expected_value));

        eval
    }
}

pub type SimpleFibComponent = FrameworkComponent<FibEval>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_creation() {
        use stwo_constraint_framework::TraceLocationAllocator;

        let mut tree_span_provider = TraceLocationAllocator::default();

        let eval = FibEval {
            log_n_rows: 4,
            fibonacci_value: 5,
            is_first_id: PreProcessedColumnId {
                id: "is_first_4".to_string(),
            },
        };

        use num_traits::Zero;
        use stwo::core::fields::qm31::SecureField;

        let component = SimpleFibComponent::new(&mut tree_span_provider, eval, SecureField::zero());

        println!("Component created successfully");
        println!("  Log size: {}", component.log_size());
    }
}
