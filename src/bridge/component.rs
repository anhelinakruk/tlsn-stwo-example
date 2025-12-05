use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, RelationEntry, preprocessed_columns::PreProcessedColumnId};

use crate::multi_fib::IndexRelation;
use crate::bridge::LOG_CONSTRAINT_DEGREE;
pub struct IndexBridgeEval {
    pub log_n_rows: u32,
    pub index_value: usize,
    pub index_relation: IndexRelation,
    pub is_first_id: PreProcessedColumnId,
}

impl FrameworkEval for IndexBridgeEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + LOG_CONSTRAINT_DEGREE
    }

    fn evaluate<E: stwo_constraint_framework::EvalAtRow>(&self, mut eval: E) -> E {
        let is_first = eval.get_preprocessed_column(self.is_first_id.clone());
        let index_curr = eval.next_trace_mask();

        eval.add_to_relation(RelationEntry::new(&self.index_relation, is_first.into(), &[index_curr]));

        eval.finalize_logup_in_pairs();
        eval
    }

}

pub type IndexBridgeComponent = FrameworkComponent<IndexBridgeEval>;

