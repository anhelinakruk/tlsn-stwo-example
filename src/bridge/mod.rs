use stwo_constraint_framework::relation;

mod component;
mod trace_gen;

pub use component::{IndexBridgeComponent, IndexBridgeEval};
pub use trace_gen::{gen_bridge_trace, gen_bridge_interaction_trace};

pub const LOG_CONSTRAINT_DEGREE: u32 = 1;
pub const INDEX_RELATION_SIZE: usize = 1;

// relation!(IndexRelation, INDEX_RELATION_SIZE);
