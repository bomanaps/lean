//! State transition tests
//!
//! Tests for full state transitions including signature validation
//! and state root verification.

use containers::{Block, Slot, State};
use pretty_assertions::assert_eq;
use rstest::fixture;
use ssz::{H256, SszHash};

#[path = "common.rs"]
mod common;
use common::{create_block, sample_config};

#[fixture]
fn genesis_state() -> State {
    let config = sample_config();
    State::generate_genesis(config.genesis_time, 4)
}

#[test]
fn test_state_transition_full() {
    let state = genesis_state();
    let state_at_slot_1 = state.process_slots(Slot(1)).unwrap();

    let block = create_block(1, &mut state_at_slot_1.latest_block_header.clone(), None);

    let state_after_header = state_at_slot_1.process_block_header(&block).unwrap();
    let expected_state = state_after_header
        .process_attestations(&block.body.attestations)
        .unwrap();

    let block_with_correct_root = Block {
        state_root: expected_state.hash_tree_root(),
        ..block
    };

    let final_state = state.state_transition(&block_with_correct_root).unwrap();

    assert_eq!(
        final_state.hash_tree_root(),
        expected_state.hash_tree_root()
    );
}

#[test]
fn test_state_transition_bad_state_root() {
    let state = genesis_state();
    let mut state_at_slot_1 = state.process_slots(Slot(1)).unwrap();

    let mut block = create_block(1, &mut state_at_slot_1.latest_block_header, None);
    block.state_root = H256::zero();

    let result = state.state_transition(&block);
    assert!(result.is_err());
}
