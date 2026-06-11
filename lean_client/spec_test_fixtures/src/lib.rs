//! Shared serde types for lean spec-test JSON fixtures.
//!
//! These types deserialize the JSON test vectors that drive the spec-asset
//! suites and convert them into the consensus types defined in the
//! `containers` and related crates.
//!
//! The same fixture format is consumed by:
//!   - the `containers` and `fork_choice` integration tests, and
//!   - the `http_api` test-driver endpoints (`/lean/v0/test_driver/*`).
//!
//! Layout: all inner consensus shapes live in `common`, while the per-family
//! modules host only the top-level wrappers.

pub mod common;
pub mod fork_choice;
pub mod state_transition;
pub mod verify_signatures;

pub use common::{
    HexBytesJSON, TestAggregatedAttestation, TestAggregatedSignatureProofFixture,
    TestAggregationBits, TestAnchorBlock, TestAnchorState, TestAttestation, TestAttestationData,
    TestBlock, TestBlockBody, TestBlockHeader, TestBlockWithAttestation, TestCheckpoint,
    TestConfig, TestDataWrapper, TestMultiMessageAggregateFixture, TestSignedBlock, TestValidator,
    parse_root,
};
pub use fork_choice::{
    AttestationCheck, ForkChoiceStep, ForkChoiceTest, GossipAggregatedAttestationStep,
    GossipProofJSON, StoreChecks,
};
pub use state_transition::{Info, PostState, TestCase, TestVectorFile};
pub use verify_signatures::{VerifySignaturesTestCase, VerifySignaturesTestVectorFile};
