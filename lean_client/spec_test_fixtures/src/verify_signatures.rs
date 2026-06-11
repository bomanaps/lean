//! Verify-signatures fixture types.
//!
//! Uses fixture-shape wrapper types (`TestAnchorState`, `TestSignedBlock`)
//! rather than the raw `containers::State` / `containers::SignedBlock`
//! because the fixtures encode validators, signatures and aggregated proofs
//! as JSON wrappers / hex strings that the consensus types' own Deserialize
//! impls do not currently accept.

use std::collections::HashMap;

use serde::Deserialize;

use crate::{
    common::{TestAnchorState, TestSignedBlock},
    state_transition::Info,
};

/// Top-level wrapper for a verify-signatures fixture file. Each file holds a
/// `{test_name -> case}` map.
#[derive(Debug, Deserialize)]
pub struct VerifySignaturesTestVectorFile {
    #[serde(flatten)]
    pub tests: HashMap<String, VerifySignaturesTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifySignaturesTestCase {
    #[serde(default)]
    pub network: Option<String>,
    pub anchor_state: TestAnchorState,
    pub signed_block: TestSignedBlock,
    #[serde(default)]
    pub expect_exception: Option<String>,
    #[serde(default)]
    pub rejection_reason: Option<String>,
    /// `_info` is a metadata blob the test harness emits for traceability.
    /// Not all fixtures populate every sub-field (and we do not consume any
    /// of them), so it is fully optional.
    #[serde(default, rename = "_info")]
    pub info: Option<Info>,
}
