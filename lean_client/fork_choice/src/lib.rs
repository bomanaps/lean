pub mod block_cache;
pub mod handlers;
pub mod store;
pub mod sync_state;

// dirty hack to avoid issues compiling grandine dependencies. by default, bls
// crate has no features enabled, and thus compilation fails (as exactly one
// backend must be enabled). So we include bls crate with one feature enabled,
// to make everything work.
use bls as _;
