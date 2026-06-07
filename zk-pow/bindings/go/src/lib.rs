//! Go FFI bindings for ZK-POW.
//!
//! This crate provides C-compatible FFI functions for ZK proof generation and verification,
//! primarily used by the Go pearld node.

#[cfg(unix)]
use tikv_jemallocator::Jemalloc;

#[cfg(unix)]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod common;
mod mine;
mod plain;
mod verify;

pub use common::CZKProof;
pub use zk_pow::api::proof::{IncompleteBlockHeader, MiningConfiguration};

pub use mine::mine;
pub use plain::{mine_plain_proof, prove_and_verify_plain_proof_ffi, prove_plain_proof_ffi, verify_plain_proof_ffi};
pub use verify::verify_zk_proof;
pub use verify::verify_zk_proof_with_nbits;