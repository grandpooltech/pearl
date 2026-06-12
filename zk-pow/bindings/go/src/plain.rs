//! PlainProof FFI for the mining pool. Two entry points the pool links:
//!   - `verify_plain_proof_ffi` — cheap blake3 share validation (no plonky2).
//!   - `prove_plain_proof_ffi`  — plonky2 ZK certificate for block submission.
//! Public data is variable-length (V2/MoE): `CZKProof.public_data_len` holds the used size.

use std::os::raw::c_char;
use std::slice;

use zk_pow::api::proof::IncompleteBlockHeader;
use zk_pow::api::{prove, verify};
use zk_pow::ffi::plain_proof::PlainProof;

use crate::common::{acquire_cache, catch_panic, set_error_msg, CZKProof, MAX_ZK_PROOF_SIZE};

/// Verify a bincode-serialized PlainProof against the block header. The jackpot difficulty is
/// checked against `nbits_override` (the pool share target; 0 = use the header's own nbits, i.e. a
/// full-block check). The header's nbits is NOT modified — the proof commitment is derived from the
/// header including its nbits, so it must stay what the miner mined. blake3-only (no plonky2).
/// Returns 0 = accepted, 1 = rejected, 2 = bad input / panic; the reason is written to `error_msg_out`.
#[no_mangle]
pub unsafe extern "C" fn verify_plain_proof_ffi(
    block_header: *const IncompleteBlockHeader,
    pp_bytes: *const u8,
    pp_len: usize,
    nbits_override: u32,
    error_msg_out: *mut c_char,
) -> i32 {
    if block_header.is_null() || pp_bytes.is_null() || pp_len == 0 {
        set_error_msg(error_msg_out, "Null/empty input");
        return 1;
    }
    let header = *block_header;
    let bytes = slice::from_raw_parts(pp_bytes, pp_len);

    let result = catch_panic(|| {
        let pp: PlainProof = match PlainProof::deserialize_compat(bytes) {
            Ok(p) => p,
            Err(e) => return (1, format!("deserialize: {e}")),
        };
        let nover = if nbits_override == 0 { None } else { Some(nbits_override) };
        match verify::verify_plain_proof(&header, &pp, nover) {
            Ok(()) => (0, "accepted".to_string()),
            Err(e) => (1, format!("rejected: {e}")),
        }
    });

    match result {
        Ok((code, msg)) => {
            set_error_msg(error_msg_out, &msg);
            code
        }
        Err(panic_msg) => {
            set_error_msg(error_msg_out, &format!("panic: {panic_msg}"));
            2
        }
    }
}

/// Generate a plonky2 ZK certificate from a (bincode) PlainProof — the master's block-finalization
/// step (EXPENSIVE; needs the circuit cache). Fills `zk_proof_out`: `public_data_len` + `public_data`
/// (variable-length; the caller copies `public_data[..public_data_len]` into the block certificate),
/// and `proof_blob`/`proof_blob_len` (the caller-allocated blob must hold `MAX_ZK_PROOF_SIZE` bytes).
/// Returns 0 = success, 2 = bad input / prove failure / panic.
#[no_mangle]
pub unsafe extern "C" fn prove_plain_proof_ffi(
    block_header: *const IncompleteBlockHeader,
    pp_bytes: *const u8,
    pp_len: usize,
    zk_proof_out: *mut CZKProof,
    error_msg_out: *mut c_char,
) -> i32 {
    if block_header.is_null() || pp_bytes.is_null() || pp_len == 0 || zk_proof_out.is_null() {
        set_error_msg(error_msg_out, "Null/empty input");
        return 2;
    }
    let header = *block_header;
    let bytes = slice::from_raw_parts(pp_bytes, pp_len);
    let out = &mut *zk_proof_out;
    if out.proof_blob.is_null() {
        set_error_msg(error_msg_out, "proof_blob buffer is null");
        return 2;
    }

    let pp: PlainProof = match PlainProof::deserialize_compat(bytes) {
        Ok(p) => p,
        Err(e) => {
            set_error_msg(error_msg_out, &format!("deserialize: {e}"));
            return 2;
        }
    };

    let mut cache = acquire_cache();
    let result = match catch_panic(|| prove::zk_prove_plain_proof(header, &pp, &mut cache, false)) {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            set_error_msg(error_msg_out, &format!("prove: {e}"));
            return 2;
        }
        Err(panic_msg) => {
            set_error_msg(error_msg_out, &format!("prove panic: {panic_msg}"));
            return 2;
        }
    };

    if result.proof_data.len() > MAX_ZK_PROOF_SIZE {
        set_error_msg(error_msg_out, "proof exceeds MAX_ZK_PROOF_SIZE");
        return 2;
    }
    // Variable-length public data (V2/MoE): record the used length and copy that many bytes.
    let pd = &result.public_data;
    if pd.len() > out.public_data.len() {
        set_error_msg(error_msg_out, "public_data exceeds buffer");
        return 2;
    }
    out.public_data_len = pd.len();
    out.public_data[..pd.len()].copy_from_slice(pd);

    let buffer = slice::from_raw_parts_mut(out.proof_blob, MAX_ZK_PROOF_SIZE);
    buffer[..result.proof_data.len()].copy_from_slice(&result.proof_data);
    out.proof_blob_len = result.proof_data.len();

    set_error_msg(error_msg_out, "proof generation successful");
    0
}