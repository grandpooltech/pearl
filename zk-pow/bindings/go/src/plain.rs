//! Cheap PlainProof FFI for the mining pool (Stage-0 spike, Path B).
//!
//! The pool validates miner *shares* using `verify_plain_proof`, which is blake3-only
//! (no plonky2, no node, no circuit cache). This module exposes that path to Go, plus a
//! CPU `mine_plain_proof` helper so the spike can produce a real PlainProof to verify.

use std::os::raw::c_char;
use std::slice;

use zk_pow::api::proof::{IncompleteBlockHeader, MMAType, MiningConfiguration, PeriodicPattern, ZKProof};
use zk_pow::api::{prove, verify};
use zk_pow::ffi::mine::mine as ffi_mine;
use zk_pow::ffi::plain_proof::PlainProof;

use crate::common::{acquire_cache, catch_panic, set_error_msg, CZKProof, MAX_ZK_PROOF_SIZE};

fn test_block_header(nbits: u32) -> IncompleteBlockHeader {
    IncompleteBlockHeader {
        version: 0,
        prev_block: [1; 32],
        merkle_root: [2; 32],
        timestamp: 0x6666_6666,
        nbits,
    }
}

fn default_mining_config(common_dim: u32, rank: u16) -> anyhow::Result<MiningConfiguration> {
    Ok(MiningConfiguration {
        common_dim,
        rank,
        mma_type: MMAType::Int7xInt7ToInt32,
        rows_pattern: PeriodicPattern::from_list(&[0, 1, 8, 9, 64, 65, 72, 73])?,
        cols_pattern: PeriodicPattern::from_list(&[0, 1, 8, 9, 64, 65, 72, 73])?,
        reserved: MiningConfiguration::RESERVED_VALUE,
    })
}

/// Mine a PlainProof on CPU (no ZK) for a built-in easy test job and return it
/// bincode-serialized in `out_buf`. The block header used is written to `block_header_out`
/// so the caller can verify the proof against the matching header.
///
/// Returns: 0 = ok, 1 = invalid input (e.g. buffer too small), 2 = system error.
///
/// # Safety
/// - `block_header_out`, `out_buf`, `out_len` must be valid; `out_buf` must have `out_buf_cap` bytes.
/// - `error_msg_out` must be null or point to an `ERROR_MSG_MAX_SIZE` byte buffer.
#[no_mangle]
pub unsafe extern "C" fn mine_plain_proof(
    rank: u16,
    block_header_out: *mut IncompleteBlockHeader,
    out_buf: *mut u8,
    out_buf_cap: usize,
    out_len: *mut usize,
    error_msg_out: *mut c_char,
) -> i32 {
    if block_header_out.is_null() || out_buf.is_null() || out_len.is_null() {
        set_error_msg(error_msg_out, "Null pointer");
        return 2;
    }

    let mined = catch_panic(|| {
        let header = test_block_header(0x1D2FFFFF); // easy difficulty
        let rank = if rank == 0 { 64 } else { rank };
        let k = (16 * rank as usize).max(1024) + 192;
        let (m, n) = (6144usize, 4096usize);
        let config = default_mining_config(k as u32, rank).map_err(|e| format!("config: {e}"))?;
        let pp = ffi_mine(m, n, k, header, config, None, false).map_err(|e| format!("mine: {e}"))?;
        let bytes = bincode::serialize(&pp).map_err(|e| format!("serialize: {e}"))?;
        Ok::<_, String>((header, bytes))
    });

    match mined {
        Ok(Ok((header, bytes))) => {
            if bytes.len() > out_buf_cap {
                set_error_msg(error_msg_out, "out_buf too small");
                return 1;
            }
            slice::from_raw_parts_mut(out_buf, bytes.len()).copy_from_slice(&bytes);
            *out_len = bytes.len();
            *block_header_out = header;
            set_error_msg(error_msg_out, "ok");
            0
        }
        Ok(Err(msg)) => {
            set_error_msg(error_msg_out, &msg);
            2
        }
        Err(panic_msg) => {
            set_error_msg(error_msg_out, &format!("panic: {panic_msg}"));
            2
        }
    }
}

/// Verify a bincode-serialized PlainProof against a block header using the cheap
/// (blake3-only) verifier. This is what the pool runs on every submitted share.
///
/// Returns: 0 = accepted, 1 = rejected / bad input, 2 = system error.
///
/// # Safety
/// - `block_header` and `pp_bytes` must be valid; `pp_bytes` points to `pp_len` bytes.
/// - `error_msg_out` must be null or point to an `ERROR_MSG_MAX_SIZE` byte buffer.
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
        let pp: PlainProof = match bincode::deserialize(bytes) {
            Ok(p) => p,
            Err(e) => return (1, format!("deserialize: {e}")),
        };
        // The commitment (Hash A) is derived from block_header incl. its nbits, so the header must
        // keep the nbits the miner mined; the difficulty is instead checked against nbits_override
        // (the pool share target). 0 means "use the header's nbits" (block check).
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

/// Generate a plonky2 ZK certificate from a (bincode) PlainProof and verify it — the
/// pool's block-finalization step. Measures real prove cost. `nbits_override`=0 uses the
/// header's nbits for the difficulty check, otherwise the given (e.g. easy) nbits.
/// Writes the serialized ZK proof length to `out_proof_len`.
///
/// Returns: 0 = proved AND cert verified, 1 = cert rejected, 2 = system error.
///
/// # Safety
/// - `block_header`, `pp_bytes`, `out_proof_len` must be valid; `pp_bytes` has `pp_len` bytes.
/// - `error_msg_out` must be null or point to an `ERROR_MSG_MAX_SIZE` byte buffer.
#[no_mangle]
pub unsafe extern "C" fn prove_and_verify_plain_proof_ffi(
    block_header: *const IncompleteBlockHeader,
    pp_bytes: *const u8,
    pp_len: usize,
    nbits_override: u32,
    out_proof_len: *mut usize,
    error_msg_out: *mut c_char,
) -> i32 {
    if block_header.is_null() || pp_bytes.is_null() || pp_len == 0 || out_proof_len.is_null() {
        set_error_msg(error_msg_out, "Null/empty input");
        return 2;
    }
    let header = *block_header;
    let bytes = slice::from_raw_parts(pp_bytes, pp_len);

    let result = catch_panic(|| {
        let pp: PlainProof = match bincode::deserialize(bytes) {
            Ok(p) => p,
            Err(e) => return (2, format!("deserialize: {e}"), 0usize),
        };
        let mut cache = acquire_cache();
        let r = match prove::zk_prove_plain_proof(header, &pp, &mut cache, false) {
            Ok(r) => r,
            Err(e) => return (2, format!("prove: {e}"), 0usize),
        };
        let proof_len = r.proof_data.len();
        let nover = if nbits_override == 0 { None } else { Some(nbits_override) };
        let (params, zkp) = match ZKProof::deserialize(header, &r.public_data, &r.proof_data) {
            Ok(v) => v,
            Err(e) => return (1, format!("cert deserialize: {e}"), proof_len),
        };
        match verify::verify_block_cached_circuits_only(&params, &zkp, &cache, nover) {
            Ok(()) => (0, "proved+verified".to_string(), proof_len),
            Err(e) => (1, format!("cert rejected: {e}"), proof_len),
        }
    });

    match result {
        Ok((code, msg, plen)) => {
            *out_proof_len = plen;
            set_error_msg(error_msg_out, &msg);
            code
        }
        Err(panic_msg) => {
            set_error_msg(error_msg_out, &format!("panic: {panic_msg}"));
            2
        }
    }
}

/// Generate a plonky2 ZK certificate from a (bincode) PlainProof for BLOCK SUBMISSION. Unlike
/// `mine`, it does not mine a new proof — it proves the share the miner already found (the pool's
/// finalization step). The serialized proof is written to `zk_proof_out` (public_data + proof_blob)
/// for the caller to assemble into a block certificate. This is expensive (real plonky2 prove) and
/// requires the circuit cache.
///
/// Returns: 0 = proved, 2 = error.
///
/// # Safety
/// - `block_header`, `pp_bytes`, `zk_proof_out` must be valid; `pp_bytes` has `pp_len` bytes;
///   `zk_proof_out.proof_blob` must have capacity `MAX_ZK_PROOF_SIZE`.
/// - `error_msg_out` must be null or point to an `ERROR_MSG_MAX_SIZE` byte buffer.
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

    let pp: PlainProof = match bincode::deserialize(bytes) {
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
    out.public_data = result.public_data;
    let buffer = slice::from_raw_parts_mut(out.proof_blob, MAX_ZK_PROOF_SIZE);
    buffer[..result.proof_data.len()].copy_from_slice(&result.proof_data);
    out.proof_blob_len = result.proof_data.len();

    set_error_msg(error_msg_out, "proof generation successful");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mine an easy PlainProof; mine_plain_proof overwrites the header with the one it used.
    fn mine() -> (IncompleteBlockHeader, Vec<u8>) {
        let mut hdr = test_block_header(0);
        let mut buf = vec![0u8; 8 << 20];
        let mut len: usize = 0;
        let mut err = [0u8; 256];
        let rc = unsafe {
            mine_plain_proof(64, &mut hdr, buf.as_mut_ptr(), buf.len(), &mut len, err.as_mut_ptr() as *mut c_char)
        };
        assert_eq!(rc, 0, "mine_plain_proof failed");
        buf.truncate(len);
        (hdr, buf)
    }

    #[test]
    fn verify_accepts_valid_and_rejects_tampered() {
        let (hdr, mut proof) = mine();
        let mut err = [0u8; 256];

        let rc = unsafe { verify_plain_proof_ffi(&hdr, proof.as_ptr(), proof.len(), err.as_mut_ptr() as *mut c_char) };
        assert_eq!(rc, 0, "valid proof should be accepted");

        let mid = proof.len() / 2;
        proof[mid] ^= 0xFF;
        let rc = unsafe { verify_plain_proof_ffi(&hdr, proof.as_ptr(), proof.len(), err.as_mut_ptr() as *mut c_char) };
        assert_ne!(rc, 0, "tampered proof should be rejected");
    }

    #[test]
    #[ignore = "plonky2 prove is slow; run with `cargo test -- --ignored`"]
    fn prove_generates_certificate() {
        let (hdr, proof) = mine();
        let mut blob = vec![0u8; MAX_ZK_PROOF_SIZE];
        let mut out: CZKProof = unsafe { std::mem::zeroed() };
        out.proof_blob = blob.as_mut_ptr();
        let mut err = [0u8; 256];

        let rc = unsafe { prove_plain_proof_ffi(&hdr, proof.as_ptr(), proof.len(), &mut out, err.as_mut_ptr() as *mut c_char) };
        assert_eq!(rc, 0, "prove_plain_proof_ffi failed");
        assert!(out.proof_blob_len > 0, "empty proof");
    }
}