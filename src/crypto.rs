use std::collections::HashMap;

use rand_mt::Mt64;
use tracing::{info, instrument, trace};

use crate::bytes_as_hex;

#[instrument(skip_all)]
pub fn decrypt_command(key: &[u8], encrypted: &mut [u8]) {
    trace!(data = bytes_as_hex(encrypted), "before decryption");

    for i in 0..encrypted.len() {
        encrypted[i] ^= key[i % key.len()];
    }

    trace!(data = bytes_as_hex(encrypted), "after decryption");
}

/// The XOR of a command's first four encrypted bytes with this gives the first
/// four bytes of its key, which is what the initial keys are looked up by.
pub const HEAD_MAGIC: u32 = 0x9D74C714;

/// The key for the version the command was sent with, or the version when there
/// is none.
pub fn lookup_initial_key(initial_keys: &HashMap<u32, Vec<u8>>, bytes: &[u8; 4]) -> Result<Vec<u8>, u32> {
    let version = u32::from_be_bytes(*bytes) ^ HEAD_MAGIC;

    match initial_keys.get(&version) {
        Some(key) => {
            info!(version, "found initial decryption key");
            Ok(key.clone())
        }
        None => {
            info!(version, "didn't find decryption key");
            Err(version)
        }
    }
}

pub fn new_key_from_seed(seed: u64) -> Vec<u8> {
    // mersenne twister generator
    let mut gen = Mt64::new(seed);

    let mut key = Vec::with_capacity(512);
    for _ in 0..512 {
        for b in gen.next_u64().to_be_bytes() {
            key.push(b);
        }
    }
    key
}
