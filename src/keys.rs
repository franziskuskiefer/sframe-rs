//! Each client creates a 32 bytes secret key K and share it with with
//! other participants via an E2EE channel.  From K, we derive 3 secrets:
//!
//! 1- Salt key used to calculate the IV
//!
//! Key = HKDF(K, 'SFrameSaltKey', 16)
//!
//! 2- Encryption key to encrypt the media frame
//!
//! Key = HKDF(K, 'SFrameEncryptionKey', 16)
//!
//! 3- Authentication key to authenticate the encrypted frame and the
//! media metadata
//!
//! Key = HKDF(K, 'SFrameAuthenticationKey', 32)
//!
//! The IV is 128 bits long and calculated from the CTR field of the
//! Frame header:
//!
//! IV = CTR XOR Salt key

use crate::util::clone_into_array;
use evercrypt::prelude::*;
use std::collections::HashMap;

pub struct Keystore {
    keys: HashMap<u64, Key>,
}

impl Keystore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
    pub fn add_key(&mut self, k_id: u64, k: Key) {
        self.keys.insert(k_id, k);
    }
    pub fn get_key(&self, k_id: u64) -> Option<&Key> {
        self.keys.get(&k_id)
    }
}


#[derive(Clone)]
pub struct Key {
    value: [u8; 32],
}

impl Key {
    pub fn new(k: &[u8]) -> Self {
        Self {
            value: clone_into_array(k),
        }
    }
    pub(crate) fn derive_iv_salt(&self) -> [u8; 12] {
        let k = hkdf(HmacMode::Sha512, &[], &self.value, b"SFrameSaltKey", 12);
        clone_into_array(&k)
    }
    pub(crate) fn derive_media_key(&self) -> [u8; 16] {
        let k = hkdf(
            HmacMode::Sha512,
            &[],
            &self.value,
            b"SFrameEncryptionKey",
            16,
        );
        clone_into_array(&k)
    }
    pub(crate) fn derive_authentication_key(&self) -> [u8; 32] {
        let k = hkdf(
            HmacMode::Sha512,
            &[],
            &self.value,
            b"SFrameAuthenticationKey",
            32,
        );
        clone_into_array(&k)
    }
}

pub(crate) fn get_nonce(salt_key: &[u8; 12], ctr: &[u8]) -> [u8; 12] {
    debug_assert!(ctr.len() > 0 && ctr.len() <= 8);
    let mut out: [u8; 12] = clone_into_array(salt_key);
    for (i, c) in ctr.iter().enumerate() {
        out[i] ^= c;
    }
    out
}
