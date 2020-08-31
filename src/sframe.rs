//!
//! ```ignore
//!                              +---------------+  +---------------+
//!                              |               |  | frame metadata+----+
//!                              |               |  +---------------+    |
//!                              |     frame     |                       |
//!                              |               |                       |
//!                              |               |                       |
//!                              +-------+-------+                       |
//!                                      |                               |
//!             CTR +---------------> IV |Enc Key <----Master Key        |
//!                    derive IV         |                  |            |
//!              +                       |                  |            |
//!              |                       +                  v            |
//!              |                    encrypt           Auth Key         |
//!              |                       |                  +            |
//!              |                       |                  |            |
//!              |                       v                  |            |
//!              |               +-------+-------+          |            |
//!              |               |               |          |            |
//!              |               |   encrypted   |          v            |
//!              |               |     frame     +---->Authenticate<-----+
//!              +               |               |          +
//!          encode CTR          |               |          |
//!              +               +-------+-------+          |
//!              |                       |                  |
//!              |                       |                  |
//!              |                       |                  |
//!              |              generic RTP packetize       |
//!              |                       +                  |
//!              |                       |                  |
//!              |                       |                  +--------------+
//!   +----------+                       v                                 |
//!   |                                                                    |
//!   |   +---------------+      +---------------+     +---------------+   |
//!   +-> | SFrame header |      |               |     |               |   |
//!       +---------------+      |               |     |  payload N/N  |   |
//!       |               |      |  payload 2/N  |     |               |   |
//!       |  payload 1/N  |      |               |     +---------------+   |
//!       |               |      |               |     |    auth tag   | <-+
//!       +---------------+      +---------------+     +---------------+
//!                            Encryption flow
//! ```

use crate::header::{Header, Metadata};
use crate::keys::{get_nonce, Key, Keystore};
use crate::util::*;
use evercrypt::prelude::*;

#[derive(Debug)]
pub enum Error {
    InvalidKeyId,
    UnknownKey,
    EncryptionFailed,
    DecryptionFailed,
    AuthenticationFailure,
}

pub enum FrameType {
    Audio,
    Video,
}

pub struct Sframe {
    frame: Vec<u8>,
    auth_tag: Vec<u8>,
}

fn get_tag_length(frame_type: &FrameType) -> usize {
    match frame_type {
        FrameType::Audio => 4,
        FrameType::Video => 10,
    }
}

impl Sframe {
    pub fn encrypt(
        plaintext_frame: &[u8],
        // metadata: Metadata, // XXX: differs from spec
        header: &mut Header,
        key_store: &Keystore,
        frame_type: &FrameType,
    ) -> Result<Self, Error> {
        let key = match key_store.get_key(header.get_kid()) {
            Some(k) => k,
            None => return Err(Error::InvalidKeyId),
        };
        let salt_key = key.derive_iv_salt();

        let ctr = header.get_ctr_mut();
        let iv = get_nonce(&salt_key, &ctr.get_bytes());
        // ctr.increment();
        let encryption_key = key.derive_media_key();
        // XXX: Using AES GCM here.
        // XXX: We should add the frame header or something as AAD
        let ctxt = match aead_encrypt(
            AeadMode::Aes128Gcm,
            &encryption_key,
            plaintext_frame,
            &iv,
            &[],
        ) {
            Ok(c) => c,
            Err(_) => return Err(Error::EncryptionFailed),
        };
        let ctxt = concat(&ctxt.0, &ctxt.1);

        let auth_key = key.derive_authentication_key();
        let tag_length = get_tag_length(frame_type);
        let auth_tag = hmac(HmacMode::Sha256, &auth_key, &ctxt, Some(tag_length));

        Ok(Self {
            frame: ctxt,
            auth_tag: auth_tag,
        })
    }

    pub fn decrypt(
        encrypted_frame: &[u8],
        header: &Header,
        auth_tag: &[u8],
        key_store: &Keystore,
        frame_type: &FrameType,
    ) -> Result<Vec<u8>, Error> {
        let key = match key_store.get_key(header.get_kid()) {
            Some(k) => k,
            None => return Err(Error::UnknownKey),
        };
        let salt_key = key.derive_iv_salt();
        
        let ctr = header.get_ctr();
        let iv = get_nonce(&salt_key, &ctr.get_bytes());
        let encryption_key = key.derive_media_key();
        let ptxt = match aead_decrypt(
            AeadMode::Aes128Gcm,
            &encryption_key,
            &encrypted_frame[0..encrypted_frame.len() - 16],
            &encrypted_frame[encrypted_frame.len() - 16..],
            &iv,
            &[],
        ) {
            Ok(c) => c,
            Err(_) => return Err(Error::DecryptionFailed),
        };

        let auth_key = key.derive_authentication_key();
        let tag_length = get_tag_length(frame_type);
        let my_auth_tag = hmac(
            HmacMode::Sha256,
            &auth_key,
            encrypted_frame,
            Some(tag_length),
        );
        debug_assert_eq!(my_auth_tag, auth_tag);
        if auth_tag != my_auth_tag {
            return Err(Error::AuthenticationFailure);
        }

        Ok(ptxt)
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.frame
    }

    pub fn get_auth_tag(&self) -> &[u8] {
        &self.auth_tag
    }
}
