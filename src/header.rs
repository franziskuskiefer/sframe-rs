//!
//! Spec:
//! 
//! ```ignore
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+
//! |S|LEN  |X|  K  |
//! +-+-+-+-+-+-+-+-+
//! SFrame header metadata
//! ```
//! 
//! Signature flag (S):
//! 1 bit This field indicates the payload contains a signature if set.
//! Counter Length (LEN): 3 bits This field indicates
//! the length of the CTR fields in bytes.
//! Extended Key Id Flag (X): 1
//! bit Indicates if the key field contains the key id or the key length.
//! Key or Key Length: 3 bits This field contains the key id (KID) if the
//! X flag is set to 0, or the key length (KLEN) if set to 1.
//!
//! If X flag is 0 then the KID is in the range of 0-7 and the frame
//! counter (CTR) is found in the next LEN bytes:
//!
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+---------------------------------+
//! |S|LEN  |0| KID |    CTR... (length=LEN)          |
//! +-+-+-+-+-+-+-+-+---------------------------------+
//!
//! Key id (KID): 3 bits The key id (0-7).  Frame counter (CTR):
//! (Variable length) Frame counter value up to 8 bytes long.
//!
//! if X flag is 1 then KLEN is the length of the key (KID), that is
//! found after the SFrame header metadata byte.  After the key id (KID),
//! the frame counter (CTR) will be found in the next LEN bytes:
//!
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+---------------------------+---------------------------+
//! |S|LEN  |1|KLEN |   KID... (length=KLEN)    |    CTR... (length=LEN)    |
//! +-+-+-+-+-+-+-+-+---------------------------+---------------------------+
//!
//! Key length (KLEN): 3 bits The key length in bytes.  Key id (KID):
//! (Variable length) The key id value up to 8 bytes long.  Frame counter
//! (CTR): (Variable length) Frame counter value up to 8 bytes long.
//!

#[derive(Clone, Copy, Debug)]
enum KeyIdOrLength {
    KeyId(u8),     // if !extended_key_id
    KeyLength(u8), // if extended_key_id
}

impl Into<u64> for KeyIdOrLength {
    fn into(self) -> u64 {
        match self {
            KeyIdOrLength::KeyId(v) => v.into(),
            KeyIdOrLength::KeyLength(v) => v.into(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Ctr {
    v: u64, // [u8; 8]
}

impl Ctr {
    pub(crate) fn new(v: u64) -> Self {
        Self {
            v,
        }
    }
    pub(crate) fn from_bytes(v: &[u8]) -> Self {
        debug_assert!(v.len() <= 8);
        if v.len() > 8 {
            panic!("Invalid ctr len {}", v.len());
        }
        let mut bytes = [0u8; 8];
        for (&v_i, b) in v.iter().zip(bytes.iter_mut()) {
            *b = v_i;
        }
        Self {
            v: u64::from_be_bytes(bytes),
        }
    }
    pub(crate) fn get_bytes(&self) -> [u8; 8] {
        self.v.to_be_bytes()
    }
    pub(crate) fn increment(&mut self) {
        self.v += 1;
    }
}

impl Into<[u8; 8]> for &Ctr {
    fn into(self) -> [u8; 8] {
        self.v.to_be_bytes()
    }
}

#[derive(Debug)]
pub struct Metadata {
    signature: bool,
    ctr_len: u8, // in bytes
    extended_key_id: bool,
    key: KeyIdOrLength,
}

impl Metadata {
    pub fn new(signature: bool, key_id: u64) -> Self {
        Self {
            signature,
            ctr_len: 1,
            extended_key_id: true,
            key: KeyIdOrLength::KeyLength(8),
        }
    }
    pub(crate) fn decode(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() >= 1);
        let signature = (bytes[0] & 1) == 1;
        let ctr_len = bytes[0] & 0x70;
        let extended_key_id = (bytes[0] & 0x8) == 1;
        let key = if extended_key_id {
            KeyIdOrLength::KeyLength(bytes[0] & 0x7)
        } else {
            KeyIdOrLength::KeyId(bytes[0] & 0x7)
        };
        Self {
            signature,
            ctr_len,
            extended_key_id,
            key,
        }
    }
}

#[derive(Debug)]
pub struct Header {
    metadata: Metadata,
    ctr: Ctr,
    kid: u64,
}

impl Header {
    pub fn new(metadata: Metadata, kid: u64) -> Self {
        Self {
            metadata,
            ctr: Ctr::new(0),
            kid
        }
    }
    pub(crate) fn decode(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() >= 1);
        let metadata = Metadata::decode(bytes);
        let (kid, ctr) = if metadata.extended_key_id {
            let key_id_len: u64 = metadata.key.into();
            let key_id_len = key_id_len as usize;
            debug_assert!(bytes.len() >= (1 + metadata.ctr_len as usize + key_id_len));
            let mut kid_bytes = [0u8; 8];
            kid_bytes.copy_from_slice(&bytes[1..key_id_len]);

            let kid = u64::from_be_bytes(kid_bytes);
            let ctr = Ctr::from_bytes(&bytes[key_id_len..metadata.ctr_len as usize]);
            (kid, ctr)
        } else {
            debug_assert!(bytes.len() >= 1 + metadata.ctr_len as usize);
            let ctr = bytes[1..metadata.ctr_len as usize].to_vec();
            (metadata.key.into(), Ctr::from_bytes(&ctr))
        };
        Self { metadata, ctr, kid }
    }
    pub(crate) fn get_kid(&self) -> u64 {
        self.kid
    }
    pub(crate) fn get_ctr_mut(&mut self) -> &mut Ctr {
        &mut self.ctr
    }
    pub(crate) fn get_ctr(&self) -> &Ctr {
        &self.ctr
    }
    pub(crate) fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }
}
